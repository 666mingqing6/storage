/**
 * URL 安全校验工具（SSRF 防护）
 *
 * 使用场景：
 * - 「远程 URL 转存」功能：服务端需要主动 fetch 用户提供的任意 URL
 * - 任何由服务端发起的、目标地址来自用户输入的外呼请求
 *
 * 防护策略（纵深防御）：
 * 1. 协议白名单：仅允许 http / https
 * 2. 禁止携带账号密码的 URL（http://user:pass@host/）
 * 3. 端口白名单：仅允许 80 / 443，以及常见的显式 HTTP(S) 端口
 * 4. DNS 解析后校验所有 A / AAAA 记录，拦截内网、回环、链路本地、保留网段
 * 5. 域名黑名单（可配置），拦截云元数据服务等已知敏感目标
 * 6. 重定向逐跳校验：每一次跳转都重新执行上述全部检查（避免 302 绕过）
 *
 * 重要限制（务必知悉）：
 * - JS 运行时（Workers / Node）无法对 fetch 的内核做「DNS pinning」。
 *   本模块通过「先解析校验、后发起请求」降低风险，但在 DNS 解析校验与真正的
 *   TCP 连接之间存在极小的 TOCTOU 时间窗口，理论上可被 DNS Rebinding 利用。
 *   该残余风险已通过禁止重定向重定向、限制协议与端口、以及仅允许受信身份调用
 *   来收敛。若需彻底消除，需在具备固定出口 IP 的环境中配合出站防火墙策略。
 */

import { ValidationError, DriverError } from "../http/errors.js";
import { ApiStatus } from "../constants/index.js";

/** 允许的协议 */
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * 允许的显式端口
 * - 80 / 443 为协议默认端口
 * - 8080 / 8443 / 8880 等常见 HTTP(S) 服务端口通常为公网服务，一并放行
 * - 其余端口（如 22 / 3306 / 6379 / 9200）一律拒绝，避免端口探测与协议走私
 */
const ALLOWED_PORTS = new Set(["", "80", "443", "8080", "8443", "8880", "2052", "2082", "2086", "2095"]);

/** 内置域名黑名单：云厂商元数据服务与本地开发地址 */
const DEFAULT_HOSTNAME_BLACKLIST = [
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "metadata",
  "169.254.169.254",
];

/**
 * 判断 IPv4 是否属于禁止访问的网段
 * 覆盖：本机回环、私有网段、链路本地、CGNAT、组播、保留与文档用网段
 * @param {string} ip 形如 "10.0.0.1"
 * @returns {boolean}
 */
function isForbiddenIPv4(ip) {
  const parts = String(ip || "").split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true; // 无法解析视为不安全
  }
  const [a, b, c] = parts;

  // 0.0.0.0/8       "本网络"
  if (a === 0) return true;
  // 10.0.0.0/8      私有
  if (a === 10) return true;
  // 100.64.0.0/10   CGNAT 运营商级 NAT
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8     回环
  if (a === 127) return true;
  // 169.254.0.0/16  链路本地（含 169.254.169.254 云元数据）
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12   私有
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24    IETF 协议保留（含 192.0.0.170/171 等）
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.0.2.0/24    文档用
  if (a === 192 && b === 0 && c === 2) return true;
  // 192.88.99.0/24  6to4 中继任播
  if (a === 192 && b === 88 && c === 99) return true;
  // 192.168.0.0/16  私有
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15   基准测试
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 文档用
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24  文档用
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4     组播
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4     保留（含 255.255.255.255 广播）
  if (a >= 240) return true;

  return false;
}

/**
 * 把 IPv6 文本展开为 8 组 16 位整数
 *
 * 支持：
 * - 完整写法 / `::` 压缩写法
 * - 末尾内嵌的 IPv4 点分写法（::ffff:127.0.0.1、::127.0.0.1）
 * - 十六进制形式的 IPv4-mapped（::ffff:7f00:1，URL 解析器会产出这种形式）
 *
 * @param {string} ip 已剥离方括号的 IPv6 文本
 * @returns {number[]|null} 8 个 0..65535 的整数；解析失败返回 null
 */
function expandIPv6(ip) {
  let text = String(ip || "").trim().toLowerCase();
  if (!text) return null;

  // 去掉 zone id（fe80::1%eth0）
  text = text.split("%")[0];

  // 处理末尾内嵌的 IPv4 点分写法
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = tail.split(".").map((n) => Number(n));
    if (v4.length !== 4 || v4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return null;
    }
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  // 拆分 `::`
  const doubleColonCount = (text.match(/::/g) || []).length;
  if (doubleColonCount > 1) return null;

  let head;
  let tailGroups;
  if (doubleColonCount === 1) {
    const [left, right] = text.split("::");
    head = left ? left.split(":") : [];
    tailGroups = right ? right.split(":") : [];
  } else {
    head = text.split(":");
    tailGroups = [];
  }

  const all = doubleColonCount === 1 ? [...head, ...tailGroups] : head;
  // 组数量：压缩写法 <= 8；非压缩必须恰好 8
  if (doubleColonCount === 0 && all.length !== 8) return null;
  if (doubleColonCount === 1 && all.length > 7) return null;

  const groups = all.map((g) => {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return NaN;
    return parseInt(g, 16);
  });
  if (groups.some((n) => Number.isNaN(n))) return null;

  if (doubleColonCount === 1) {
    const fill = 8 - groups.length;
    const headLen = head.length;
    const expanded = [...groups.slice(0, headLen), ...new Array(fill).fill(0), ...groups.slice(headLen)];
    return expanded.length === 8 ? expanded : null;
  }

  return groups.length === 8 ? groups : null;
}

/**
 * 判断 IPv6 是否属于禁止访问的网段
 *
 * 关键点：URL 解析器产出的 IPv6 主机名带方括号（如 `[::1]`），
 * 调用方可能传入带或不带括号的形式，这里统一先剥离再解析，
 * 否则 `http://[::ffff:169.254.169.254]/` 这类地址会完全绕过校验。
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isForbiddenIPv6(ip) {
  const normalized = stripIpv6Brackets(String(ip || "")).toLowerCase().split("%")[0].trim();
  if (!normalized) return true;

  const groups = expandIPv6(normalized);
  if (!groups) return true; // 无法解析视为不安全

  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;

  // 未指定 :: 
  if (groups.every((g) => g === 0)) return true;
  // 回环 ::1
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) {
    return true;
  }

  // IPv4 映射 ::ffff:a.b.c.d —— 必须按 IPv4 规则复核，否则可绕过 IPv4 黑名单
  const isV4Mapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  if (isV4Mapped) {
    const v4 = `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
    return isForbiddenIPv4(v4);
  }

  // IPv4 兼容（已废弃）::a.b.c.d —— 同样按 IPv4 处理，保守拒绝私网
  const isV4Compatible = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && (g6 !== 0 || g7 > 1);
  if (isV4Compatible) {
    const v4 = `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
    if (isForbiddenIPv4(v4)) return true;
  }

  // 6to4 2002::/16 —— 内嵌 IPv4，需复核以避免封装绕过
  if (g0 === 0x2002) {
    const v4 = `${g1 >> 8}.${g1 & 0xff}.${g2 >> 8}.${g2 & 0xff}`;
    if (isForbiddenIPv4(v4)) return true;
  }

  // Teredo 2001:0000::/32 —— 内嵌混淆的 IPv4，保守拒绝
  if (g0 === 0x2001 && g1 === 0x0000) return true;

  // NAT64 64:ff9b::/96（及本地前缀 64:ff9b:1::/48）—— 可映射到 IPv4，保守拒绝
  if (g0 === 0x0064 && g1 === 0xff9b) return true;

  // fc00::/7  唯一本地地址（ULA）
  if ((g0 & 0xfe00) === 0xfc00) return true;
  // fe80::/10 链路本地
  if ((g0 & 0xffc0) === 0xfe80) return true;
  // ff00::/8  组播
  if ((g0 & 0xff00) === 0xff00) return true;
  // 2001:db8::/32 文档用
  if (g0 === 0x2001 && g1 === 0x0db8) return true;
  // 100::/64 丢弃前缀
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true;
  // 2001:10::/28 ORCHID（已废弃，保守拒绝）
  if (g0 === 0x2001 && (g1 & 0xfff0) === 0x0010) return true;

  return false;
}

/**
 * 判断 IP 字面量是否被禁止
 *
 * 注意：hostname 可能形如 `[::1]`（URL 解析器对 IPv6 的产出形式），
 * 因此这里必须先剥离方括号再判断归属，否则会按 IPv4 分支误判为「无法解析 → 禁止」
 * 或漏判为放行。
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isForbiddenIp(ip) {
  const value = stripIpv6Brackets(String(ip || "")).split("%")[0].trim();
  if (!value) return true;
  if (value.includes(":")) return isForbiddenIPv6(value);
  return isForbiddenIPv4(value);
}

/**
 * 缓存的 DNS 解析器句柄
 * 使用动态 import 而非顶层 import，原因：
 * - Docker / Node 部署下可用
 * - Cloudflare Workers 需启用 nodejs_compat 才提供该模块，
 *   动态导入可避免在不支持的环境下于模块加载阶段直接崩溃
 */
let dnsResolverPromise = null;

/**
 * 获取 DNS 解析器（resolver 对象），不支持时返回 null
 * @returns {Promise<Object|null>}
 */
async function getDnsResolver() {
  if (dnsResolverPromise === null) {
    dnsResolverPromise = (async () => {
      try {
        const mod = await import("node:dns");
        const promisesApi = mod?.promises ?? mod?.default?.promises;
        return promisesApi && typeof promisesApi.resolve4 === "function" ? promisesApi : null;
      } catch {
        return null;
      }
    })();
  }
  return dnsResolverPromise;
}

/**
 * 解析主机名对应的所有 IP 地址
 *
 * 若运行时不支持 DNS 解析（例如未启用 nodejs_compat 的边缘运行时），
 * 则只能退化为「仅字面量 IP 校验」——此时对域名目标的防护强度下降，
 * 因此调用方应通过 requireDnsResolution 选项决定是否允许该降级。
 *
 * @param {string} hostname
 * @returns {Promise<{supported: boolean, addresses: string[]}>}
 */
async function resolveHostnameAddresses(hostname) {
  // 字面量 IP 无需解析
  if (isIpLiteral(hostname)) {
    return { supported: true, addresses: [stripIpv6Brackets(hostname)] };
  }

  const resolver = await getDnsResolver();
  if (!resolver) {
    return { supported: false, addresses: [] };
  }

  const collected = [];
  const tasks = [
    resolver.resolve4(hostname).catch(() => []),
    typeof resolver.resolve6 === "function" ? resolver.resolve6(hostname).catch(() => []) : Promise.resolve([]),
  ];
  const results = await Promise.all(tasks);
  for (const list of results) {
    if (Array.isArray(list)) collected.push(...list);
  }

  return { supported: true, addresses: collected };
}

/**
 * 判断输入是否为 IP 字面量
 *
 * 注意：URL 解析器产出的 IPv6 主机名带方括号（`[::1]`），
 * 必须先剥离括号，否则会被误判为「非 IP 字面量」而进入 DNS 解析分支。
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isIpLiteral(value) {
  const host = stripIpv6Brackets(String(value || "").trim());
  if (!host) return false;
  if (host.includes(":")) {
    // 交给 expandIPv6 严格判定，避免把 ":::" 之类的畸形输入当成 IP
    return expandIPv6(host) !== null;
  }
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/**
 * 去掉 IPv6 的方括号包裹
 * @param {string} value
 * @returns {string}
 */
function stripIpv6Brackets(value) {
  const s = String(value || "").trim();
  if (s.startsWith("[") && s.endsWith("]")) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * 归一化主机名，用于黑名单比对
 * @param {string} hostname
 * @returns {string}
 */
function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, ""); // 去掉 FQDN 末尾的点，避免 "localhost." 绕过
}

/**
 * 校验一个 URL 字符串是否安全可访问
 *
 * @param {string} rawUrl 用户输入的 URL
 * @param {Object} [options]
 * @param {boolean} [options.requireDnsResolution=true] 运行时不支持 DNS 解析时是否直接拒绝
 * @param {string[]} [options.hostnameBlacklist] 追加的域名黑名单
 * @param {boolean} [options.allowPrivateNetwork=false] 是否允许内网地址（自托管场景可选开启，默认关闭）
 * @returns {Promise<{url: string, hostname: string, addresses: string[]}>}
 * @throws {ValidationError} 校验失败时抛出
 */
export async function assertSafeUrl(rawUrl, options = {}) {
  const {
    requireDnsResolution = true,
    hostnameBlacklist = [],
    allowPrivateNetwork = false,
  } = options;

  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new ValidationError("URL 不能为空");
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new ValidationError("无效的 URL 格式");
  }

  // 1) 协议白名单
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    throw new ValidationError("仅支持 HTTP / HTTPS 协议的 URL");
  }

  // 2) 禁止 URL 内嵌凭据
  if (parsed.username || parsed.password) {
    throw new ValidationError("URL 中不允许包含用户名或密码");
  }

  // 3) 端口白名单
  const port = parsed.port || "";
  if (!ALLOWED_PORTS.has(port)) {
    throw new ValidationError(`不允许访问端口 ${port}，仅支持 80 / 443 等标准 HTTP(S) 端口`);
  }

  const hostname = normalizeHostname(parsed.hostname);
  if (!hostname) {
    throw new ValidationError("URL 缺少有效的主机名");
  }

  // 4) 域名黑名单
  const blacklist = [...DEFAULT_HOSTNAME_BLACKLIST, ...hostnameBlacklist]
    .map((item) => normalizeHostname(item))
    .filter(Boolean);
  for (const blocked of blacklist) {
    if (hostname === blocked || hostname.endsWith(`.${blocked}`)) {
      throw new ValidationError("该目标地址被安全策略阻止");
    }
  }

  // 5) 内网访问开关（默认关闭）
  if (allowPrivateNetwork) {
    return { url: parsed.toString(), hostname, addresses: [] };
  }

  // 6) DNS 解析 + IP 网段校验
  const { supported, addresses } = await resolveHostnameAddresses(hostname);

  if (!supported) {
    if (requireDnsResolution) {
      throw new DriverError("当前运行时不支持 DNS 安全校验，已拒绝该 URL", {
        status: ApiStatus.BAD_REQUEST,
        code: "URL_TRANSFER.DNS_CHECK_UNAVAILABLE",
        expose: true,
      });
    }
    // 退化模式：仅字面量 IP 已在上一步无法覆盖，此处放行但由上层提示风险
    return { url: parsed.toString(), hostname, addresses: [] };
  }

  if (addresses.length === 0) {
    // 无法解析出任何地址：可能是域名不存在，直接拒绝避免无意义重试
    throw new ValidationError("无法解析该 URL 的主机名");
  }

  const forbidden = addresses.filter((ip) => isForbiddenIp(ip));
  if (forbidden.length > 0) {
    throw new ValidationError("该 URL 指向受保护的内网地址，出于安全考虑已拒绝");
  }

  return { url: parsed.toString(), hostname, addresses };
}

/**
 * 判断一个具体的 IP 字符串是否被安全策略禁止
 * 由 SafeUrlFetcher 在手动跟随重定向时逐跳调用
 * @param {string} ip
 * @returns {boolean}
 */
export function isIpForbidden(ip) {
  return isForbiddenIp(ip);
}

export const __testing = {
  isForbiddenIPv4,
  isForbiddenIPv6,
  isForbiddenIp,
  expandIPv6,
  stripIpv6Brackets,
  normalizeHostname,
  ALLOWED_PORTS,
  DEFAULT_HOSTNAME_BLACKLIST,
};
