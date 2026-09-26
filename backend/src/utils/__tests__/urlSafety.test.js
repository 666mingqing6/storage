/**
 * urlSafety.js 回归测试（SSRF 防护）
 *
 * 运行：node --test src/utils/__tests__/urlSafety.test.js
 *
 * 背景：本文件覆盖一个曾经真实存在的严重缺陷 ——
 * URL 解析器产出的 IPv6 主机名带方括号（`[::1]`），而 isForbiddenIPv6 未剥离括号，
 * 导致 `http://[::ffff:169.254.169.254]/` 这类 IPv4-mapped 地址可绕过全部网段校验，
 * 直通云元数据服务。以下用例即为该缺陷的回归护栏。
 */

import test from "node:test";
import assert from "node:assert/strict";

import { assertSafeUrl, isIpLiteral, isIpForbidden, __testing } from "../urlSafety.js";

const { isForbiddenIp, expandIPv6 } = __testing;

/** 必须被拒绝的 URL —— 每条都是一个真实的 SSRF 绕过向量或其变体 */
const MUST_BLOCK = [
  // IPv4-mapped IPv6（历史绕过点，最高优先级）
  ["http://[::ffff:169.254.169.254]/latest/meta-data/", "云元数据 IPv4-mapped"],
  ["http://[::ffff:127.0.0.1]/", "回环 IPv4-mapped"],
  ["http://[::ffff:10.0.0.1]/", "私网 10/8 IPv4-mapped"],
  ["http://[::ffff:172.16.0.1]/", "私网 172.16/12 IPv4-mapped"],
  ["http://[::ffff:192.168.1.1]/", "私网 192.168/16 IPv4-mapped"],
  ["http://[::ffff:a00:1]/", "私网 IPv4-mapped 十六进制"],
  ["http://[::ffff:7f00:1]/", "回环 IPv4-mapped 十六进制"],
  // IPv6 特殊地址
  ["http://[::1]/", "IPv6 回环"],
  ["http://[0:0:0:0:0:0:0:1]/", "IPv6 回环完整写法"],
  ["http://[::]/", "IPv6 未指定"],
  ["http://[fe80::1]/", "IPv6 链路本地"],
  ["http://[fd00::1]/", "IPv6 ULA"],
  ["http://[fc00::1]/", "IPv6 ULA"],
  ["http://[ff02::1]/", "IPv6 组播"],
  ["http://[2001:db8::1]/", "IPv6 文档网段"],
  ["http://[100::1]/", "IPv6 丢弃前缀"],
  ["http://[fe80::1%25eth0]/", "带 zone id 的链路本地"],
  // IPv6 封装 IPv4
  ["http://[64:ff9b::7f00:1]/", "NAT64 映射"],
  ["http://[2002:7f00:1::]/", "6to4 封装回环"],
  ["http://[2002:a00:1::]/", "6to4 封装私网"],
  ["http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "Teredo"],
  ["http://[::127.0.0.1]/", "IPv4 兼容回环"],
  // IPv4 直接目标与整数/进制变体（URL 解析器会归一化）
  ["http://127.0.0.1/", "IPv4 回环"],
  ["http://169.254.169.254/", "IPv4 云元数据"],
  ["http://10.0.0.1/", "IPv4 私网"],
  ["http://192.168.1.1/", "IPv4 私网"],
  ["http://2130706433/", "十进制整数形式的 127.0.0.1"],
  ["http://0x7f000001/", "十六进制形式的 127.0.0.1"],
  ["http://017700000001/", "八进制形式的 127.0.0.1"],
  ["http://127.1/", "简写形式的 127.0.0.1"],
  ["http://127.0.1/", "简写形式的 127.0.0.1"],
  ["http://3232235777/", "十进制整数形式的 192.168.1.1"],
  // 协议 / 端口 / 凭据 / 黑名单
  ["file:///etc/passwd", "非 HTTP 协议"],
  ["gopher://127.0.0.1:6379/_", "gopher 协议"],
  ["ftp://example.com/x", "ftp 协议"],
  ["http://user:pass@example.com/", "URL 内嵌凭据"],
  ["http://example.com:22/", "SSH 端口"],
  ["http://example.com:3306/", "MySQL 端口"],
  ["http://example.com:6379/", "Redis 端口"],
  ["http://example.com:9200/", "Elasticsearch 端口"],
  ["http://metadata.google.internal/computeMetadata/v1/", "GCP 元数据主机名"],
];

test("assertSafeUrl 拒绝全部 SSRF 绕过向量", async () => {
  const leaked = [];
  for (const [url, desc] of MUST_BLOCK) {
    try {
      await assertSafeUrl(url, {});
      leaked.push(`${url}  (${desc})`);
    } catch {
      // 预期被拒绝
    }
  }
  assert.deepEqual(leaked, [], `以下 URL 未被拦截：\n${leaked.join("\n")}`);
});

test("IPv6 方括号不会被漏判为安全（核心回归点）", () => {
  // 带括号与不带括号必须得到完全一致的判定
  const pairs = [
    ["[::1]", "::1"],
    ["[::]", "::"],
    ["[fe80::1]", "fe80::1"],
    ["[fd00::1]", "fd00::1"],
    ["[::ffff:127.0.0.1]", "::ffff:127.0.0.1"],
    ["[::ffff:169.254.169.254]", "::ffff:169.254.169.254"],
    ["[::ffff:7f00:1]", "::ffff:7f00:1"],
  ];
  for (const [bracketed, plain] of pairs) {
    assert.equal(
      isIpForbidden(bracketed),
      isIpForbidden(plain),
      `${bracketed} 与 ${plain} 判定不一致`,
    );
    assert.equal(isIpForbidden(bracketed), true, `${bracketed} 应被判定为禁止`);
  }
});

test("IPv6 字面量识别不受方括号影响", () => {
  for (const v of ["[::1]", "::1", "[2001:db8::1]", "2001:db8::1", "[2606:4700::1111]"]) {
    assert.equal(isIpLiteral(v), true, `${v} 应被识别为 IP 字面量`);
  }
  // 畸形输入不应被误认为 IP
  for (const v of [":::", "1::2::3", "12345::1", "g::1", ""]) {
    assert.equal(isIpLiteral(v), false, `${v} 不应被识别为 IP 字面量`);
  }
});

test("公网 IPv4 / IPv6 不被误伤", () => {
  const allowed = [
    "8.8.8.8",
    "104.16.124.96",
    "172.32.0.1", // 172.16/12 边界外
    "192.169.0.1", // 192.168/16 边界外
    "11.0.0.1",
    "100.128.0.1", // CGNAT 边界外
    "198.20.0.1",
    "203.0.114.1",
    "223.255.255.255",
    "192.88.98.1",
    "2606:4700::1111",
    "2a00:1450:4001:80e::200e",
    "[2606:4700::1111]",
  ];
  for (const ip of allowed) {
    assert.equal(isForbiddenIp(ip), false, `${ip} 被误判为禁止`);
  }
});

test("expandIPv6 正确展开各类语法", () => {
  assert.deepEqual(expandIPv6("::1"), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(expandIPv6("::"), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(expandIPv6("::ffff:1.2.3.4"), [0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
  assert.deepEqual(expandIPv6("fe80::1%eth0"), [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(expandIPv6("2002:7f00:1::"), [0x2002, 0x7f00, 0x0001, 0, 0, 0, 0, 0]);
  // 畸形输入一律返回 null（调用方会按不安全处理）
  for (const bad of [":::", "1::2::3", "12345::1", "g::1", "", "1:2:3"]) {
    assert.equal(expandIPv6(bad), null, `${bad} 应解析失败`);
  }
});

test("合法公网 URL 通过校验（含 DNS 解析）", async () => {
  // 字面量公网 IP 不依赖 DNS，可稳定断言
  const result = await assertSafeUrl("http://104.16.124.96/file.zip", {});
  assert.equal(result.hostname, "104.16.124.96");
  assert.deepEqual(result.addresses, ["104.16.124.96"]);
});

test("allowPrivateNetwork 开关可放行内网（自托管场景）", async () => {
  const result = await assertSafeUrl("http://127.0.0.1:8080/x", { allowPrivateNetwork: true });
  assert.equal(result.hostname, "127.0.0.1");
});
