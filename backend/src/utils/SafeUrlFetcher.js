/**
 * 安全远程抓取器（SafeUrlFetcher）
 *
 * 为「远程 URL 转存」提供两件事：
 * 1. fetchRemoteMetadata —— 只发 HEAD（必要时退化 GET Range）读取元信息，不下载正文
 * 2. fetchRemoteStream   —— 返回可管道写入存储的 ReadableStream，并在流头部做幻数校验
 *
 * 设计要点：
 * - 手动跟随重定向（redirect: "manual"），每一跳都重新执行 SSRF 校验，
 *   避免「首次校验通过 → 302 跳到内网」的经典绕过。
 * - 流式返回，不将整个文件读入内存；仅在头部暂存少量字节用于幻数嗅探。
 * - 幻数校验（magic bytes）用于识别远程服务返回的伪装内容：
 *   例如把一个 HTML 错误页当作 image/jpeg 下发——这是 URL 转存场景最常见的问题。
 */

import { ValidationError, DriverError } from "../http/errors.js";
import { ApiStatus } from "../constants/index.js";
import { assertSafeUrl } from "./urlSafety.js";
import { sniffContentKind, mimeFamily, guessMimeFromFilename } from "./contentSniffer.js";

/** 默认最大重定向跳数 */
const DEFAULT_MAX_REDIRECTS = 5;
/** 幻数嗅探所需的最小字节数（需覆盖 PDF/RIFF/MP4 等较长魔数） */
const SNIFF_BYTES = 32;

/**
 * 规范化响应头里的 Content-Type，去掉 charset 等参数
 * @param {string|null} raw
 * @returns {string|null}
 */
function normalizeContentType(raw) {
  if (!raw) return null;
  const value = String(raw).split(";")[0].trim().toLowerCase();
  return value || null;
}

/**
 * 从 URL 路径中提取候选文件名
 * @param {URL} parsed
 * @returns {string|null}
 */
function filenameFromUrl(parsed) {
  try {
    const segments = parsed.pathname.split("/").filter(Boolean);
    if (!segments.length) return null;
    const last = segments[segments.length - 1];
    if (!last || last.endsWith(".")) return null;
    try {
      return decodeURIComponent(last);
    } catch {
      return last;
    }
  } catch {
    return null;
  }
}

/**
 * 从 Content-Disposition 解析文件名
 * 兼容 filename*=UTF-8''xxx 与 filename="xxx" 两种写法
 * @param {string|null} header
 * @returns {string|null}
 */
function filenameFromContentDisposition(header) {
  if (!header) return null;
  const value = String(header);

  // RFC 5987: filename*=UTF-8''%E4%B8%AD%E6%96%87.png
  const extended = value.match(/filename\*=(?:UTF-8|utf-8)''([^;]+)/i);
  if (extended && extended[1]) {
    try {
      return decodeURIComponent(extended[1].trim());
    } catch {
      return extended[1].trim();
    }
  }

  // 常规: filename="a.png" 或 filename=a.png
  const plain = value.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/i);
  if (plain && plain[1]) {
    return plain[1].replace(/['"]/g, "").trim() || null;
  }

  return null;
}

/**
 * 统一的响应头读取（兼容 Headers 对象与普通对象）
 * @param {Headers} headers
 * @param {string} name
 * @returns {string|null}
 */
function readHeader(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === "function") {
    return headers.get(name);
  }
  return headers[name] ?? headers[name.toLowerCase()] ?? null;
}

/**
 * 发起一次带 SSRF 防护的外呼，并手动跟随重定向
 *
 * @param {string} rawUrl
 * @param {Object} [options]
 * @param {string} [options.method="GET"]
 * @param {HeadersInit} [options.headers]
 * @param {number} [options.maxRedirects=5]
 * @param {AbortSignal} [options.signal]
 * @param {boolean} [options.allowPrivateNetwork=false]
 * @param {string[]} [options.hostnameBlacklist]
 * @returns {Promise<{response: Response, finalUrl: string, redirects: number}>}
 */
export async function safeFetch(rawUrl, options = {}) {
  const {
    method = "GET",
    headers = {},
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    signal,
    allowPrivateNetwork = false,
    hostnameBlacklist = [],
  } = options;

  let currentUrl = rawUrl;
  let redirects = 0;

  for (;;) {
    // 每一跳都重新执行完整 SSRF 校验
    const { url: validatedUrl } = await assertSafeUrl(currentUrl, {
      allowPrivateNetwork,
      hostnameBlacklist,
      requireDnsResolution: true,
    });

    const response = await fetch(validatedUrl, {
      method,
      headers,
      redirect: "manual", // 手动处理，确保逐跳校验
      signal,
    });

    const status = response.status;
    const isRedirect = status >= 300 && status < 400;
    if (!isRedirect) {
      return { response, finalUrl: validatedUrl, redirects };
    }

    const location = readHeader(response.headers, "location");
    if (!location) {
      // 3xx 但没有 Location：视为异常响应，交由调用方判断
      return { response, finalUrl: validatedUrl, redirects };
    }

    redirects += 1;
    if (redirects > maxRedirects) {
      throw new DriverError(`重定向次数超过上限（${maxRedirects} 次），已终止`, {
        status: ApiStatus.BAD_REQUEST,
        code: "URL_TRANSFER.TOO_MANY_REDIRECTS",
        expose: true,
      });
    }

    // 解析相对 Location
    currentUrl = new URL(location, validatedUrl).toString();

    // 主动释放上一个响应体，避免连接堆积
    try {
      response.body?.cancel?.();
    } catch {
      // ignore
    }
  }
}

/**
 * 读取远端文件元信息（不发正文）
 *
 * 策略：
 * - 优先 HEAD，成本最低
 * - 若 HEAD 返回 405/403/501（很多 CDN / 网盘不支持 HEAD），退化为
 *   GET + Range: bytes=0-0，只取 1 字节，避免拉全量
 * - 若对端返回 Content-Range，则从中解析总长度
 *
 * @param {string} rawUrl
 * @param {Object} [options] 透传给 safeFetch
 * @returns {Promise<Object>} 元信息
 */
export async function fetchRemoteMetadata(rawUrl, options = {}) {
  const { allowPrivateNetwork = false, hostnameBlacklist = [] } = options;
  const fetchOptions = { allowPrivateNetwork, hostnameBlacklist };

  let response = null;
  let finalUrl = rawUrl;
  let headUnsupported = false;

  try {
    const result = await safeFetch(rawUrl, { ...fetchOptions, method: "HEAD" });
    response = result.response;
    finalUrl = result.finalUrl;
    if (response.status === 405 || response.status === 403 || response.status === 501) {
      headUnsupported = true;
    }
  } catch (error) {
    // HEAD 阶段的网络错误允许退化到 GET 再试一次
    if (error instanceof ValidationError) throw error;
    headUnsupported = true;
  }

  if (headUnsupported || !response || !response.ok) {
    const result = await safeFetch(rawUrl, {
      ...fetchOptions,
      method: "GET",
      headers: { Range: "bytes=0-0" },
    });
    response = result.response;
    finalUrl = result.finalUrl;
    try {
      response.body?.cancel?.();
    } catch {
      // ignore
    }
  }

  if (!response.ok) {
    throw new DriverError(`远程服务器返回错误状态：HTTP ${response.status}`, {
      status: ApiStatus.BAD_REQUEST,
      code: "URL_TRANSFER.REMOTE_HTTP_ERROR",
      expose: true,
      details: { remoteStatus: response.status },
    });
  }

  const contentType = normalizeContentType(readHeader(response.headers, "content-type"));
  const disposition = filenameFromContentDisposition(readHeader(response.headers, "content-disposition"));

  // 解析文件大小：优先 content-length，其次 content-range 的总量
  let size = null;
  const contentLength = readHeader(response.headers, "content-length");
  if (contentLength && /^\d+$/.test(String(contentLength).trim())) {
    size = parseInt(String(contentLength).trim(), 10);
  }
  if ((size === null || size <= 1)) {
    const contentRange = readHeader(response.headers, "content-range");
    const totalMatch = contentRange && String(contentRange).match(/\/(\d+)\s*$/);
    if (totalMatch && totalMatch[1]) {
      const total = parseInt(totalMatch[1], 10);
      if (Number.isFinite(total) && total > 0) size = total;
    }
  }

  const parsedFinal = new URL(finalUrl);
  const filename = disposition || filenameFromUrl(parsedFinal) || "download";

  return {
    url: rawUrl,
    finalUrl,
    filename,
    contentType,
    size: size && size > 0 ? size : null,
    lastModified: readHeader(response.headers, "last-modified"),
    etag: readHeader(response.headers, "etag"),
    acceptRanges: /bytes/i.test(String(readHeader(response.headers, "accept-ranges") || "")),
  };
}

/**
 * 以流的方式抓取远程内容
 *
 * 返回的 stream 未读取时不会产生任何字节。在流的最前面插入幻数嗅探逻辑：
 * - 累积最初 SNIFF_BYTES 字节
 * - 与声明/推断的内容类型比对
 * - 若明显不匹配（例如声明 image/jpeg 但实际是 HTML），立即终止并抛错
 *
 * 注意：校验失败在流已开始消费后发生，此时上层可能已经收到 200。
 * 因此本函数同时提供 validateContentKind()，供调用方在写盘前先做一次预检。
 *
 * @param {string} rawUrl
 * @param {Object} [options]
 * @returns {Promise<{stream: ReadableStream, finalUrl: string, contentType: string|null, size: number|null}>}
 */
export async function fetchRemoteStream(rawUrl, options = {}) {
  const {
    allowPrivateNetwork = false,
    hostnameBlacklist = [],
    headers = {},
    expectedContentType = null,
    requireContentMatch = false,
    maxBytes = null,
    signal,
  } = options;

  const { response, finalUrl } = await safeFetch(rawUrl, {
    allowPrivateNetwork,
    hostnameBlacklist,
    headers,
    signal,
    method: "GET",
  });

  if (!response.ok) {
    throw new DriverError(`远程服务器返回错误状态：HTTP ${response.status}`, {
      status: ApiStatus.BAD_REQUEST,
      code: "URL_TRANSFER.REMOTE_HTTP_ERROR",
      expose: true,
      details: { remoteStatus: response.status },
    });
  }

  if (!response.body) {
    throw new DriverError("远程服务器未返回可读取的内容", {
      status: ApiStatus.BAD_REQUEST,
      code: "URL_TRANSFER.EMPTY_BODY",
      expose: true,
    });
  }

  const contentType = normalizeContentType(readHeader(response.headers, "content-type"));
  const contentLength = readHeader(response.headers, "content-length");
  const declaredSize = contentLength && /^\d+$/.test(String(contentLength).trim())
    ? parseInt(String(contentLength).trim(), 10)
    : null;

  // 声明长度即超限时提前拒绝，避免无谓流量
  if (maxBytes && declaredSize && declaredSize > maxBytes) {
    try {
      response.body.cancel?.();
    } catch {
      // ignore
    }
    throw new ValidationError("远程文件超过允许的最大大小");
  }

  const state = {
    contentType,
    expectedContentType: normalizeContentType(expectedContentType),
    requireContentMatch,
    maxBytes,
    bytesSeen: 0,
    sniffed: false,
    validated: !requireContentMatch, // 未开启强校验时直接视为已通过
  };

  const validatedStream = buildSniffingStream(response.body, state);

  return {
    stream: validatedStream,
    finalUrl,
    contentType,
    size: declaredSize && declaredSize > 0 ? declaredSize : null,
    acceptRanges: /bytes/i.test(String(readHeader(response.headers, "accept-ranges") || "")),
  };
}

/**
 * 构造带幻数嗅探与体积上限保护的流
 * @param {ReadableStream} source
 * @param {Object} state
 * @returns {ReadableStream}
 */
function buildSniffingStream(source, state) {
  const reader = source.getReader();
  let buffer = new Uint8Array(0);

  const appendBuffer = (chunk) => {
    const merged = new Uint8Array(buffer.length + chunk.length);
    merged.set(buffer, 0);
    merged.set(chunk, buffer.length);
    buffer = merged;
  };

  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await reader.read();

      if (done) {
        // 流结束时若仍未完成嗅探校验，对已经攒到的字节做最后一次判断
        if (!state.sniffed && buffer.length > 0) {
          const result = checkContentKind(buffer, state);
          state.sniffed = true;
          if (!result.ok) {
            controller.error(new ValidationError(result.message));
            return;
          }
        }
        controller.close();
        return;
      }

      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);

      // 体积上限保护（对端 Content-Length 不可信或缺失时的兜底）
      state.bytesSeen += chunk.length;
      if (state.maxBytes && state.bytesSeen > state.maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // ignore
        }
        controller.error(new ValidationError("远程文件超过允许的最大大小"));
        return;
      }

      // 首次嗅探：需要攒够 SNIFF_BYTES 或等到流结束
      if (!state.sniffed) {
        appendBuffer(chunk);
        if (buffer.length < SNIFF_BYTES) {
          // 继续读取，暂不外发
          return;
        }
        const result = checkContentKind(buffer, state);
        state.sniffed = true;
        if (!result.ok) {
          try {
            await reader.cancel();
          } catch {
            // ignore
          }
          controller.error(new ValidationError(result.message));
          return;
        }
        const out = buffer;
        buffer = new Uint8Array(0);
        controller.enqueue(out);
        return;
      }

      controller.enqueue(chunk);
    },

    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } catch {
        // ignore
      }
    },
  });
}

/**
 * 依据已嗅探字节判断内容类型是否与声明一致
 *
 * 判定逻辑（保守，避免误报）：
 * - 只有当「字节推断出的族」与「响应头声明的族」落在不同族时才算不匹配
 * - 声明 application/octet-stream 等通用二进制 → 一律放行
 * - 字节无法识别（unknown）→ 放行，交给上层按扩展名处理
 * - 文本伪装成媒体是最典型的失败模式（错误页），单独给出更准确的提示
 *
 * @param {Uint8Array} bytes
 * @param {Object} state
 * @returns {{ok: boolean, message?: string, detected?: string|null}}
 */
function checkContentKind(bytes, state) {
  if (!state.requireContentMatch) {
    return { ok: true };
  }

  const { family: detectedFamily, mime: detectedMime } = sniffContentKind(bytes);
  const declaredType = state.expectedContentType || state.contentType;

  if (detectedFamily === "unknown") {
    return { ok: true, detected: null };
  }

  if (!declaredType) {
    return { ok: true, detected: detectedFamily };
  }

  const declaredFamily = mimeFamily(declaredType);

  // 通用二进制容器不参与比对
  if (declaredFamily === "binary" || declaredFamily === "unknown") {
    return { ok: true, detected: detectedFamily };
  }

  if (declaredFamily === detectedFamily) {
    return { ok: true, detected: detectedFamily };
  }

  // 文本（HTML 错误页 / JSON 报错）伪装成媒体文件
  if (detectedFamily === "text" && declaredFamily !== "text") {
    return {
      ok: false,
      detected: detectedFamily,
      message: `远程内容与声明类型不匹配：声明为 ${declaredType}，实际内容为${detectedMime ? ` ${detectedMime}` : "文本"}（可能是错误页或登录页）`,
    };
  }

  return {
    ok: false,
    detected: detectedFamily,
    message: `远程内容与声明类型不匹配：声明为 ${declaredType}，实际内容为${detectedMime || detectedFamily}`,
  };
}

/**
 * 结合响应头 MIME、文件名扩展名与字节嗅探，给出最终可用的内容类型
 *
 * 优先级：字节嗅探（最可信） > 响应头声明 > 扩展名推断
 * 但仅当响应头缺失或为通用二进制时，才允许字节/扩展名覆盖声明值，
 * 避免把服务端明确声明的类型改坏。
 *
 * @param {Uint8Array|null} sniffBytes
 * @param {string|null} declaredMime
 * @param {string} filename
 * @returns {string}
 */
export function resolveContentType(sniffBytes, declaredMime, filename) {
  const normalizedDeclared = normalizeContentType(declaredMime);

  const isDeclaredUsable =
    normalizedDeclared && normalizedDeclared !== "application/octet-stream" && normalizedDeclared !== "binary/octet-stream";

  if (isDeclaredUsable) {
    return normalizedDeclared;
  }

  // 声明不可用时，用字节嗅探
  if (sniffBytes && sniffBytes.length) {
    const { mime: sniffedMime, family } = sniffContentKind(sniffBytes);
    if (sniffedMime && family !== "text") {
      return sniffedMime;
    }
    // 文本类内容：保留更精确的文本 MIME（如 text/html），否则退回扩展名
    if (sniffedMime && family === "text") {
      const fromName = guessMimeFromFilename(filename);
      return fromName || sniffedMime;
    }
  }

  // 最后用扩展名兜底
  return guessMimeFromFilename(filename) || normalizedDeclared || "application/octet-stream";
}

export const __testing = {
  normalizeContentType,
  filenameFromUrl,
  filenameFromContentDisposition,
  checkContentKind,
  SNIFF_BYTES,
};
