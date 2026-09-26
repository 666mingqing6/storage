/**
 * 内容幻数嗅探（magic bytes sniffing）
 *
 * 用途：判断「远程 URL 返回的实际内容」是什么，用于识别服务端错误页伪装成
 * 图片/视频的常见情况。纯字节级判断，不依赖数据库与预览设置。
 *
 * 设计原则：
 * - 只识别高置信度的签名（避免误判）
 * - 返回粗粒度族（image / video / audio / pdf / archive / text / binary / unknown）
 * - 未命中任何签名时，继续用「是否可打印文本」做兜底判断
 */

/**
 * 文件签名表
 * offset 表示签名在文件中的起始偏移
 */
const SIGNATURES = [
  // 图片
  { family: "image", mime: "image/jpeg", offset: 0, bytes: [0xff, 0xd8, 0xff] },
  { family: "image", mime: "image/png", offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { family: "image", mime: "image/gif", offset: 0, ascii: "GIF87a" },
  { family: "image", mime: "image/gif", offset: 0, ascii: "GIF89a" },
  { family: "image", mime: "image/bmp", offset: 0, bytes: [0x42, 0x4d] },
  { family: "image", mime: "image/webp", offset: 0, ascii: "RIFF", also: { offset: 8, ascii: "WEBP" } },
  { family: "image", mime: "image/avif", offset: 4, ascii: "ftypavif" },
  { family: "image", mime: "image/heic", offset: 4, ascii: "ftypheic" },
  { family: "image", mime: "image/tiff", offset: 0, bytes: [0x49, 0x49, 0x2a, 0x00] },
  { family: "image", mime: "image/tiff", offset: 0, bytes: [0x4d, 0x4d, 0x00, 0x2a] },
  { family: "image", mime: "image/x-icon", offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },

  // 视频
  { family: "video", mime: "video/mp4", offset: 4, ascii: "ftyp" },
  { family: "video", mime: "video/x-matroska", offset: 0, bytes: [0x1a, 0x45, 0xdf, 0xa3] },
  { family: "video", mime: "video/x-msvideo", offset: 8, ascii: "AVI " },
  { family: "video", mime: "video/quicktime", offset: 4, ascii: "ftypqt" },
  { family: "video", mime: "video/x-flv", offset: 0, ascii: "FLV" },

  // 音频
  { family: "audio", mime: "audio/mpeg", offset: 0, ascii: "ID3" },
  { family: "audio", mime: "audio/wav", offset: 0, ascii: "RIFF", also: { offset: 8, ascii: "WAVE" } },
  { family: "audio", mime: "audio/ogg", offset: 0, ascii: "OggS" },
  { family: "audio", mime: "audio/flac", offset: 0, ascii: "fLaC" },
  { family: "audio", mime: "audio/mp4", offset: 4, ascii: "ftypM4A" },

  // 文档
  { family: "pdf", mime: "application/pdf", offset: 0, ascii: "%PDF" },

  // 压缩包
  { family: "archive", mime: "application/zip", offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { family: "archive", mime: "application/zip", offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
  { family: "archive", mime: "application/x-rar-compressed", offset: 0, ascii: "Rar!" },
  { family: "archive", mime: "application/x-7z-compressed", offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { family: "archive", mime: "application/gzip", offset: 0, bytes: [0x1f, 0x8b] },
  { family: "archive", mime: "application/x-tar", offset: 257, ascii: "ustar" },

  // Office（OLE 复合文档：doc/xls/ppt 旧格式）
  { family: "office", mime: "application/msword", offset: 0, bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },

  // 可执行文件（转存场景下通常是危险信号，单独标记）
  { family: "executable", mime: "application/x-msdownload", offset: 0, ascii: "MZ" },
  { family: "executable", mime: "application/x-elf", offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { family: "executable", mime: "application/x-mach-binary", offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
];

/**
 * 判断字节数组是否匹配给定签名
 * @param {Uint8Array} bytes
 * @param {Object} sig
 * @returns {boolean}
 */
function matchSignature(bytes, sig) {
  const offset = sig.offset || 0;
  if (bytes.length < offset + 1) return false;

  if (sig.ascii) {
    const target = sig.ascii;
    if (bytes.length < offset + target.length) return false;
    for (let i = 0; i < target.length; i += 1) {
      if (bytes[offset + i] !== target.charCodeAt(i)) return false;
    }
  } else if (Array.isArray(sig.bytes)) {
    if (bytes.length < offset + sig.bytes.length) return false;
    for (let i = 0; i < sig.bytes.length; i += 1) {
      if (bytes[offset + i] !== sig.bytes[i]) return false;
    }
  } else {
    return false;
  }

  // 部分签名需要二次确认（如 RIFF 容器需检查偏移 8 处的类型标识）
  if (sig.also) {
    return matchSignature(bytes, { ...sig.also, offset: sig.also.offset });
  }

  return true;
}

/**
 * 判断内容是否像纯文本（用于识别 HTML/JSON 错误页）
 *
 * 判定方式：前若干字节可打印 ASCII 或 UTF-8 BOM / 常见 UTF-8 中文区间，
 * 且不含 NUL 等控制字符。
 *
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
function looksLikeText(bytes) {
  if (!bytes.length) return false;

  const sample = bytes.subarray(0, Math.min(bytes.length, 512));
  // NUL 字节几乎可确定是二进制
  for (let i = 0; i < sample.length; i += 1) {
    if (sample[i] === 0x00) return false;
  }

  let printable = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const b = sample[i];
    // 常见可打印 ASCII + 换行/制表/回车
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) {
      printable += 1;
    } else if (b >= 0x80) {
      // UTF-8 多字节序列（中文、日文等）
      printable += 1;
    } else {
      // 其他控制字符
      return false;
    }
  }

  return printable / sample.length > 0.9;
}

/**
 * 检测字节序列对应的内容族
 *
 * @param {Uint8Array} bytes 文件头部字节
 * @returns {{family: string, mime: string|null}}
 */
export function sniffContentKind(bytes) {
  if (!bytes || !bytes.length) {
    return { family: "unknown", mime: null };
  }

  for (const sig of SIGNATURES) {
    if (matchSignature(bytes, sig)) {
      return { family: sig.family, mime: sig.mime };
    }
  }

  if (looksLikeText(bytes)) {
    return { family: "text", mime: detectTextMime(bytes) };
  }

  return { family: "binary", mime: null };
}

/**
 * 在判定为文本后，进一步细分文本子类型
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function detectTextMime(bytes) {
  const head = latin1(bytes.subarray(0, Math.min(bytes.length, 256))).trim().toLowerCase();

  if (head.startsWith("<!doctype html") || head.startsWith("<html") || head.includes("<head") || head.includes("<body")) {
    return "text/html";
  }
  if (head.startsWith("<?xml")) return "application/xml";
  if (head.startsWith("{") || head.startsWith("[")) {
    try {
      JSON.parse(latin1(bytes.subarray(0, Math.min(bytes.length, 2048))));
      return "application/json";
    } catch {
      return "text/plain";
    }
  }
  return "text/plain";
}

/**
 * 将 Uint8Array 转为 latin1 字符串（仅用于头部关键字匹配）
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function latin1(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

/**
 * 将 MIME 归入粗粒度族，用于与嗅探结果做宽容比对
 * @param {string|null} mime
 * @returns {string}
 */
export function mimeFamily(mime) {
  const value = String(mime || "").toLowerCase().trim();
  if (!value) return "unknown";
  if (value === "application/octet-stream" || value === "binary/octet-stream") return "binary";
  if (value.startsWith("image/")) return "image";
  if (value.startsWith("video/")) return "video";
  if (value.startsWith("audio/")) return "audio";
  if (value.startsWith("text/")) return "text";
  if (value === "application/json" || value.includes("+json")) return "text";
  if (value === "application/xml" || value.includes("+xml")) return "text";
  if (value.includes("javascript")) return "text";
  if (value.includes("pdf")) return "pdf";
  if (value.includes("zip") || value.includes("compressed") || value.includes("gzip") || value.includes("x-tar") || value.includes("x-7z") || value.includes("rar")) {
    return "archive";
  }
  if (value.includes("msword") || value.includes("officedocument") || value.includes("ms-excel") || value.includes("ms-powerpoint")) {
    return "office";
  }
  return "binary";
}

/**
 * 由文件名扩展名推断 MIME（仅在响应头未给出可用类型时兜底）
 * @param {string|null} filename
 * @returns {string|null}
 */
export function guessMimeFromFilename(filename) {
  const name = String(filename || "");
  const idx = name.lastIndexOf(".");
  if (idx === -1 || idx === name.length - 1) return null;
  const ext = name.slice(idx + 1).toLowerCase();

  const table = {
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",
    avif: "image/avif",
    bmp: "image/bmp",
    svg: "image/svg+xml",
    ico: "image/x-icon",
    tif: "image/tiff",
    tiff: "image/tiff",
    mp4: "video/mp4",
    webm: "video/webm",
    mkv: "video/x-matroska",
    mov: "video/quicktime",
    avi: "video/x-msvideo",
    flv: "video/x-flv",
    mp3: "audio/mpeg",
    wav: "audio/wav",
    flac: "audio/flac",
    ogg: "audio/ogg",
    m4a: "audio/mp4",
    pdf: "application/pdf",
    zip: "application/zip",
    rar: "application/x-rar-compressed",
    "7z": "application/x-7z-compressed",
    gz: "application/gzip",
    tar: "application/x-tar",
    txt: "text/plain",
    md: "text/markdown",
    json: "application/json",
    xml: "application/xml",
    html: "text/html",
    htm: "text/html",
    csv: "text/csv",
    doc: "application/msword",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  };

  return table[ext] || null;
}

export const __testing = {
  SIGNATURES,
  matchSignature,
  looksLikeText,
  detectTextMime,
  latin1,
};
