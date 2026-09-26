/**
 * contentSniffer.js 回归测试
 *
 * 运行：node --test src/utils/__tests__/contentSniffer.test.js
 *
 * 目的：确保「HTML 错误页伪装成图片/视频」能被识别出来。
 * 许多图床 / CDN 在文件不存在或鉴权失败时会返回 200 + text/html，
 * 若不校验幻数，会把错误页当作媒体文件存进对象存储。
 */

import test from "node:test";
import assert from "node:assert/strict";

import { sniffContentKind, mimeFamily, guessMimeFromFilename } from "../contentSniffer.js";

const bytes = (...arr) => new Uint8Array(arr);
const ascii = (s) => new Uint8Array([...s].map((c) => c.charCodeAt(0)));

/** 把多个字节片段拼成一个样本 */
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

test("识别常见图片格式", () => {
  const jpeg = concat(bytes(0xff, 0xd8, 0xff, 0xe0), ascii("JFIF"));
  const png = concat(bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a));
  const gif = ascii("GIF89a");
  const webp = concat(ascii("RIFF"), bytes(0, 0, 0, 0), ascii("WEBP"));

  assert.equal(sniffContentKind(jpeg).mime, "image/jpeg");
  assert.equal(sniffContentKind(png).mime, "image/png");
  assert.equal(sniffContentKind(gif).mime, "image/gif");
  assert.equal(sniffContentKind(webp).mime, "image/webp");
});

test("识别视频与音频格式", () => {
  const mp4 = concat(bytes(0, 0, 0, 0x18), ascii("ftyp"), ascii("isom"));
  const pdf = ascii("%PDF-1.7");

  assert.equal(sniffContentKind(mp4).family, "video");
  assert.equal(sniffContentKind(pdf).mime, "application/pdf");
});

test("识别压缩包格式", () => {
  const zip = concat(bytes(0x50, 0x4b, 0x03, 0x04));
  assert.equal(sniffContentKind(zip).family, "archive");
});

test("识别 HTML / JSON —— 关键：错误页伪装检测", () => {
  const html = ascii("<!DOCTYPE html><html><head><title>404 Not Found</title></head></html>");
  const json = ascii('{"error":"file not found","code":404}');

  assert.equal(sniffContentKind(html).mime, "text/html");
  assert.equal(sniffContentKind(html).family, "text");
  assert.equal(sniffContentKind(json).mime, "application/json");
});

test("HTML 与图/视频属于不同 family（伪装可被识别）", () => {
  const html = ascii("<html><body>403 Forbidden</body></html>");
  const htmlFamily = sniffContentKind(html).family;
  assert.notEqual(htmlFamily, mimeFamily("image/jpeg"));
  assert.notEqual(htmlFamily, mimeFamily("video/mp4"));
  assert.equal(mimeFamily("image/jpeg"), "image");
  assert.equal(mimeFamily("video/mp4"), "video");
  assert.equal(mimeFamily("text/html"), "text");
});

test("未知/过短的字节流不抛异常", () => {
  assert.doesNotThrow(() => sniffContentKind(new Uint8Array(0)));
  assert.doesNotThrow(() => sniffContentKind(bytes(0x01)));
  assert.doesNotThrow(() => sniffContentKind(new Uint8Array(3)));
});

test("按文件名推断 MIME", () => {
  assert.equal(guessMimeFromFilename("photo.jpg"), "image/jpeg");
  assert.equal(guessMimeFromFilename("clip.mp4"), "video/mp4");
  assert.equal(guessMimeFromFilename("doc.pdf"), "application/pdf");
  assert.equal(guessMimeFromFilename("archive.zip"), "application/zip");
  // 未知扩展名返回假值，由调用方兜底
  assert.ok(!guessMimeFromFilename("file.unknownext"));
});
