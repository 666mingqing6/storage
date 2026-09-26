/**
 * 远程 URL 转存服务（前端 API 层）
 *
 * 与 urlUploadService 的区别：
 * - urlUploadService：浏览器先下载远程文件，再走 Uppy 上传（受 CORS 与浏览器内存限制）
 * - urlTransferService：仅提交 URL，由 Cloudflare Worker 服务端拉取并直接写入存储
 *   → 不受浏览器 CORS 约束，无需在浏览器侧缓冲整个文件
 *
 * 对应后端端点：
 * - POST /api/share/url/probe    —— 安全校验 + 元信息探测（不下载正文）
 * - POST /api/share/url/transfer —— 执行转存并返回可访问链接
 */

import { post } from "../client";

/**
 * 探测远程 URL 的可用性与元信息
 *
 * @param {string} url 远程文件 URL
 * @param {Object} [options]
 * @param {string} [options.filename] 用户自定义文件名（用于回显探测结果）
 * @returns {Promise<Object>} 探测结果
 */
export async function probeUrl(url, options = {}) {
  return await post("share/url/probe", {
    url,
    filename: options.filename || null,
  });
}

/**
 * 执行远程 URL 转存
 *
 * @param {Object} payload
 * @param {string} payload.url 远程文件 URL
 * @param {string} [payload.filename] 目标文件名（留空则自动从 URL / 响应头推断）
 * @param {string} [payload.storage_config_id] 目标存储配置 ID
 * @param {string} [payload.path] 目标目录
 * @param {string} [payload.slug] 自定义分享链接后缀
 * @param {string} [payload.remark] 备注
 * @param {string} [payload.password] 访问密码
 * @param {number|string} [payload.expires_in] 过期小时数，0 表示永不过期
 * @param {number|string} [payload.max_views] 最大查看次数，0 表示不限制
 * @param {boolean} [payload.override] 是否覆盖同名分享记录
 * @returns {Promise<Object>} 转存结果（含 previewUrl / downloadUrl）
 */
export async function transferUrl(payload) {
  const body = {
    url: payload.url,
    filename: payload.filename || null,
    storage_config_id: payload.storage_config_id || null,
    path: payload.path || null,
    slug: payload.slug || null,
    remark: payload.remark || "",
    password: payload.password || null,
    expires_in: Number(payload.expires_in) || 0,
    max_views: Math.max(0, Number(payload.max_views) || 0),
    override: Boolean(payload.override),
  };

  return await post("share/url/transfer", body);
}
