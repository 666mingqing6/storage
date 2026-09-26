/**
 * UrlTransferService —— 远程 URL 转存服务
 *
 * 职责：
 * 1. 检测远程 URL 的可用性与元信息（不下载正文）
 * 2. 服务端流式拉取远程内容，直接管道写入目标存储
 * 3. 以「上传即分享」的方式建档，返回可访问的链接
 *
 * 安全边界（与 urlSafety / SafeUrlFetcher 协同）：
 * - 所有用户提供的 URL 必须经过 SSRF 校验
 * - 重定向逐跳校验
 * - 文件体积受系统配置与存储配额双重约束
 * - 流头部幻数校验，识别「错误页伪装成媒体」的情况
 *
 * 与前端直连中转方案的区别：
 * 该实现由 Cloudflare Worker 直接 fetch → 管道写入存储，
 * 全程不落盘、不在浏览器侧缓冲，因此不受浏览器 CORS 限制，
 * 也不受浏览器内存限制；代价是受 Worker 单请求时长与内存约束，
 * 适合中小组件文件（默认上限由系统 max_upload_size 控制）。
 */

import { ValidationError, DriverError } from "../http/errors.js";
import { UserType, ApiStatus } from "../constants/index.js";
import { ensureRepositoryFactory } from "../utils/repositories.js";
import { StorageQuotaGuard } from "../storage/usage/StorageQuotaGuard.js";
import { ShareRecordService } from "./share/ShareRecordService.js";
import { fetchRemoteMetadata, fetchRemoteStream, resolveContentType } from "../utils/SafeUrlFetcher.js";
import { assertSafeUrl } from "../utils/urlSafety.js";
import { guessMimeFromFilename } from "../utils/contentSniffer.js";

/** 系统默认最大上传体积（MB），与 FileShareService 保持一致 */
const DEFAULT_MAX_UPLOAD_SIZE_MB = 100;

/**
 * 规范化用户指定的文件名
 *
 * 规则：
 * - 去掉路径分隔符与目录穿越片段，只保留纯文件名
 * - 剔除 Windows / POSIX 下的非法字符
 * - 限制长度，避免超出存储后端 Key 长度限制
 *
 * @param {string} input
 * @returns {string}
 */
export function sanitizeFilename(input) {
  let name = String(input ?? "").trim();

  // 仅保留最后一段，阻断 a/b/../c 形式的路径注入
  name = name.replace(/\\/g, "/");
  const segments = name.split("/").filter((seg) => seg && seg !== "." && seg !== "..");
  name = segments.length ? segments[segments.length - 1] : "";

  // 剔除控制字符与文件系统非法字符
  name = name.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "");

  // 去掉首尾空白与点（Windows 不允许以点结尾）
  name = name.replace(/^[\s.]+/, "").replace(/[\s.]+$/, "");

  if (!name) return "";

  // 限制长度（保留扩展名）
  const MAX_LEN = 180;
  if (name.length > MAX_LEN) {
    const dot = name.lastIndexOf(".");
    if (dot > 0 && name.length - dot <= 16) {
      const ext = name.slice(dot);
      name = name.slice(0, MAX_LEN - ext.length) + ext;
    } else {
      name = name.slice(0, MAX_LEN);
    }
  }

  return name;
}

export class UrlTransferService {
  /**
   * @param {D1Database} db
   * @param {string} encryptionSecret
   * @param {Object} repositoryFactory
   */
  constructor(db, encryptionSecret, repositoryFactory = null) {
    this.db = db;
    this.encryptionSecret = encryptionSecret;
    this.repositoryFactory = ensureRepositoryFactory(db, repositoryFactory);
    this.quota = new StorageQuotaGuard(db, encryptionSecret, this.repositoryFactory);
    this.records = new ShareRecordService(db, encryptionSecret, this.repositoryFactory);
  }

  /**
   * 读取系统配置的最大上传体积（字节）
   * @returns {Promise<number>}
   */
  async getMaxUploadBytes() {
    const systemRepo = this.repositoryFactory?.getSystemRepository?.();
    if (!systemRepo) {
      return DEFAULT_MAX_UPLOAD_SIZE_MB * 1024 * 1024;
    }
    const setting = await systemRepo.getSettingMetadata("max_upload_size").catch(() => null);
    const limitMb = setting?.value ? parseInt(setting.value, 10) : DEFAULT_MAX_UPLOAD_SIZE_MB;
    const safeMb = Number.isFinite(limitMb) && limitMb > 0 ? limitMb : DEFAULT_MAX_UPLOAD_SIZE_MB;
    return safeMb * 1024 * 1024;
  }

  /**
   * 读取 URL 转存相关的安全策略配置
   * 支持通过系统设置覆盖默认行为，便于自托管场景适配内网源站
   * @returns {Promise<{allowPrivateNetwork: boolean, hostnameBlacklist: string[]}>}
   */
  async getSafetyPolicy() {
    const systemRepo = this.repositoryFactory?.getSystemRepository?.();
    const defaults = { allowPrivateNetwork: false, hostnameBlacklist: [] };
    if (!systemRepo) return defaults;

    try {
      const setting = await systemRepo.getSettingMetadata("url_transfer_policy").catch(() => null);
      if (!setting?.value) return defaults;
      const parsed = JSON.parse(setting.value);
      return {
        allowPrivateNetwork: parsed?.allow_private_network === true || parsed?.allow_private_network === 1,
        hostnameBlacklist: Array.isArray(parsed?.hostname_blacklist)
          ? parsed.hostname_blacklist.filter((item) => typeof item === "string" && item.trim())
          : [],
      };
    } catch {
      return defaults;
    }
  }

  /**
   * 解析当前用户可用的存储配置
   *
   * 与 FileShareService.resolveStorageConfig 保持一致的可信边界：
   * 管理员可用全部配置；API Key 仅能用 is_public 且通过 ACL 白名单的配置。
   *
   * @param {Object} params
   * @returns {Promise<Object|null>}
   */
  async resolveStorageConfig({ storageConfigId = null, userType = UserType.ADMIN, userIdOrInfo = null, withSecrets = false } = {}) {
    const repo = this.repositoryFactory.getStorageConfigRepository();
    if (!repo) return null;

    const requirePublic = userType === UserType.API_KEY;
    const findByIdFn =
      withSecrets && typeof repo.findByIdWithSecrets === "function"
        ? repo.findByIdWithSecrets.bind(repo)
        : repo.findById.bind(repo);

    let allowedConfigIdsSet = null;

    if (requirePublic && this.repositoryFactory?.getPrincipalStorageAclRepository) {
      const subjectId = typeof userIdOrInfo === "string" ? userIdOrInfo : userIdOrInfo?.id ?? null;
      if (subjectId) {
        try {
          const aclRepo = this.repositoryFactory.getPrincipalStorageAclRepository();
          const allowedIds = await aclRepo.findConfigIdsBySubject("API_KEY", subjectId);
          if (Array.isArray(allowedIds) && allowedIds.length > 0) {
            allowedConfigIdsSet = new Set(allowedIds);
          }
        } catch (error) {
          console.warn("[UrlTransfer] 加载存储 ACL 失败，回退到仅基于 is_public 的选择：", error);
        }
      }
    }

    const isAllowed = (cfg) => {
      if (!cfg) return false;
      if (requirePublic && cfg.is_public !== 1) return false;
      if (allowedConfigIdsSet && !allowedConfigIdsSet.has(cfg.id)) return false;
      return true;
    };

    if (storageConfigId) {
      const existing =
        requirePublic && typeof repo.findPublicById === "function"
          ? await repo.findPublicById(storageConfigId).catch(() => null)
          : await findByIdFn(storageConfigId).catch(() => null);
      if (isAllowed(existing)) return existing;
    }

    const config = await repo.findDefault({ requirePublic, withSecrets }).catch(() => null);
    if (isAllowed(config)) return config;

    const fallbackList = requirePublic ? await repo.findPublic().catch(() => []) : await repo.findAll().catch(() => []);
    if (!Array.isArray(fallbackList) || fallbackList.length === 0) return null;
    if (!allowedConfigIdsSet) return fallbackList[0];
    return fallbackList.find((cfg) => isAllowed(cfg)) || null;
  }

  /**
   * 检测 URL：校验安全性并读取元信息
   *
   * @param {Object} params
   * @param {string} params.url
   * @param {string} [params.overrideFilename] 用户自定义文件名，用于覆盖探测结果
   * @returns {Promise<Object>} 探测结果，可直接喂给前端预览
   */
  async probe({ url, overrideFilename = null }) {
    const policy = await this.getSafetyPolicy();

    // 先做一层快速校验，尽早给出明确错误（避免无意义的网络请求）
    await assertSafeUrl(url, {
      allowPrivateNetwork: policy.allowPrivateNetwork,
      hostnameBlacklist: policy.hostnameBlacklist,
      requireDnsResolution: true,
    });

    const metadata = await fetchRemoteMetadata(url, {
      allowPrivateNetwork: policy.allowPrivateNetwork,
      hostnameBlacklist: policy.hostnameBlacklist,
    });

    const maxBytes = await this.getMaxUploadBytes();
    const sanitizedOverride = overrideFilename ? sanitizeFilename(overrideFilename) : "";
    const finalFilename = sanitizedOverride || sanitizeFilename(metadata.filename) || "download";

    // 依据文件名与响应头推断最终类型；此处不做字节嗅探（探测阶段不下载正文）
    const guessedType = guessMimeFromFilename(finalFilename);
    const contentType =
      metadata.contentType && metadata.contentType !== "application/octet-stream"
        ? metadata.contentType
        : guessedType || metadata.contentType || "application/octet-stream";

    const sizeKnown = typeof metadata.size === "number" && metadata.size > 0;
    const exceedsLimit = sizeKnown && metadata.size > maxBytes;

    return {
      url,
      finalUrl: metadata.finalUrl,
      filename: finalFilename,
      detectedFilename: sanitizeFilename(metadata.filename) || null,
      contentType,
      size: sizeKnown ? metadata.size : null,
      sizeKnown,
      lastModified: metadata.lastModified || null,
      etag: metadata.etag || null,
      acceptRanges: metadata.acceptRanges === true,
      maxSizeBytes: maxBytes,
      exceedsMaxSize: exceedsLimit,
      redirectCount: metadata.finalUrl !== url ? 1 : 0,
    };
  }

  /**
   * 执行转存：拉取远程内容并写入存储，随后建立分享记录
   *
   * @param {Object} params
   * @param {string} params.url 远程 URL
   * @param {string} params.userIdOrInfo
   * @param {string} params.userType
   * @param {Object} [params.options] 分享选项（storage_config_id / path / slug / password / expires_in / max_views / remark / override）
   * @param {Request} [params.request] 原始请求对象，用于构建分享链接的基地址
   * @returns {Promise<Object>} 分享记录
   */
  async transfer({ url, userIdOrInfo, userType, options = {}, request = null }) {
    const policy = await this.getSafetyPolicy();
    const maxBytes = await this.getMaxUploadBytes();

    // 1) 安全校验 + 元信息探测
    await assertSafeUrl(url, {
      allowPrivateNetwork: policy.allowPrivateNetwork,
      hostnameBlacklist: policy.hostnameBlacklist,
      requireDnsResolution: true,
    });

    const metadata = await fetchRemoteMetadata(url, {
      allowPrivateNetwork: policy.allowPrivateNetwork,
      hostnameBlacklist: policy.hostnameBlacklist,
    });

    const customName = options.filename ? sanitizeFilename(options.filename) : "";
    const filename = customName || sanitizeFilename(metadata.filename) || "download";
    if (!filename) {
      throw new ValidationError("无法确定目标文件名，请手动指定");
    }

    const directory = options.path || null;

    // 2) 解析目标存储配置
    const cfg = await this.resolveStorageConfig({
      storageConfigId: options.storage_config_id || null,
      userType,
      userIdOrInfo,
      withSecrets: false,
    });
    if (!cfg) {
      throw new ValidationError("未找到可用的存储配置，无法转存");
    }
    if (!cfg.storage_type) {
      throw new ValidationError("存储配置缺少 storage_type");
    }

    // 3) 体积上限前置校验（对端声明了长度时才能提前拦截）
    if (metadata.size && metadata.size > maxBytes) {
      throw new ValidationError(`远程文件超过系统允许的最大大小（${Math.round(maxBytes / 1024 / 1024)} MB）`);
    }

    // 4) 计算计划使用的对象 Key，用于配额校验与冲突命名
    const { ObjectStore } = await import("../storage/object/ObjectStore.js");
    const store = new ObjectStore(this.db, this.encryptionSecret, this.repositoryFactory);
    const plannedKey = await store.getPlannedKey(cfg.id, directory, filename);

    // 用户自定义文件名时，若目标 Key 已存在则自动追加时间后缀，避免静默覆盖
    const finalFilename = options.filename ? await this._resolveNameConflict({
      store,
      cfg,
      directory,
      filename,
      plannedKey,
    }) : filename;

    const finalKey = finalFilename === filename
      ? plannedKey
      : await store.getPlannedKey(cfg.id, directory, finalFilename);

    // 5) 拉取远程流（带幻数校验与体积上限）
    const declaredMime = metadata.contentType;
    const { stream, finalUrl } = await fetchRemoteStream(url, {
      allowPrivateNetwork: policy.allowPrivateNetwork,
      hostnameBlacklist: policy.hostnameBlacklist,
      expectedContentType: declaredMime,
      // 仅当对端给出了具体的媒体类型时才做强制性比对，避免误伤
      requireContentMatch: Boolean(declaredMime && declaredMime !== "application/octet-stream"),
      maxBytes,
    });

    // 6) 确定写入使用的 MIME
    const effectiveMime =
      resolveContentType(null, declaredMime, finalFilename) ||
      guessMimeFromFilename(finalFilename) ||
      "application/octet-stream";

    // 7) 配额校验（未知大小时按 0 传入，由流式上限兜底）
    const quotaSize = typeof metadata.size === "number" && metadata.size > 0 ? metadata.size : 0;
    if (quotaSize > 0) {
      await this._assertStorageQuota({
        storageConfig: cfg,
        storageKey: finalKey,
        incomingBytes: quotaSize,
      });
    }

    // 8) 流式写入存储
    let uploadResult;
    try {
      uploadResult = await store.uploadDirect({
        storage_config_id: cfg.id,
        directory,
        filename: finalFilename,
        bodyStream: stream,
        size: quotaSize || undefined,
        contentType: effectiveMime,
        userIdOrInfo,
        userType,
      });
    } catch (error) {
      // 流式上传期间的错误需要归一化，避免把底层网络细节直接抛给前端
      if (error instanceof ValidationError) throw error;
      throw new DriverError(`转存写入存储失败：${error?.message || "未知错误"}`, {
        status: ApiStatus.BAD_REQUEST,
        code: "URL_TRANSFER.STORAGE_WRITE_FAILED",
        expose: true,
      });
    }

    // 9) 最终大小：优先使用存储返回值，其次回退到探测值
    const finalSize =
      (typeof uploadResult?.size === "number" && uploadResult.size > 0 ? uploadResult.size : null) ??
      (quotaSize > 0 ? quotaSize : 0);

    // 10) 建档：创建分享记录
    const { shouldUseRandomSuffix } = await import("../utils/common.js");
    const useRandom = await shouldUseRandomSuffix(this.db).catch(() => false);

    const record = await this.records.createShareRecord({
      mount: null,
      fsPath: null,
      storageSubPath: uploadResult.storagePath,
      filename: finalFilename,
      size: finalSize,
      remark: options.remark || "",
      userIdOrInfo,
      userType,
      slug: options.slug || null,
      override: Boolean(options.override),
      password: options.password || null,
      expiresInHours: options.expiresIn || 0,
      maxViews: options.maxViews || 0,
      useProxy: options.useProxy,
      mimeType: effectiveMime,
      request: request || null,
      uploadResult: {
        storagePath: uploadResult.storagePath,
        publicUrl: uploadResult.publicUrl,
        etag: uploadResult.etag,
      },
      originalFilenameUsed: true,
      storageConfig: cfg,
      updateIfExists: !useRandom,
    });

    return {
      record,
      sourceUrl: url,
      finalUrl,
      filename: finalFilename,
      size: finalSize,
      contentType: effectiveMime,
      storageConfigId: cfg.id,
      renamedForConflict: finalFilename !== filename,
    };
  }

  /**
   * 用户自定义文件名时的冲突处理：存在同名对象则追加时间戳后缀
   *
   * 说明：`ObjectStore._composeKeyWithStrategy` 仅在系统开启「随机后缀命名策略」
   * 时才会自动改 key。本功能按用户要求，在「手动指定文件名」场景下
   * 主动检测冲突并追加时间后缀，避免覆盖已有文件。
   *
   * @param {Object} params
   * @returns {Promise<string>} 最终使用的文件名
   */
  async _resolveNameConflict({ store, cfg, directory, filename, plannedKey }) {
    const fileRepo = this.repositoryFactory?.getFileRepository?.();
    if (!fileRepo?.findByStoragePath || !cfg?.storage_type) {
      return filename;
    }

    const exists = await fileRepo
      .findByStoragePath(cfg.id, plannedKey, cfg.storage_type)
      .catch(() => null);
    if (!exists) return filename;

    const { name, ext } = splitNameAndExt(filename);
    const stamp = buildTimestampSuffix();
    const candidate = `${name}-${stamp}${ext}`;

    // 极端情况下（同一秒内重复提交）再探测一次，必要时附加随机短串
    const candidateKey = await store.getPlannedKey(cfg.id, directory, candidate);
    const stillExists = await fileRepo
      .findByStoragePath(cfg.id, candidateKey, cfg.storage_type)
      .catch(() => null);
    if (!stillExists) return candidate;

    const random = Math.random().toString(36).slice(2, 7);
    return `${name}-${stamp}-${random}${ext}`;
  }

  /**
   * 存储配额校验
   * @param {Object} params
   */
  async _assertStorageQuota({ storageConfig, storageKey, incomingBytes }) {
    const size = Number(incomingBytes) || 0;
    if (!storageConfig?.id || !storageKey || size <= 0) return;

    let oldBytes = null;
    try {
      const fileRepo = this.repositoryFactory.getFileRepository();
      if (storageConfig.storage_type) {
        const existing = await fileRepo
          .findByStoragePath(storageConfig.id, storageKey, storageConfig.storage_type)
          .catch(() => null);
        if (existing && typeof existing.size === "number" && existing.size >= 0) {
          oldBytes = existing.size;
        }
      }
    } catch {
      oldBytes = null;
    }

    await this.quota.assertCanConsume({
      storageConfigId: storageConfig.id,
      incomingBytes: size,
      oldBytes,
      context: "url-transfer",
    });
  }
}

/**
 * 拆分文件名与扩展名
 * @param {string} filename
 * @returns {{name: string, ext: string}}
 */
function splitNameAndExt(filename) {
  const name = String(filename || "");
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) {
    return { name, ext: "" };
  }
  return { name: name.slice(0, dot), ext: name.slice(dot) };
}

/**
 * 生成时间戳后缀，格式 YYYYMMDDHHmmss
 * @returns {string}
 */
function buildTimestampSuffix() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return [
    d.getUTCFullYear(),
    pad(d.getUTCMonth() + 1),
    pad(d.getUTCDate()),
    pad(d.getUTCHours()),
    pad(d.getUTCMinutes()),
    pad(d.getUTCSeconds()),
  ].join("");
}
