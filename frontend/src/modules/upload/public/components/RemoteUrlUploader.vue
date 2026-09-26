<template>
  <div class="remote-url-uploader">
    <!-- 步骤一：输入远程 URL -->
    <div
      class="url-input-zone border-2 border-dashed rounded-lg transition-all duration-300 overflow-hidden"
      :class="darkMode ? 'border-gray-600 bg-gray-800/30' : 'border-gray-300 bg-gray-50'"
    >
      <div class="flex flex-col items-center justify-center pt-4 px-4">
        <div class="icon-container mb-2 bg-opacity-10 p-2 rounded-full" :class="darkMode ? 'bg-emerald-600' : 'bg-emerald-100'">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="h-8 w-8 transition-colors duration-300"
            :class="darkMode ? 'text-emerald-400' : 'text-emerald-600'"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="1.5"
              d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"
            />
          </svg>
        </div>
        <div class="text-center mb-3">
          <p class="text-base font-medium transition-colors duration-300" :class="darkMode ? 'text-gray-200' : 'text-gray-800'">
            {{ t("file.remoteUrl.title") }}
          </p>
          <p class="text-xs mt-0.5 transition-colors duration-300" :class="darkMode ? 'text-gray-400' : 'text-gray-500'">
            {{ t("file.remoteUrl.subtitle") }}
          </p>
        </div>
      </div>

      <div class="px-4 pb-5">
        <div class="w-full max-w-2xl mx-auto">
          <div class="flex flex-col sm:flex-row gap-2">
            <input
              v-model="urlInput"
              type="url"
              class="form-input flex-1 rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent h-11 px-4"
              :class="inputClass"
              :placeholder="t('file.remoteUrl.urlPlaceholder')"
              :disabled="isBusy"
              @keyup.enter="probe"
            />
            <button
              type="button"
              class="px-4 h-11 rounded-md font-medium transition-colors flex items-center justify-center min-w-[110px]"
              :class="probeButtonClass"
              :disabled="!urlInput || isBusy"
              @click="probe"
            >
              <svg v-if="isProbing" class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
              </svg>
              {{ isProbing ? t("file.remoteUrl.probing") : t("file.remoteUrl.probe") }}
            </button>
          </div>

          <!-- 探测错误 -->
          <p v-if="probeError" class="mt-2 text-sm text-red-600 dark:text-red-400 flex items-start">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1 flex-shrink-0 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
              <path
                fill-rule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                clip-rule="evenodd"
              />
            </svg>
            <span>{{ probeError }}</span>
          </p>
        </div>
      </div>
    </div>

    <!-- 步骤二：探测结果 + 目标设置 -->
    <div v-if="probeResult" class="mt-5 animate-fadeIn">
      <div
        class="rounded-lg border p-3"
        :class="darkMode ? 'bg-gray-800/60 border-gray-700' : 'bg-gray-50 border-gray-200'"
      >
        <div class="flex items-start">
          <div class="mr-3 p-1.5 rounded-lg flex-shrink-0" :class="darkMode ? 'bg-gray-700' : 'bg-white'">
            <div class="h-9 w-9" v-html="fileIconHtml"></div>
          </div>
          <div class="min-w-0 flex-1">
            <div class="font-medium text-sm truncate" :class="darkMode ? 'text-white' : 'text-gray-900'">
              {{ probeResult.filename }}
            </div>
            <div class="flex flex-wrap gap-1.5 mt-1">
              <span class="text-xs px-1.5 py-0.5 rounded-full" :class="darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'">
                {{ formatSize(probeResult.size) }}
              </span>
              <span
                v-if="probeResult.contentType"
                class="text-xs px-1.5 py-0.5 rounded-full max-w-56 truncate"
                :class="darkMode ? 'bg-blue-900/30 text-blue-300' : 'bg-blue-100 text-blue-700'"
                :title="probeResult.contentType"
              >
                {{ probeResult.contentType }}
              </span>
              <span
                v-if="probeResult.exceedsMaxSize"
                class="text-xs px-1.5 py-0.5 rounded-full"
                :class="darkMode ? 'bg-red-900/40 text-red-300' : 'bg-red-100 text-red-700'"
              >
                {{ t("file.remoteUrl.overLimit", { size: formatSize(probeResult.maxSizeBytes) }) }}
              </span>
              <span
                v-else-if="!probeResult.sizeKnown"
                class="text-xs px-1.5 py-0.5 rounded-full"
                :class="darkMode ? 'bg-amber-900/30 text-amber-300' : 'bg-amber-100 text-amber-700'"
              >
                {{ t("file.remoteUrl.sizeUnknown") }}
              </span>
            </div>
            <p
              v-if="probeResult.finalUrl && probeResult.finalUrl !== probeResult.url"
              class="mt-1.5 text-xs break-all"
              :class="darkMode ? 'text-amber-400' : 'text-amber-600'"
            >
              {{ t("file.remoteUrl.redirected") }} {{ probeResult.finalUrl }}
            </p>
          </div>
        </div>
      </div>

      <!-- 目标设置表单 -->
      <form class="mt-5" @submit.prevent="submitTransfer">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- 目标文件名 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.remoteUrl.targetFilename") }}
            </label>
            <input
              v-model="form.filename"
              type="text"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="probeResult.filename"
              :disabled="isBusy"
            />
            <p class="mt-1 text-xs" :class="darkMode ? 'text-gray-500' : 'text-gray-400'">
              {{ t("file.remoteUrl.targetFilenameHint") }}
            </p>
          </div>

          <!-- 存储配置 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.storage") }}
            </label>
            <div class="relative">
              <select
                v-model="form.storage_config_id"
                class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent appearance-none"
                :class="inputClass"
                :disabled="!storageConfigs.length || isBusy"
                required
              >
                <option value="" disabled>{{ storageConfigs.length ? t("file.selectStorage") : t("file.noStorage") }}</option>
                <option v-for="config in storageConfigs" :key="config.id" :value="config.id">
                  {{ formatStorageOptionLabel(config) }}
                </option>
              </select>
              <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" :class="darkMode ? 'text-gray-400' : 'text-gray-500'" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>
          </div>

          <!-- 存储目录 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.path") }}
            </label>
            <input
              v-model="form.path"
              type="text"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="t('file.pathPlaceholder')"
              :disabled="isBusy"
            />
          </div>

          <!-- 备注 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.remark") }}
            </label>
            <input
              v-model="form.remark"
              type="text"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="t('file.remarkPlaceholder')"
              :disabled="isBusy"
            />
          </div>

          <!-- 自定义链接 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.customLink") }}
            </label>
            <input
              v-model="form.slug"
              type="text"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="t('file.customLinkPlaceholder')"
              :disabled="isBusy"
            />
          </div>

          <!-- 访问密码 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.passwordProtection") }}
            </label>
            <input
              v-model="form.password"
              type="text"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="t('file.passwordPlaceholder')"
              :disabled="isBusy"
            />
          </div>

          <!-- 过期时间 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.expireTime") }}
            </label>
            <select v-model="form.expires_in" class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent" :class="inputClass" :disabled="isBusy">
              <option value="1">{{ t("file.expireOptions.hour1") }}</option>
              <option value="24">{{ t("file.expireOptions.day1") }}</option>
              <option value="168">{{ t("file.expireOptions.day7") }}</option>
              <option value="720">{{ t("file.expireOptions.day30") }}</option>
              <option value="0">{{ t("file.expireOptions.never") }}</option>
            </select>
          </div>

          <!-- 最大查看次数 -->
          <div class="flex flex-col">
            <label class="text-sm font-medium mb-1.5" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">
              {{ t("file.maxViews") }}
            </label>
            <input
              v-model.number="form.max_views"
              type="number"
              min="0"
              step="1"
              class="form-input w-full rounded-md shadow-sm focus:ring-2 focus:ring-offset-1 focus:border-transparent"
              :class="inputClass"
              :placeholder="t('file.maxViewsPlaceholder')"
              :disabled="isBusy"
            />
          </div>
        </div>

        <!-- 转存进行中提示 -->
        <div v-if="isTransferring" class="mt-5">
          <div class="flex items-center gap-2 mb-2">
            <span class="text-sm" :class="darkMode ? 'text-gray-300' : 'text-gray-700'">{{ t("file.remoteUrl.transferring") }}</span>
            <span class="text-xs px-2 py-0.5 rounded animate-pulse" :class="darkMode ? 'bg-emerald-900/40 text-emerald-300' : 'bg-emerald-100 text-emerald-700'">
              {{ t("file.remoteUrl.serverSideHint") }}
            </span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-2 overflow-hidden dark:bg-gray-700">
            <div class="h-2 rounded-full bg-emerald-600 animate-indeterminate"></div>
          </div>
          <p class="mt-2 text-xs" :class="darkMode ? 'text-gray-500' : 'text-gray-400'">
            {{ t("file.remoteUrl.transferringHint") }}
          </p>
        </div>

        <!-- 转存错误 -->
        <p v-if="transferError" class="mt-4 text-sm text-red-600 dark:text-red-400">{{ transferError }}</p>

        <div class="mt-6 flex flex-row items-center gap-3">
          <button
            type="submit"
            class="px-4 py-2 rounded-md font-medium transition-colors flex items-center justify-center min-w-[130px]"
            :class="submitButtonClass"
            :disabled="!canSubmit"
          >
            <svg v-if="isTransferring" class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            {{ isTransferring ? t("file.remoteUrl.transferring") : t("file.remoteUrl.transfer") }}
          </button>

          <button
            type="button"
            class="px-4 py-2 rounded-md font-medium transition-colors border"
            :class="
              darkMode
                ? 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600'
                : 'bg-gray-100 border-gray-300 text-gray-700 hover:bg-gray-200'
            "
            :disabled="isBusy"
            @click="reset"
          >
            {{ t("file.clear") }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, reactive, onMounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import { api } from "@/api";
import { getFileIcon } from "@/utils/fileTypeIcons";
import { formatFileSize as formatFileSizeUtil } from "@/utils/fileTypes.js";
import { useStorageConfigsStore } from "@/stores/storageConfigsStore.js";

const props = defineProps({
  darkMode: { type: Boolean, default: false },
  storageConfigs: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
});

const emit = defineEmits(["upload-success", "upload-error", "share-results", "refresh-files"]);

const { t } = useI18n();
const storageConfigsStore = useStorageConfigsStore();

// 实际可用的存储配置：优先父组件传入，其次全局 store
const storageConfigs = computed(() => {
  if (props.storageConfigs && props.storageConfigs.length) {
    return props.storageConfigs;
  }
  return storageConfigsStore.sortedConfigs;
});

const urlInput = ref("");
const probeResult = ref(null);
const probeError = ref("");
const transferError = ref("");
const isProbing = ref(false);
const isTransferring = ref(false);

const form = reactive({
  filename: "",
  storage_config_id: "",
  path: "",
  remark: "",
  slug: "",
  password: "",
  expires_in: "0",
  max_views: 0,
});

const isBusy = computed(() => isProbing.value || isTransferring.value);
const canSubmit = computed(() => {
  if (isBusy.value) return false;
  if (!probeResult.value) return false;
  if (probeResult.value.exceedsMaxSize) return false;
  if (!form.storage_config_id) return false;
  return true;
});

/* ---------- 样式计算 ---------- */

const inputClass = computed(() =>
  props.darkMode
    ? "bg-gray-700 border-gray-600 text-white focus:ring-emerald-600 focus:ring-offset-gray-800"
    : "bg-white border-gray-300 text-gray-900 focus:ring-emerald-500 focus:ring-offset-white",
);

const probeButtonClass = computed(() => {
  if (!urlInput.value || isBusy.value) {
    return props.darkMode ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed";
  }
  return "bg-emerald-600 hover:bg-emerald-700 text-white";
});

const submitButtonClass = computed(() => {
  if (!canSubmit.value) {
    return props.darkMode ? "bg-gray-700 text-gray-400 cursor-not-allowed" : "bg-gray-200 text-gray-500 cursor-not-allowed";
  }
  return "bg-emerald-600 hover:bg-emerald-700 text-white";
});

/* ---------- 展示辅助 ---------- */

const fileIconHtml = computed(() => {
  const info = probeResult.value;
  if (!info) return "";
  return getFileIcon(
    {
      extension: (info.filename || "").split(".").pop() || "",
      mime: info.contentType || "",
      darkMode: props.darkMode,
    },
    props.darkMode,
  );
});

const formatSize = (bytes) => {
  if (typeof bytes !== "number" || bytes <= 0) return t("file.unknownSize");
  return formatFileSizeUtil(bytes);
};

const formatStorageOptionLabel = (config) => {
  if (!config) return t("file.storage");
  const meta = config.provider_type || config.storage_type;
  return meta ? `${config.name} (${meta})` : config.name;
};

/** 与后端保持一致的 URL 合法性预校验，避免明显无效请求打后端 */
const isValidUrl = (value) => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
};

/* ---------- 存储配置默认值 ---------- */

const selectDefaultStorage = () => {
  const configs = storageConfigs.value;
  if (!configs || !configs.length) return;
  if (form.storage_config_id && configs.some((cfg) => cfg.id === form.storage_config_id)) {
    return;
  }
  const defaultConfig = configs.find((cfg) => cfg.is_default);
  form.storage_config_id = (defaultConfig || configs[0]).id;
};

watch(storageConfigs, selectDefaultStorage, { immediate: true });

/* ---------- 主要动作 ---------- */

const probe = async () => {
  probeError.value = "";
  transferError.value = "";
  probeResult.value = null;

  const url = urlInput.value.trim();
  if (!url) return;
  if (!isValidUrl(url)) {
    probeError.value = t("file.messages.invalidUrl");
    return;
  }

  isProbing.value = true;
  try {
    const response = await api.urlTransfer.probeUrl(url, { filename: form.filename || null });
    if (!response?.success) {
      throw new Error(response?.message || t("file.remoteUrl.probeFailed"));
    }
    probeResult.value = response.data || null;
    // 用探测到的文件名回填，用户可在此基础上修改
    if (probeResult.value && !form.filename) {
      form.filename = probeResult.value.filename || "";
    }
    selectDefaultStorage();
  } catch (error) {
    probeError.value = error?.message || t("file.remoteUrl.probeFailed");
    probeResult.value = null;
  } finally {
    isProbing.value = false;
  }
};

const buildRemark = () => {
  if (form.remark) return form.remark;
  const url = urlInput.value.trim();
  const maxLength = 100;
  const shortUrl = url.length > maxLength ? `${url.slice(0, maxLength)}...` : url;
  return `[${t("file.remoteUrl.remarkPrefix")}]${shortUrl}`;
};

const submitTransfer = async () => {
  if (!canSubmit.value) return;

  transferError.value = "";
  isTransferring.value = true;

  try {
    const response = await api.urlTransfer.transferUrl({
      url: urlInput.value.trim(),
      filename: form.filename || null,
      storage_config_id: form.storage_config_id,
      path: form.path || null,
      slug: form.slug || null,
      remark: buildRemark(),
      password: form.password || null,
      expires_in: form.expires_in,
      max_views: form.max_views,
    });

    if (!response?.success) {
      throw new Error(response?.message || t("file.remoteUrl.transferFailed"));
    }

    const data = response.data || {};

    emit("upload-success", {
      message: t("file.remoteUrl.transferSuccess"),
      url: urlInput.value.trim(),
      filename: data.filename || form.filename || "",
      renamedForConflict: data.renamedForConflict === true,
    });

    // 把结果交给上传页的「分享链接」区域统一展示
    emit("share-results", [
      {
        id: data.id || data.slug || data.filename,
        filename: data.filename || form.filename || "file",
        slug: data.slug || null,
        shareUrl: data.link || data.shareUrl || data.url || "",
        previewUrl: data.previewUrl || "",
        downloadUrl: data.downloadUrl || "",
        password: form.password || null,
        expiresAt: data.expiresAt || data.expires_at || null,
      },
    ]);

    emit("refresh-files");
    reset({ keepStorage: true });
  } catch (error) {
    transferError.value = error?.message || t("file.remoteUrl.transferFailed");
    emit("upload-error", error);
  } finally {
    isTransferring.value = false;
  }
};

const reset = (options = {}) => {
  urlInput.value = "";
  probeResult.value = null;
  probeError.value = "";
  transferError.value = "";
  form.filename = "";
  form.path = "";
  form.remark = "";
  form.slug = "";
  form.password = "";
  form.expires_in = "0";
  form.max_views = 0;
  if (!options.keepStorage) {
    form.storage_config_id = "";
    selectDefaultStorage();
  }
};

onMounted(selectDefaultStorage);
</script>

<style scoped>
.remote-url-uploader {
  width: 100%;
}

.form-input:disabled,
button:disabled {
  cursor: not-allowed;
  opacity: 0.7;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-fadeIn {
  animation: fadeIn 0.3s ease-out forwards;
}

/* 服务端转存无法提供细粒度进度，使用不定长进度条表达「进行中」 */
@keyframes indeterminate {
  0% {
    margin-left: -40%;
    width: 40%;
  }
  50% {
    margin-left: 30%;
    width: 55%;
  }
  100% {
    margin-left: 100%;
    width: 40%;
  }
}

.animate-indeterminate {
  animation: indeterminate 1.4s ease-in-out infinite;
}
</style>
