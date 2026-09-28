<script setup>
import { computed, onActivated, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { diagnoseFingerprint, getFingerprintConfig, saveFingerprintConfig } from '@/api/fingerprint'

const loading = ref(false)
const saving = ref(false)
const diagnosing = ref(false)
const diagnostic = ref(null)

const config = reactive({
  country_code: '',
  browser_family: 'auto',
  browser_engine: 'auto',
  randomize: true,
})

const options = reactive({
  countries: [],
  browser_families: [],
  browser_engines: [],
})

const familyLabels = {
  auto: '自动选择',
  chrome: 'Chrome',
  firefox: 'Firefox',
  safari: 'Safari',
}

const engineLabels = {
  auto: '自动（优先 Camoufox）',
  camoufox: 'Camoufox',
  playwright: 'Playwright',
}

const typeLabels = {
  chrome: 'Chrome / Windows',
  firefox: 'Firefox / Windows',
  mac_safari: 'Safari / macOS',
  ios_safari: 'Safari / iPhone',
}

const checkLabels = {
  screen_matches_viewport: 'screen 与 viewport 一致',
  ua_matches_browser_family: 'UA 与浏览器家族一致',
  platform_matches_browser_family: '平台与浏览器家族一致',
  language_matches_locale: '语言与 locale 一致',
  timezone_is_explicit: '时区已明确设置',
  geoip_override_disabled: 'Camoufox 不覆盖手动地区',
  country_matches_detected: '画像国家与探测国家一致',
}

const familyOptions = computed(() =>
  (options.browser_families.length ? options.browser_families : Object.keys(familyLabels))
    .map((value) => ({ value, label: familyLabels[value] || value })),
)

const engineOptions = computed(() =>
  (options.browser_engines.length ? options.browser_engines : Object.keys(engineLabels))
    .map((value) => ({ value, label: engineLabels[value] || value })),
)

const countryOptions = computed(() => {
  const current = config.country_code && !options.countries.includes(config.country_code)
    ? [config.country_code]
    : []
  return [
    { value: '', label: '自动（按代理国家探测）' },
    ...[...new Set([...current, ...options.countries])].map((value) => ({
      value,
      label: value,
    })),
  ]
})

const checkEntries = computed(() =>
  Object.entries(diagnostic.value?.checks || {})
    .filter(([key]) => key !== 'all_passed'),
)

const diagnosticPassed = computed(() => diagnostic.value?.checks?.all_passed === true)
const viewportText = computed(() => {
  const viewport = diagnostic.value?.viewport
  return viewport?.width && viewport?.height ? `${viewport.width} x ${viewport.height}` : '-'
})

function applyResponse(payload) {
  Object.assign(config, payload.config || {})
  Object.assign(options, payload.options || {})
  diagnostic.value = payload.diagnostic || null
}

async function load() {
  loading.value = true
  try {
    applyResponse(await getFingerprintConfig())
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function onFamilyChange(value) {
  if (value !== 'auto' && value !== 'firefox' && config.browser_engine === 'camoufox') {
    config.browser_engine = 'playwright'
  }
}

async function save() {
  saving.value = true
  try {
    const result = await saveFingerprintConfig({ ...config })
    Object.assign(config, result.config || {})
    ElMessage.success('指纹配置已保存')
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

async function diagnose() {
  diagnosing.value = true
  try {
    const result = await diagnoseFingerprint({
      country_code: config.country_code,
      browser_family: config.browser_family,
      browser_engine: config.browser_engine,
    })
    diagnostic.value = result.diagnostic || null
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    diagnosing.value = false
  }
}

onActivated(() => load())
load()
</script>

<template>
  <div class="page" v-loading="loading">
    <el-row :gutter="16">
      <el-col :xs="24" :lg="10">
        <el-card shadow="never">
          <template #header>
            <div class="card-header">
              <span class="section-title" style="margin: 0">指纹环境策略</span>
              <el-tag type="success" size="small" effect="plain">任务级</el-tag>
            </div>
          </template>

          <el-form label-position="top">
            <el-form-item label="地区画像">
              <el-select v-model="config.country_code" filterable clearable style="width: 100%">
                <el-option
                  v-for="item in countryOptions"
                  :key="item.value || 'auto'"
                  :label="item.label"
                  :value="item.value"
                />
              </el-select>
              <div class="hint">留空时在任务启动前按代理出口探测；手动选择会固定语言和时区联动。</div>
            </el-form-item>

            <el-form-item label="浏览器家族">
              <el-radio-group v-model="config.browser_family" @change="onFamilyChange">
                <el-radio v-for="item in familyOptions" :key="item.value" :value="item.value">
                  {{ item.label }}
                </el-radio>
              </el-radio-group>
            </el-form-item>

            <el-form-item label="浏览器引擎">
              <el-select v-model="config.browser_engine" style="width: 100%">
                <el-option
                  v-for="item in engineOptions"
                  :key="item.value"
                  :label="item.label"
                  :value="item.value"
                  :disabled="item.value === 'camoufox' && !['auto', 'firefox'].includes(config.browser_family)"
                />
              </el-select>
              <div class="hint">Camoufox 仅使用 Firefox 家族画像，并显式关闭 geoip 覆盖。</div>
            </el-form-item>

            <el-form-item label="画像随机化">
              <div class="switch-line">
                <el-switch v-model="config.randomize" />
                <span>{{ config.randomize ? '已启用' : '已关闭' }}</span>
              </div>
              <div class="hint">每个任务始终新建唯一 fingerprint_id；此开关保留用于兼容任务策略配置。</div>
            </el-form-item>
          </el-form>

          <el-alert
            type="info"
            :closable="false"
            show-icon
            title="screen 与浏览器 viewport 会从同一组尺寸生成，并在启动前校验。"
          />
        </el-card>
      </el-col>

      <el-col :xs="24" :lg="14">
        <el-card shadow="never" class="diagnostic-card">
          <template #header>
            <div class="card-header">
              <span class="section-title" style="margin: 0">当前诊断样本</span>
              <el-tag
                v-if="diagnostic"
                :type="diagnosticPassed ? 'success' : 'danger'"
                size="small"
              >
                {{ diagnosticPassed ? '检查通过' : '存在不一致' }}
              </el-tag>
            </div>
          </template>

          <el-empty v-if="!diagnostic" description="暂无诊断样本" />
          <template v-else>
            <el-descriptions :column="2" border size="small">
              <el-descriptions-item label="画像 ID">
                <span class="mono">{{ diagnostic.fingerprint_id || '-' }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="浏览器">
                {{ typeLabels[diagnostic.browser_type] || diagnostic.browser_type || '-' }}
              </el-descriptions-item>
              <el-descriptions-item label="screen">
                <span class="mono">{{ diagnostic.screen || '-' }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="viewport">
                <span class="mono">{{ viewportText }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="语言 / locale">
                {{ diagnostic.lang || '-' }} / {{ diagnostic.locale || '-' }}
              </el-descriptions-item>
              <el-descriptions-item label="时区">
                <span class="mono">{{ diagnostic.timezone || '-' }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="平台">
                {{ diagnostic.navigator_platform || '-' }}
              </el-descriptions-item>
              <el-descriptions-item label="DPR">
                {{ diagnostic.device_pixel_ratio || '-' }}
              </el-descriptions-item>
            </el-descriptions>

            <div class="detail-block">
              <div class="detail-label">Accept-Language</div>
              <div class="mono detail-value">{{ diagnostic.accept_language || '-' }}</div>
            </div>
            <div class="detail-block">
              <div class="detail-label">User-Agent</div>
              <div class="mono detail-value ua-value">{{ diagnostic.user_agent || '-' }}</div>
            </div>
          </template>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="diagnostic" shadow="never" class="checks-card">
      <template #header>
        <div class="card-header">
          <span class="section-title" style="margin: 0">一致性检查</span>
          <span class="hint">{{ checkEntries.filter(([, value]) => value).length }} / {{ checkEntries.length }} 通过</span>
        </div>
      </template>

      <div class="checks-grid">
        <div v-for="[key, passed] in checkEntries" :key="key" class="check-row">
          <el-icon :class="passed ? 'check-pass' : 'check-fail'">
            <component :is="passed ? 'CircleCheck' : 'CircleClose'" />
          </el-icon>
          <span>{{ checkLabels[key] || key }}</span>
        </div>
      </div>
      <el-alert
        v-if="diagnostic.errors?.length"
        type="error"
        :closable="false"
        show-icon
        style="margin-top: 12px"
        :title="diagnostic.errors.join('；')"
      />
    </el-card>

    <div class="action-bar">
      <el-button :loading="loading" @click="load">
        <el-icon><Refresh /></el-icon>
        刷新样本
      </el-button>
      <el-button :loading="diagnosing" @click="diagnose">
        <el-icon><Monitor /></el-icon>
        重新诊断
      </el-button>
      <el-button type="primary" :loading="saving" @click="save">
        <el-icon><Select /></el-icon>
        保存配置
      </el-button>
    </div>
  </div>
</template>

<style scoped>
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.switch-line {
  display: flex;
  align-items: center;
  gap: 10px;
}

.diagnostic-card {
  min-height: 100%;
}

.detail-block {
  margin-top: 14px;
}

.detail-label {
  color: var(--el-text-color-secondary);
  font-size: 12px;
  margin-bottom: 4px;
}

.detail-value {
  padding: 8px 10px;
  border: 1px solid var(--app-border);
  border-radius: 4px;
  background: var(--el-fill-color-light);
  overflow-wrap: anywhere;
  line-height: 1.5;
}

.ua-value {
  max-height: 96px;
  overflow: auto;
}

.checks-card {
  margin-top: 0;
}

.checks-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 24px;
}

.check-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 28px;
  color: var(--el-text-color-regular);
}

.check-pass { color: var(--el-color-success); }
.check-fail { color: var(--el-color-danger); }

.action-bar {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 16px;
}

@media (max-width: 768px) {
  .checks-grid { grid-template-columns: 1fr; }
  .action-bar { justify-content: stretch; }
  .action-bar .el-button { flex: 1 1 30%; }
}
</style>
