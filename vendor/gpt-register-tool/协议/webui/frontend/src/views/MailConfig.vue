<script setup>
// 邮箱来源配置。
//
// 这个页面不认识任何具体邮箱 —— 单选项和下面的表单字段全部来自
// GET /api/mail/providers 的声明（provider 类里的 config_fields）。
// 后端加一种邮箱，这个文件一行都不用改。
import { computed, onActivated, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getMailConfig, getMailProviders, saveMailConfig, testMail } from '@/api/settings'
import FooterToolbar from '@/components/FooterToolbar.vue'

const providers = ref([])
const source = ref('outlook')
const form = ref({})          // { 字段 key: 用户填的值 }
const saved = ref({})         // 后端返回的原值，密码类是 '***'
const loading = ref(true)
const saving = ref(false)
const testing = ref(false)

const current = computed(
  () => providers.value.find((p) => p.kind === source.value) || null,
)
const fields = computed(() => current.value?.config_fields || [])

// 池化 provider（Outlook 这类导号进来的）连通性绑在具体某个号上，
// 没号可测；测试按钮只对非池化的显示。
const canTest = computed(() => !!current.value && !current.value.pooled)

/** 密码类字段已存过 → 输入框留空表示"不修改"，提示语要说清楚 */
function phFor(f) {
  if (f.type === 'password' && saved.value[f.key] === '***') {
    return '已设置（留空则不修改）'
  }
  return f.placeholder || ''
}

async function load() {
  loading.value = true
  try {
    const [pr, cfg] = await Promise.all([getMailProviders(), getMailConfig()])
    providers.value = pr.providers || []
    saved.value = cfg.config || {}
    source.value = saved.value.mail_source || pr.current || 'outlook'

    // 回填：密码类一律留空（后端存的是 '***'，填进去会把真值覆盖掉）
    const next = {}
    for (const p of providers.value) {
      for (const f of p.config_fields) {
        next[f.key] = f.type === 'password' ? '' : (saved.value[f.key] ?? '')
      }
    }
    form.value = next
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

async function save() {
  const payload = { mail_source: source.value }
  for (const f of fields.value) {
    const v = (form.value[f.key] ?? '').trim()
    if (f.type === 'password' && !v) {
      // 留空 = 不修改。后端见到 '***' 会跳过，不覆盖已存的真 token
      if (saved.value[f.key] === '***') continue
    }
    payload[f.key] = v
  }

  const missing = fields.value
    .filter((f) => f.required)
    .filter((f) => {
      const v = (form.value[f.key] ?? '').trim()
      return !v && !(f.type === 'password' && saved.value[f.key] === '***')
    })
  if (missing.length) {
    ElMessage.warning('还没填：' + missing.map((f) => f.label).join('、'))
    return
  }

  saving.value = true
  try {
    await saveMailConfig(payload)
    ElMessage.success('保存成功')
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

async function test() {
  testing.value = true
  try {
    const r = await testMail()
    ElMessage.success(r.message || '连通正常')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    testing.value = false
  }
}

onActivated(() => load())
load()
</script>

<template>
  <div class="page" v-loading="loading">
    <el-card shadow="never" style="max-width: 720px">
      <template #header>
        <span class="section-title" style="margin: 0">邮箱来源配置</span>
      </template>
      <p class="hint">
        OpenAI 注册需要邮箱收 OTP。下面的选项由后端已注册的 provider 自动生成。
      </p>

      <el-form label-position="top">
        <el-form-item label="邮箱来源">
          <el-radio-group v-model="source">
            <el-radio v-for="p in providers" :key="p.kind" :value="p.kind">
              {{ p.display_name }}
            </el-radio>
          </el-radio-group>
        </el-form-item>

        <!-- 能力说明：让主人一眼看出这种邮箱是怎么工作的 -->
        <el-form-item v-if="current">
          <div class="caps">
            <el-tag size="small" :type="current.pooled ? 'warning' : 'success'">
              {{ current.pooled ? '号池型：需先导入号，用完要补' : '自建型：自动生成地址，无限量' }}
            </el-tag>
            <el-tag size="small" :type="current.ephemeral ? 'success' : 'info'">
              {{ current.ephemeral ? '每次新地址' : '固定地址' }}
            </el-tag>
            <el-tag v-if="current.line_segments > 0" size="small" type="info">
              导入格式 {{ current.line_segments }} 段
            </el-tag>
          </div>
        </el-form-item>

        <!-- 配置项：完全由 provider 声明驱动 -->
        <el-form-item v-for="f in fields" :key="f.key" :label="f.label">
          <el-input
            v-model="form[f.key]"
            :type="f.type === 'password' ? 'password' : 'text'"
            :show-password="f.type === 'password'"
            :placeholder="phFor(f)"
          />
          <div v-if="f.help" class="hint" style="margin-top: 4px">{{ f.help }}</div>
        </el-form-item>

        <el-alert
          v-if="current && !current.pooled && fields.length"
          type="warning" :closable="false" show-icon
          title="自建邮箱需要把域名的 catch-all 收件正确转发到服务端，否则收不到验证码。"
        />

        <el-alert
          v-if="current && current.pooled"
          type="info" :closable="false" show-icon
          :title="`${current.display_name} 不需要在这里配置，去「导入邮箱」页把号导进来即可。`"
        />
      </el-form>
    </el-card>

    <FooterToolbar>
      <template #left>
        邮箱来源：{{ current?.display_name || source }}
      </template>
      <el-button v-if="canTest" :loading="testing" @click="test">测试连通性</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存配置</el-button>
    </FooterToolbar>
  </div>
</template>

<style scoped>
.caps {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
</style>
