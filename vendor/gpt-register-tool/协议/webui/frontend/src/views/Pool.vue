<script setup>
import { computed, onActivated, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listAccounts, deleteAccount, bulkDeleteAccounts, resetFailed,
  resetAccount, bulkResetAccounts, releaseStale,
} from '@/api/accounts'
import { getMailProviders } from '@/api/settings'
import { useStatsStore } from '@/stores/stats'
import { useRuntimeStore } from '@/stores/runtime'
import StatusDot from '@/components/StatusDot.vue'

const router = useRouter()
const statsStore = useStatsStore()
const runtime = useRuntimeStore()
const { dataVersion } = storeToRefs(runtime)

const PAGE_SIZE = 20
const rows = ref([])
const total = ref(0)
const page = ref(1)
const statusFilter = ref('')
const kindFilter = ref('')
const bulkStatus = ref('')
const selected = ref([])
const loading = ref(false)
// 号池现在可以混放多种邮箱，这两个用来显示「来源」列和按来源过滤
const providers = ref([])
const byKind = ref({})

const STATUS_TYPE = { available: 'success', in_use: 'warning', done: 'primary', failed: 'danger' }

// 列表里只列池子里真有号的来源，免得下拉框塞一堆空选项
const kindOptions = computed(() =>
  providers.value.filter((p) => p.pooled).map((p) => ({
    kind: p.kind,
    label: p.display_name,
    count: byKind.value[p.kind]?.total || 0,
  })),
)

function kindLabel(k) {
  return providers.value.find((p) => p.kind === k)?.display_name || k || 'outlook'
}

async function loadProviders() {
  try {
    providers.value = (await getMailProviders()).providers || []
  } catch (_) { /* 拿不到就退化成显示原始 kind 字符串 */ }
}

async function load(resetPage) {
  if (resetPage) page.value = 1
  loading.value = true
  try {
    const { items, total: t, by_kind } = await listAccounts({
      status: statusFilter.value,
      kind: kindFilter.value,
      limit: PAGE_SIZE,
      offset: (page.value - 1) * PAGE_SIZE,
    })
    rows.value = items
    total.value = t
    byKind.value = by_kind || {}
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function afterMutate() { load(); statsStore.refresh() }

async function confirm(msg, title = '确认') {
  try { await ElMessageBox.confirm(msg, title, { type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消' }); return true }
  catch (_) { return false }
}

async function resetFailedAll() {
  if (!(await confirm('把所有 failed 号重置为 available？'))) return
  try { const r = await resetFailed(); ElMessage.success(`重置 ${r.reset} 个`); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}
async function releaseStaleAll() {
  try { const r = await releaseStale(); ElMessage.success(`释放 ${r.released} 个卡死号`); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}
async function resetSelected() {
  const emails = selected.value.map((r) => r.email)
  if (!emails.length) return
  if (!(await confirm(`重置选中的 ${emails.length} 个号为 available？（已保存凭证不变）`))) return
  try { const r = await bulkResetAccounts(emails); ElMessage.success(`已重置 ${r.reset} 个`); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}
async function deleteSelected() {
  const emails = selected.value.map((r) => r.email)
  if (!emails.length) return
  if (!(await confirm(`确定删除选中的 ${emails.length} 个号？(不可恢复)`))) return
  try { const r = await bulkDeleteAccounts({ emails }); ElMessage.success(`已删除 ${r.deleted} 个`); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}
async function bulkDeleteByStatus() {
  if (!bulkStatus.value) { ElMessage.warning('请先选择要删除的状态'); return }
  const tip = bulkStatus.value === 'all'
    ? '这会删除邮箱列表里所有号（含未注册的），确定？'
    : `确定删除全部 ${bulkStatus.value} 状态的号？`
  if (!(await confirm(tip))) return
  try {
    const r = await bulkDeleteAccounts({ status: bulkStatus.value })
    ElMessage.success(`已删除 ${r.deleted} 个 ${bulkStatus.value} 号`)
    bulkStatus.value = ''
    afterMutate()
  } catch (e) { ElMessage.error(e.message) }
}
function useAccount(email) {
  router.push({ path: '/register', query: { email } })
}
async function resetOne(email) {
  if (!(await confirm(`重置 ${email} 为 available？`))) return
  try { await resetAccount(email); ElMessage.success('已重置'); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}
async function deleteOne(email) {
  if (!(await confirm(`删除 ${email}？`))) return
  try { await deleteAccount(email); ElMessage.success('已删除'); afterMutate() }
  catch (e) { ElMessage.error(e.message) }
}

watch(page, () => load())
watch(dataVersion, () => load())
onActivated(() => load())
loadProviders()
</script>
<template>
  <div class="page">
    <el-card shadow="never">
      <template #header>
        <span class="section-title" style="margin: 0">邮箱列表</span>
      </template>

      <el-space wrap style="margin-bottom: 12px">
        <el-select v-model="statusFilter" placeholder="全部" style="width: 130px" @change="load(true)">
          <el-option label="全部" value="" />
          <el-option label="available" value="available" />
          <el-option label="in_use" value="in_use" />
          <el-option label="done" value="done" />
          <el-option label="failed" value="failed" />
        </el-select>
        <!-- 号池混放多种邮箱时才有意义，只有一种来源就不显示 -->
        <el-select
          v-if="kindOptions.length > 1"
          v-model="kindFilter" placeholder="全部来源" style="width: 190px" @change="load(true)"
        >
          <el-option label="全部来源" value="" />
          <el-option
            v-for="o in kindOptions" :key="o.kind"
            :label="`${o.label} (${o.count})`" :value="o.kind"
          />
        </el-select>
        <el-button @click="load(false)"><el-icon><Refresh /></el-icon>刷新</el-button>
        <el-button @click="resetFailedAll">重试 failed</el-button>
        <el-button @click="releaseStaleAll">释放卡死号</el-button>
      </el-space>

      <el-space wrap style="margin-bottom: 12px">
        <el-button type="primary" plain :disabled="!selected.length" @click="resetSelected">
          重置选中 ({{ selected.length }})
        </el-button>
        <el-button type="danger" plain :disabled="!selected.length" @click="deleteSelected">
          删除选中 ({{ selected.length }})
        </el-button>
        <el-select v-model="bulkStatus" placeholder="— 按状态批量删 —" style="width: 180px">
          <el-option label="删全部 failed" value="failed" />
          <el-option label="删全部 done" value="done" />
          <el-option label="删全部 available" value="available" />
          <el-option label="删全部 in_use" value="in_use" />
          <el-option label="删全部（危险）" value="all" />
        </el-select>
        <el-button @click="bulkDeleteByStatus">执行</el-button>
      </el-space>

      <el-skeleton v-if="loading && !rows.length" :rows="6" animated style="padding: 8px 0" />
      <el-table
        v-else
        v-loading="loading" :data="rows" size="small" stripe
        @selection-change="(v) => (selected = v)"
      >
        <el-table-column type="selection" width="44" />
        <el-table-column prop="email" label="邮箱" min-width="220" show-overflow-tooltip />
        <el-table-column v-if="kindOptions.length > 1" label="来源" width="130">
          <template #default="{ row }">
            <el-tag size="small" type="info">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <StatusDot :type="STATUS_TYPE[row.status] || 'info'" :text="row.status" />
          </template>
        </el-table-column>
        <el-table-column prop="fail_reason" label="失败原因" min-width="180" show-overflow-tooltip />
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button size="small" text @click="useAccount(row.email)">使用</el-button>
            <el-button
              v-if="row.status === 'done' || row.status === 'failed'"
              size="small" text type="primary" @click="resetOne(row.email)"
            >重置</el-button>
            <el-button size="small" text type="danger" @click="deleteOne(row.email)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <el-empty description="暂无数据，去「导入邮箱」添加接码号" :image-size="70" />
        </template>
      </el-table>

      <div style="display: flex; justify-content: center; margin-top: 14px">
        <el-pagination
          v-model:current-page="page" :page-size="PAGE_SIZE" :total="total"
          layout="prev, pager, next, total" background
        />
      </div>
    </el-card>
  </div>
</template>
