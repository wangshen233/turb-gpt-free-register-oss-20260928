<script setup>
import { onActivated, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getRunProbes, listRuns } from '@/api/register'
import { fmtTime } from '@/api/request'
import { useRuntimeStore } from '@/stores/runtime'
import StatusDot from '@/components/StatusDot.vue'

const { dataVersion } = storeToRefs(useRuntimeStore())
const rows = ref([])
const loading = ref(false)
const probeVisible = ref(false)
const probeLoading = ref(false)
const probeRun = ref(null)
const probeItems = ref([])

const STATUS_TYPE = { done: 'primary', failed: 'danger', running: 'warning' }

function runtimeCheck(row) {
  const report = row.runtime_observation || {}
  if (!row.fingerprint_id) return { type: 'info', text: '未分配' }
  if (!Object.keys(report).length) {
    return row.status === 'running'
      ? { type: 'warning', text: '等待校验' }
      : { type: 'info', text: '无观测' }
  }
  return report.all_passed
    ? { type: 'success', text: '一致' }
    : { type: 'danger', text: '不一致' }
}

function profileSize(row) {
  const viewport = row.fingerprint?.viewport
  if (!viewport?.width || !viewport?.height) return '-'
  return `${viewport.width} x ${viewport.height}`
}

const PROBE_TYPE = { ok: 'success', failed: 'danger', started: 'warning', skipped: 'info', partial: 'warning' }
function probeText(item) {
  return `${item.stage || item.operation} · ${item.status}`
}

async function showProbes(row) {
  probeRun.value = row
  probeVisible.value = true
  probeLoading.value = true
  try {
    const { probes } = await getRunProbes(row.run_id)
    probeItems.value = probes || []
  } catch (e) {
    probeItems.value = []
    ElMessage.error(e.message)
  } finally { probeLoading.value = false }
}

async function load() {
  loading.value = true
  try { const { items } = await listRuns(50); rows.value = items }
  catch (e) { ElMessage.error(e.message) }
  finally { loading.value = false }
}

watch(dataVersion, () => load())
onActivated(() => load())
</script>

<template>
  <div class="page">
    <el-card shadow="never">
      <template #header>
        <div style="display: flex; align-items: center; justify-content: space-between">
          <span class="section-title" style="margin: 0">运行记录</span>
          <el-button size="small" @click="load"><el-icon><Refresh /></el-icon>刷新</el-button>
        </div>
      </template>
      <el-skeleton v-if="loading && !rows.length" :rows="6" animated style="padding: 8px 0" />
      <el-table v-else v-loading="loading" :data="rows" size="small" stripe>
        <el-table-column prop="run_id" label="run_id" width="180">
          <template #default="{ row }"><span class="mono">{{ row.run_id }}</span></template>
        </el-table-column>
        <el-table-column prop="email" label="邮箱" min-width="200" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <StatusDot :type="STATUS_TYPE[row.status] || 'info'" :text="row.status" />
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
        </el-table-column>
        <el-table-column label="环境画像" min-width="230">
          <template #default="{ row }">
            <div v-if="row.fingerprint_id" class="environment-cell">
              <span class="mono">{{ row.fingerprint_id }}</span>
              <span class="hint">
                {{ row.country_code || 'auto' }} · {{ row.exit_ip || '出口待探测' }} · {{ profileSize(row) }}
              </span>
            </div>
            <span v-else class="hint">未分配</span>
          </template>
        </el-table-column>
        <el-table-column label="运行时校验" width="120" align="center">
          <template #default="{ row }">
            <el-tag :type="runtimeCheck(row).type" size="small" effect="plain">
              {{ runtimeCheck(row).text }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="探针" width="100" align="center">
          <template #default="{ row }">
            <el-button size="small" text type="primary" @click="showProbes(row)">
              {{ row.probes?.length || 0 }} 条
            </el-button>
          </template>
        </el-table-column>
        <el-table-column prop="error" label="错误" min-width="200" show-overflow-tooltip />
        <template #empty>
          <el-empty description="暂无运行记录" :image-size="70" />
        </template>
      </el-table>

      <el-dialog v-model="probeVisible" :title="`探针详情 · ${probeRun?.run_id || ''}`" width="760px">
        <el-skeleton v-if="probeLoading" :rows="5" animated />
        <el-empty v-else-if="!probeItems.length" description="暂无探针事件" />
        <el-table v-else :data="probeItems" size="small" stripe max-height="460">
          <el-table-column prop="stage" label="阶段" min-width="190">
            <template #default="{ row }">{{ row.stage || row.operation }}</template>
          </el-table-column>
          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <el-tag size="small" effect="plain" :type="PROBE_TYPE[row.status] || 'info'">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="duration_ms" label="耗时" width="90">
            <template #default="{ row }">{{ row.duration_ms == null ? '-' : `${row.duration_ms} ms` }}</template>
          </el-table-column>
          <el-table-column label="详情" min-width="250" show-overflow-tooltip>
            <template #default="{ row }">{{ row.error || JSON.stringify(row.details || {}) }}</template>
          </el-table-column>
        </el-table>
      </el-dialog>
    </el-card>
  </div>
</template>

<style scoped>
.environment-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.environment-cell .mono {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
