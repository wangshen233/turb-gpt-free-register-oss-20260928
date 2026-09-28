import { defineStore } from 'pinia'
import { ref } from 'vue'
import { getStats } from '@/api/accounts'

// 号池统计（总计/可用/进行中/完成/失败/可试用），顶栏 + 仪表盘共用，5s 轮询。
export const useStatsStore = defineStore('stats', () => {
  const stats = ref({ total: 0, available: 0, in_use: 0, done: 0, failed: 0, plus_eligible: 0 })
  let timer = null

  async function refresh() {
    try {
      const { stats: s } = await getStats()
      if (s) stats.value = s
    } catch (e) {
      // 静默：统计失败不打扰用户
      console.error('stats refresh:', e)
    }
  }

  function startPolling(interval = 5000) {
    refresh()
    if (timer) clearInterval(timer)
    timer = setInterval(refresh, interval)
  }

  function stopPolling() {
    if (timer) clearInterval(timer)
    timer = null
  }

  return { stats, refresh, startPolling, stopPolling }
})
