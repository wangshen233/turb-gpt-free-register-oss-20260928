import axios from 'axios'
import { ElMessage } from 'element-plus'

// ────────────────────────────────────────────────────────────
// ⭐ 后端地址统一入口
// 换 Go 后端时，只改这一处（或设置 VITE_API_BASE 环境变量）即可。
// 留空 = 与前端同源（当前 FastAPI / 未来 Gin 都伺服在同一端口）。
// ────────────────────────────────────────────────────────────
export const API_BASE = import.meta.env.VITE_API_BASE || ''

const http = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 60000,
})

// 统一解包 + 错误提示。后端约定：
//   - 一般错误：非 2xx，body 里有 detail 字段
//   - 校验类错误（如导入逐行报错）：422，body 是 { message, errors: [{line, error}] }
//
// 抛出的 Error 会挂上 .status 和 .data，调用方需要逐行详情时读 err.data.errors，
// 只想弹个提示的话照旧读 err.message —— 老代码不用改。
http.interceptors.response.use(
  (resp) => resp.data,
  (error) => {
    const data = error?.response?.data
    const detail =
      data?.detail ||
      data?.message ||
      error?.response?.statusText ||
      error?.message ||
      '请求失败'
    const err = new Error(detail)
    err.status = error?.response?.status
    err.data = data
    return Promise.reject(err)
  },
)

export default http

/**
 * 建立一个 SSE 连接。
 * @param {string} path  相对路径，如 `/api/auto/stream`
 * @param {Object<string, (ev: MessageEvent)=>void>} handlers 事件名 -> 回调
 * @param {(err: Event)=>void} [onError] 出错回调（默认自动关闭）
 * @returns {EventSource}
 */
export function createSSE(path, handlers = {}, onError) {
  const es = new EventSource(API_BASE + path)
  for (const [event, cb] of Object.entries(handlers)) {
    es.addEventListener(event, cb)
  }
  es.onerror = (err) => {
    if (onError) onError(err)
    else {
      try { es.close() } catch (_) {}
    }
  }
  return es
}

/** 复制文本到剪贴板（带降级） */
export async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.cssText = 'position:fixed;left:-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    ElMessage.success('已复制到剪贴板')
    return true
  } catch (e) {
    ElMessage.error('复制失败: ' + e.message)
    return false
  }
}

/** 时间戳(秒) -> 本地时间字符串 */
export function fmtTime(ts) {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
}
