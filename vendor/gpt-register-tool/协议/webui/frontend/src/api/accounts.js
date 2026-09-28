import http from './request'

// ──────────────── 统计 ────────────────
export const getStats = () => http.get('/api/stats')

// ──────────────── 号池 accounts ────────────────
// kind = 邮箱来源（outlook / ...）。留空后端会按段数猜，
// 但 Outlook 和 Gmail 都是 4 段猜不出来，所以页面上必选。
export const importAccounts = (text, kind = '') =>
  http.post('/api/import', { text, kind })

export const listAccounts = (params) =>
  http.get('/api/accounts', { params }) // { status, limit, offset, kind }

export const deleteAccount = (email) =>
  http.delete(`/api/accounts/${encodeURIComponent(email)}`)

export const bulkDeleteAccounts = (payload) =>
  http.post('/api/accounts/bulk_delete', payload) // { status } 或 { emails }

export const resetFailed = () => http.post('/api/accounts/reset_failed')

export const resetAccount = (email) =>
  http.post(`/api/accounts/reset/${encodeURIComponent(email)}`)

export const bulkResetAccounts = (emails) =>
  http.post('/api/accounts/bulk_reset', { emails })

export const releaseStale = () => http.post('/api/accounts/release_stale')
