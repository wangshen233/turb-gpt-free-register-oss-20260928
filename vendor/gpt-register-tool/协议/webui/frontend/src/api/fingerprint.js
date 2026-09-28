import http from './request'

export const getFingerprintConfig = () => http.get('/api/fingerprint/config')
export const saveFingerprintConfig = (payload) => http.post('/api/fingerprint/config', payload)
export const diagnoseFingerprint = (payload = {}) =>
  http.post('/api/fingerprint/diagnose', payload)
