<script setup>
// Ant 风状态：圆点 + 文字，比纯色块 tag 更克制专业。
defineProps({
  type: { type: String, default: 'info' }, // success/warning/danger/primary/info
  text: { type: [String, Number], default: '' },
})
const COLORS = {
  success: '#52c41a',
  warning: '#faad14',
  danger: '#ff4d4f',
  primary: 'var(--brand)',
  info: '#909399',
}
</script>

<template>
  <span class="status-dot">
    <i :style="{ background: COLORS[type] || COLORS.info }" />{{ text }}
  </span>
</template>

<style scoped>
.status-dot { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; white-space: nowrap; }
.status-dot i { width: 6px; height: 6px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
</style>
