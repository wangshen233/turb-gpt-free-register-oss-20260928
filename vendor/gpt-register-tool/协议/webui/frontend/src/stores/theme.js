import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

const KEY = 'dango_theme_dark'

export const useThemeStore = defineStore('theme', () => {
  const dark = ref(localStorage.getItem(KEY) === '1')

  function apply() {
    document.documentElement.classList.toggle('dark', dark.value)
  }
  function toggle() {
    dark.value = !dark.value
  }

  watch(dark, (v) => {
    localStorage.setItem(KEY, v ? '1' : '0')
    apply()
  }, { immediate: true })

  return { dark, toggle, apply }
})
