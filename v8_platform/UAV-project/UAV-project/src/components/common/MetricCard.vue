<script setup lang="ts">
withDefaults(defineProps<{
  label: string
  value: string | number
  note?: string
  tone?: 'blue' | 'red' | 'green' | 'orange' | 'slate'
  icon?: string
}>(), { note: '', tone: 'blue', icon: '•' })
</script>

<template>
  <article class="metric-card" :class="`tone-${tone}`">
    <div class="metric-icon">{{ icon }}</div>
    <div class="metric-content"><span>{{ label }}</span><strong>{{ value }}</strong><small>{{ note || '—' }}</small></div>
  </article>
</template>

<style scoped>
.metric-card { display: flex; gap: 13px; min-width: 0; min-height: 124px; padding: 18px; border: 1px solid #dfe6ef; border-radius: 13px; background: white; box-shadow: 0 7px 22px rgba(24,49,81,.06); }
.metric-icon { display: grid; place-items: center; flex: 0 0 38px; height: 38px; border-radius: 10px; font-size: 19px; font-weight: 800; }
.metric-content { min-width: 0; }
.metric-content span { display: block; color: #6d7c90; font-size: 12px; }
.metric-content strong { display: block; margin: 5px 0 4px; overflow: hidden; color: #17243a; font-size: 24px; line-height: 1.1; text-overflow: ellipsis; white-space: nowrap; }
.metric-content small { display: -webkit-box; min-height: 27px; overflow: hidden; color: #8795a7; font-size: 10px; line-height: 1.35; overflow-wrap: anywhere; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
.tone-blue .metric-icon { color: #246fe5; background: #e6f0ff; }.tone-red .metric-icon { color: #d53f4f; background: #fee8eb; }.tone-green .metric-icon { color: #168a5b; background: #dcf8ea; }.tone-orange .metric-icon { color: #c47414; background: #fff1d7; }.tone-slate .metric-icon { color: #52667e; background: #e9eef5; }
</style>
