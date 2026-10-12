<script setup lang="ts">
import StatusBadge from './StatusBadge.vue'

defineProps<{
  eyebrow: string
  title: string
  description: string
  detectionLabel?: string
  protectionLabel?: string
  protectionTone?: 'neutral' | 'info' | 'success' | 'warning' | 'danger'
  eavesdropping?: boolean
}>()
</script>

<template>
  <header class="page-header">
    <div class="page-copy">
      <p>{{ eyebrow }}</p>
      <h1>{{ title }}</h1>
      <span>{{ description }}</span>
    </div>
    <div class="mechanism-state">
      <StatusBadge v-if="eavesdropping" label="直接检测 N/A" tone="neutral" />
      <StatusBadge v-else :label="detectionLabel || '检测机制：已配置'" tone="info" />
      <StatusBadge :label="protectionLabel || '处置策略：按规则执行'" :tone="protectionTone || 'info'" />
    </div>
  </header>
</template>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
.page-copy { min-width: 0; }
.page-copy p { margin: 0 0 7px; color: #3575ca; font-size: 11px; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
.page-copy h1 { margin: 0; color: #17243a; font-size: clamp(24px, 2.2vw, 32px); line-height: 1.2; }
.page-copy span { display: block; max-width: 850px; margin-top: 9px; color: #69788c; font-size: 13px; line-height: 1.65; }
.mechanism-state { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; padding-top: 5px; }
@media (max-width: 850px) { .page-header { flex-direction: column; }.mechanism-state { justify-content: flex-start; } }
</style>
