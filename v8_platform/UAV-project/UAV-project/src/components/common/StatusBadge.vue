<script setup lang="ts">
withDefaults(defineProps<{
  label: string
  tone?: 'neutral' | 'info' | 'success' | 'warning' | 'danger'
  pulse?: boolean
}>(), { tone: 'neutral', pulse: false })
</script>

<template>
  <span class="status-badge" :class="[`tone-${tone}`, { pulse }]">
    <i aria-hidden="true"></i>{{ label }}
  </span>
</template>

<style scoped>
.status-badge { display: inline-flex; align-items: center; gap: 7px; min-height: 27px; padding: 0 10px; border-radius: 999px; font-size: 11px; font-weight: 700; white-space: nowrap; }
.status-badge i { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.tone-neutral { color: #64748b; background: #edf1f6; }
.tone-info { color: #2466bb; background: #e6f0ff; }
.tone-success { color: #168157; background: #dcf7e9; }
.tone-warning { color: #af6811; background: #fff0d1; }
.tone-danger { color: #c73546; background: #fee8eb; }
.pulse i { animation: pulse 1.6s infinite; }
@keyframes pulse { 50% { box-shadow: 0 0 0 5px color-mix(in srgb, currentColor 16%, transparent); } }
</style>
