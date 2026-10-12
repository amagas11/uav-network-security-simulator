<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useSimulationStore } from '@/stores/simulation'
import StatusBadge from './StatusBadge.vue'

const route = useRoute()
const store = useSimulationStore()
const stateTone = computed(() => store.status?.state === 'RUNNING' ? 'info' : store.status?.state === 'PAUSED' ? 'warning' : store.status?.state === 'COMPLETED' ? 'info' : 'neutral')
</script>

<template>
  <header class="topbar">
    <div class="breadcrumb"><span>无人机编队安全</span><b>/</b><strong>{{ route.meta.title || '系统总览' }}</strong></div>
    <div class="topbar-right">
      <span class="mode">在线仿真 · 运行数据</span>
      <details v-if="store.status" class="run-details"><summary>运行详情</summary><code>{{ store.status.run_id }}</code></details>
      <StatusBadge :label="store.status?.state || '未初始化'" :tone="stateTone" :pulse="store.status?.state === 'RUNNING'" />
    </div>
  </header>
</template>

<style scoped>
.topbar { position: sticky; top: 0; z-index: 15; display: flex; align-items: center; justify-content: space-between; gap: 20px; height: 62px; padding: 0 28px; border-bottom: 1px solid #e1e7ef; background: rgba(255,255,255,.94); backdrop-filter: blur(12px); }
.breadcrumb { display: flex; align-items: center; gap: 8px; color: #8a98aa; font-size: 12px; }.breadcrumb b { color: #c3cbd5; }.breadcrumb strong { color: #33445b; }
.run-details { position:relative;font-size:11px;color:#758399; }.run-details code { position:absolute;right:0;top:24px;padding:12px;background:white;border:1px solid #dce3eb;white-space:nowrap; }
.topbar-right { display: flex; align-items: center; gap: 11px; }.mode { color: #52749c; font-size: 11px; font-weight: 650; }.run-id { padding: 5px 8px; border: 1px solid #dce3eb; border-radius: 6px; color: #758399; font: 10px ui-monospace,monospace; background: #f8fafc; }
@media (max-width: 780px) { .mode, .run-id { display: none; }.topbar { padding: 0 16px; } }
</style>
