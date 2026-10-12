<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import Sidebar from '@/components/common/Sidebar.vue'
import TopBar from '@/components/common/TopBar.vue'
import NoticeBanner from '@/components/common/NoticeBanner.vue'

const store = useSimulationStore()

onMounted(() => void store.bootstrap())
onBeforeUnmount(() => store.stopPolling())
</script>

<template>
  <div class="app-shell">
    <Sidebar />
    <div class="app-column">
      <TopBar />
      <main class="app-content">
        <NoticeBanner v-if="store.error" tone="danger" title="操作未完成">{{ store.error }}</NoticeBanner>
        <RouterView />
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-shell { min-height: 100vh; background: #f4f7fb; }
.app-column { min-width: 0; margin-left: 224px; }
.app-content { width: min(100%, 1720px); min-height: calc(100vh - 62px); margin: 0 auto; padding: 24px 28px 20px; }
.app-content > :deep(.notice) { margin-bottom: 16px; }
@media (max-width: 900px) { .app-column { margin-left: 72px; }.app-content { padding: 20px 16px; } }
</style>
