<script setup lang="ts">
withDefaults(defineProps<{
  title?: string
  tone?: 'neutral' | 'info' | 'warning' | 'danger' | 'success'
}>(), { title: '', tone: 'info' })
</script>

<template>
  <aside class="notice" :class="`notice-${tone}`">
    <div class="notice-icon">{{ tone === 'warning' ? '!' : tone === 'danger' ? '×' : tone === 'success' ? '✓' : 'i' }}</div>
    <div><strong v-if="title">{{ title }}</strong><p><slot /></p></div>
  </aside>
</template>

<style scoped>
.notice { display: flex; gap: 12px; align-items: flex-start; padding: 13px 15px; border: 1px solid; border-radius: 11px; font-size: 12px; line-height: 1.65; }
.notice-icon { display: grid; place-items: center; flex: 0 0 22px; height: 22px; border-radius: 50%; color: white; font-weight: 800; }
.notice strong { display: block; margin-bottom: 2px; color: #27364b; }
.notice p { margin: 0; }
.notice-info { border-color: #c8def9; color: #496681; background: #f0f7ff; }.notice-info .notice-icon { background: #3b82f6; }
.notice-neutral { border-color: #d8e0e9; color: #64748b; background: #f7f9fc; }.notice-neutral .notice-icon { background: #8796a8; }
.notice-warning { border-color: #efd39e; color: #72531f; background: #fff9eb; }.notice-warning .notice-icon { background: #d58a1e; }
.notice-danger { border-color: #f0b8c0; color: #7e3740; background: #fff3f5; }.notice-danger .notice-icon { background: #d94857; }
.notice-success { border-color: #b8e2cd; color: #356a51; background: #effaf5; }.notice-success .notice-icon { background: #1c9767; }
</style>
