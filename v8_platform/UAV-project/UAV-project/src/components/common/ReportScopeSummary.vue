<script setup lang="ts">
import { computed } from 'vue'
import type { SecurityReport } from '@/api'
import { visibleReportScope } from '@/utils/reportScope'
import { humanizeReportCategory } from '@/utils/runtimeFormat'
const props = defineProps<{ reports: SecurityReport[]; crossCategory?: boolean }>()
const scope = computed(() => visibleReportScope(props.reports))
</script>
<template>
  <div v-if="reports.length" class="report-scope" data-testid="report-scope">
    <div><strong>GCS 已接收报告</strong><span v-for="(count, category) in scope.categories" :key="category" :data-report-category="category">{{ humanizeReportCategory(category) }} {{ count }} 份</span></div>
    <div><strong>报告确认执行</strong><span v-for="(count, action) in scope.actions" :key="action" :data-report-action="action">{{ action }} {{ count }} 份</span><span v-if="!scope.executed">无已执行处置</span></div>
    <details><summary>报告与动作口径</summary>每份已送达 GCS 的报告/汇总计一次；汇总保留最近处置结果，不能作为全部本地动作总数。洪泛检测与认证丢弃分别统计，均不表示无线拥塞已消除。<p v-if="crossCategory && scope.categories.DOS">接收总到达速率触发额外洪泛告警，不表示新增 DoS 攻击计划。合法原报文、攻击副本及控制流量均可能贡献接收负载。</p></details>
  </div>
</template>
<style scoped>
.report-scope { margin:10px 0;color:#64748b;font-size:12px;line-height:1.6; }
.report-scope > div { display:flex;gap:8px 14px;flex-wrap:wrap; }.report-scope strong { color:#425670; }.report-scope span { white-space:nowrap; }.report-scope p { margin:5px 0; }.report-scope details { margin-top:4px; }
</style>
