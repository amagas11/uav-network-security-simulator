<script setup lang="ts">
import { computed } from 'vue'
import type { SecurityReport } from '@/api'
import {
  formatReportTime,
  humanizeReportCategory,
  nodeDisplayName,
  reportAction,
  reportReason,
  shortId,
} from '@/utils/runtimeFormat'
import StatusBadge from './StatusBadge.vue'

const props = withDefaults(defineProps<{
  reports: SecurityReport[]
  limit?: number
  nodeRoles?: Record<string, string>
}>(), { limit: 8, nodeRoles: () => ({}) })
const rows = computed(() => [...props.reports].reverse().slice(0, props.limit))
const scopeSummary = computed(() => props.reports.length > rows.value.length
  ? `最近 ${rows.value.length} 条 / 共 ${props.reports.length} 条`
  : `共 ${props.reports.length} 条`)

function severityTone(value?: string): 'danger' | 'warning' | 'info' | 'neutral' {
  if (['CRITICAL', 'EMERGENCY', 'HIGH'].includes(String(value))) return 'danger'
  if (value === 'MEDIUM') return 'warning'
  if (value === 'LOW') return 'info'
  return 'neutral'
}

function executionLabel(report: SecurityReport): string {
  if (report.action_result?.executed === true) return '已执行'
  if (report.action_result?.executed === false) return '未执行'
  return '—'
}
</script>

<template>
  <div class="table-wrap">
    <div v-if="rows.length" class="table-scope-summary">{{ scopeSummary }}</div>
    <table v-if="rows.length" class="event-table">
      <thead><tr><th>仿真时间</th><th>报告ID</th><th>检测/上报节点</th><th>类别 / 证据</th><th>处置</th><th>执行状态</th></tr></thead>
      <tbody>
        <tr v-for="report in rows" :key="String(report.report_id || report.summary_id)">
          <td>{{ formatReportTime(report) }}</td>
          <td class="mono" :title="String(report.report_id || report.summary_id || '—')">{{ shortId(String(report.report_id || report.summary_id || '—')) }}</td>
          <td><strong class="node-name">{{ nodeDisplayName(report.source_node_id, nodeRoles) }}</strong><small v-if="report.source_node_id != null">Node {{ report.source_node_id }}</small></td>
          <td><StatusBadge :label="humanizeReportCategory(report.category || report.report_type)" :tone="severityTone(report.severity)" /><small class="technical-evidence" :title="`${report.category || report.report_type || '—'} · ${reportReason(report)}`">{{ report.category || report.report_type || '—' }} · {{ reportReason(report) }}</small></td>
          <td class="action-code">{{ reportAction(report) }}</td>
          <td><StatusBadge :label="executionLabel(report)" :tone="report.action_result?.executed === true ? 'success' : 'neutral'" /></td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty-state"><div><strong>暂无安全报告</strong></div></div>
  </div>
</template>

<style scoped>
.table-wrap { width: 100%; overflow-x: auto; }
.table-scope-summary { padding: 0 2px 9px; color: #7b899b; font-size: 10px; text-align: right; }
.event-table { width: 100%; min-width: 760px; border-collapse: collapse; }
th { padding: 10px 12px; color: #718096; background: #f7f9fc; font-size: 10px; font-weight: 700; letter-spacing: .05em; text-align: left; text-transform: uppercase; }
td { padding: 12px; border-bottom: 1px solid #edf1f5; color: #35455a; font-size: 12px; vertical-align: middle; }
tbody tr:hover { background: #fafcff; }
td small { display: block; max-width: 220px; margin-top: 5px; overflow: hidden; color: #8290a2; text-overflow: ellipsis; white-space: nowrap; }
.node-name { display: block; color: #35455a; font-size: 11px; font-weight: 700; }
.technical-evidence { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.action-code,.mono { white-space:nowrap; word-break:normal; overflow-wrap:normal; }
</style>
