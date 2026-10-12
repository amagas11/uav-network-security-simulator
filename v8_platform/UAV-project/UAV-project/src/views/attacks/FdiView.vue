<script setup lang="ts">
import { computed } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import PageHeader from '@/components/common/PageHeader.vue'
import StageStepper from '@/components/common/StageStepper.vue'
import RunControls from '@/components/common/RunControls.vue'
import PacketStatistics from '@/components/common/PacketStatistics.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ScenarioContextNotice from '@/components/common/ScenarioContextNotice.vue'
import EventTable from '@/components/common/EventTable.vue'
import AttackEvaluationPanel from '@/components/common/AttackEvaluationPanel.vue'
import ScenarioTopology from '@/components/topology/ScenarioTopology.vue'
import TimeSeriesChart from '@/components/charts/TimeSeriesChart.vue'
import ApplicationHmacCard from '@/components/security/ApplicationHmacCard.vue'
import { humanizeSecurityResult, displayValue, formatNumber, reportReason, shortId } from '@/utils/runtimeFormat'
import { buildCumulativeReportSeries } from '@/utils/reportSeries'
import { fdiEvidence } from '@/utils/fdiEvidence'

const store = useSimulationStore()
const runMatches = computed(() => store.isRunFor('FDI'))
const plan = computed(() => runMatches.value ? store.runMetadata?.attack_plan?.find((item) => item.attack_family === 'FDI') ?? null : null)
const modifications = computed(() => fdiEvidence(runMatches.value ? store.packetAccounting : null, authReports.value))
const modification = computed(() => modifications.value[modifications.value.length - 1] ?? null)
const capture = computed(() => runMatches.value ? store.packetAccounting?.causal_evidence?.captures?.find(item => item.family === 'FDI') ?? null : null)
const originalAltitude = computed(() => {
  const value = modification.value?.original_payload?.altitude_m
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const offset = computed(() => {
  const value = originalAltitude.value === null || modifiedAltitude.value === null ? null : modifiedAltitude.value - originalAltitude.value
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const modifiedAltitude = computed(() => {
  const value = modification.value?.payload?.altitude_m
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const hmacMetadata = computed(() => runMatches.value ? store.runMetadata?.application_hmac ?? null : null)
const originalPayloadLabel = computed(() => originalAltitude.value === null ? '—' : `altitude_m=${formatNumber(originalAltitude.value, 3)}`)
const modifiedPayloadLabel = computed(() => modifiedAltitude.value === null ? '—' : `altitude_m=${formatNumber(modifiedAltitude.value, 3)}`)
const authReports = computed(() => store.reportsForFamily('FDI'))
const authReport = computed(() => modification.value?.report ?? null)
const detectionConfirmed = computed(() => authReport.value !== null)
const defenseExecuted = computed(() => authReport.value?.action_result?.executed === true)
const executedDefenseAction = computed(() => defenseExecuted.value
  ? authReport.value?.action_result?.request?.action ?? '已执行安全处置'
  : null)
const onlineHmacResult = computed(() => authReport.value ? reportReason(authReport.value) : null)
const reportTrend = computed(() => buildCumulativeReportSeries({
  reports: authReports.value,
  matchDetection: (report) => String(report.category || '').toUpperCase() === 'AUTH_FAILURE',
  matchExecutedAction: (report) => report.action_result?.executed === true,
}))
const labels = computed(() => reportTrend.value.map((point) => point.label))
const series = computed(() => [
  { name: 'AUTH_FAILURE 累计', color: '#d94857', area: true, step: 'end' as const, data: reportTrend.value.map((point) => point.detectedCount) },
  { name: '已执行安全处置累计', color: '#168a5b', step: 'end' as const, data: reportTrend.value.map((point) => point.executedCount) },
])
</script>

<template>
  <div class="page-grid">
    <PageHeader eyebrow="Attack / False Data Injection" title="FDI攻击（虚假数据注入）" description="External 捕获合法遥测报文，篡改业务内容后额外注入副本；合法原报文正常传输。" detection-label="检测机制：HMAC 完整性校验" protection-label="处置策略：丢弃且不更新业务" />
    <StageStepper :current="store.scenarioStage('FDI')" />
    <section class="panel"><RunControls scenario="fdi" /></section>
    <PacketStatistics family="FDI" />
    <ScenarioContextNotice family="FDI" page-label="FDI" />

    <section class="scenario-core">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景配置 / 执行证据</span><h2 class="panel-title">合法报文 → 捕获 → 篡改副本注入</h2></div></div>
        <ScenarioTopology mode="fdi" :topology="runMatches ? store.topology : null" :attack-plan="plan" :reports="authReports" :primary-flow="store.primaryBusinessFlowFor('FDI')" :run-state="store.status?.state" :capture="capture" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">仿真真值 · 最近篡改</span><h2 class="panel-title">遥测字段篡改（altitude_m）</h2></div></div>
        <div class="value-comparison"><div><span>原始高度测量（m）</span><strong>{{ formatNumber(originalAltitude, 3) }}</strong><small>合法原报文真实测量值</small></div><b>{{ offset === null ? '—' : `+ ${formatNumber(offset, 3)}` }}</b><div class="modified"><span>攻击副本篡改值（m）</span><strong>{{ formatNumber(modifiedAltitude, 3) }}</strong><small>原始 HMAC 标签保持不变</small></div></div>
        <dl class="data-list">
          <div class="data-row"><dt>修改阶段</dt><dd>已认证合法报文捕获后，修改副本业务内容</dd></div>
          <div class="data-row"><dt>来源报文</dt><dd :title="modification?.original_message_id">{{ modification?.original_message_id ?? '—' }}</dd></div>
          <div class="data-row"><dt>报文 / 序号</dt><dd>{{ modification?.message_id ?? '—' }} / {{ modification?.sequence_no ?? '—' }}</dd></div>
          <div class="data-row"><dt>实际修改时间</dt><dd>{{ modification ? `${formatNumber(modification.modified_time_s, 2)} s` : '—' }}</dd></div>
          <div class="data-row"><dt>HMAC 重算</dt><dd>{{ modification ? (modification.hmac_recomputed ? '是' : '否') : '—' }}</dd></div>
          <div class="data-row"><dt>主检测机制</dt><dd>Application HMAC mismatch</dd></div>
          <div class="data-row"><dt>实际接收证据</dt><dd>{{ authReport ? reportReason(authReport) : '—' }}</dd></div>
        </dl>
        <details data-testid="fdi-details"><summary>篡改详情（{{ modifications.length }} 条）</summary><p>逐报文小幅扰动验证完整性检测，不代表严重飞行偏差。</p><div class="table-scroll"><table class="event-table evidence-table"><thead><tr><th>原报文 / 攻击副本</th><th>altitude_m 原值 → 篡改值</th><th>捕获 / 修改 / 发送</th><th>在线验证</th><th>处置 / 执行状态</th></tr></thead><tbody>
          <tr v-for="item in modifications" :key="item.message_id" class="causal-detail-row" :data-message-id="item.message_id">
            <td><span :title="item.original_message_id">{{ item.original_message_id ? shortId(item.original_message_id) : '兼容模式' }}</span><br /><span :title="item.message_id">{{ shortId(item.message_id) }}</span><br />序号 {{ item.sequence_no }}</td>
            <td>{{ item.original_payload.altitude_m }} → {{ item.payload.altitude_m }}<br />HMAC 不重算</td>
            <td>External<br />捕获 {{ item.capture_time_s == null ? '—' : formatNumber(item.capture_time_s,2) + ' s' }}<br />修改 {{ formatNumber(item.modified_time_s,2) }} s<br />发送 {{ item.transmission ? formatNumber(item.transmission.sent_time_s,2) + ' s' : '等待发送' }}</td>
            <td><span class="evidence-code">{{ item.report ? reportReason(item.report) : '等待报告' }}</span></td>
            <td><span class="evidence-code">{{ item.report?.action_result?.request?.action || '—' }}</span><span class="evidence-execution">{{ item.report?.action_result?.executed === true ? '已执行' : item.report?.action_result?.executed === false ? '未执行' : '—' }}</span></td>
          </tr>
        </tbody></table></div></details>
      </article>
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">仿真执行 / 在线判定</span><h2 class="panel-title">HMAC 检测与阻断</h2></div></div>
        <div class="mechanism-flow fdi-mechanism-flow"><div class="mechanism-node"><strong>原始业务 HMAC</strong><span>altitude_m={{ formatNumber(originalAltitude, 3) }}</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node"><strong>业务内容篡改</strong><span>altitude_m={{ formatNumber(modifiedAltitude, 3) }}</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node" :class="{ danger: detectionConfirmed }"><strong>{{ authReport ? humanizeSecurityResult(reportReason(authReport)) : '等待在线检测证据' }}</strong><span>微小修改同样会导致不匹配</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node" :class="{ success: defenseExecuted }"><strong>{{ executedDefenseAction === 'DROP_PACKET' ? '实际丢弃' : executedDefenseAction || '等待安全处置' }}</strong><span>实际安全处置</span></div></div>
        <TimeSeriesChart :labels="labels" :series="series" :height="220" />
      </article>
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">GCS 已接收</span><h2 class="panel-title">实时安全事件</h2><p class="panel-subtitle">当前 FDI 在线报告数 {{ displayValue(authReports.length) }}。</p></div></div><EventTable :reports="authReports" :node-roles="store.runMetadata?.node_roles" /></article>
    </section>
    <ApplicationHmacCard
      mode="fdi"
      :metadata="hmacMetadata"
      :original-payload="originalPayloadLabel"
      :modified-payload="modifiedPayloadLabel"
      :online-result="onlineHmacResult"
      :action="authReport?.action_result?.request?.action"
      :action-executed="authReport?.action_result?.executed"
      :injection-stage="String(plan?.parameters?.injection_mode || 'POST_HMAC_PRE_TRANSMISSION')"
      :hmac-recomputed="modification?.hmac_recomputed ?? null"
    />

    <AttackEvaluationPanel family="FDI" />
  </div>
</template>

<style scoped>
.value-comparison { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 12px; margin-bottom: 13px; }.value-comparison > div { padding: 17px; border: 1px solid #dce4ed; border-radius: 11px; background: #f8fbff; }.value-comparison > div.modified { border-color: #f0b9c0; background: #fff5f6; }.value-comparison span,.value-comparison strong,.value-comparison small { display: block; }.value-comparison span { color: #718096; font-size: 11px; }.value-comparison strong { margin: 7px 0; font-size: 25px; }.value-comparison small { color: #8996a7; font-size: 10px; }.value-comparison > b { color: #d94857; font-size: 13px; }
.enum-stack { display: grid; justify-items: end; gap: 5px; }.enum-stack code,.technical-value { color: #8794a5; font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }.technical-value { display: block; margin-top: 4px; overflow-wrap: anywhere; }
.fdi-mechanism-flow .mechanism-node { min-width: 0; padding-right: 9px; padding-left: 9px; }.fdi-mechanism-flow .mechanism-arrow { flex: 0 0 auto; }
@media (max-width: 700px) { .value-comparison { grid-template-columns: 1fr; }.value-comparison > b { text-align: center; } }
</style>
