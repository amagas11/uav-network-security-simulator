<script setup lang="ts">
import { computed, ref, watch } from 'vue'
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
import { formatNumber, humanizeAttackSubtype } from '@/utils/runtimeFormat'
import { filterTargetDosReports, selectTargetDosReport } from '@/config/topologySemantics'
import { authFailureReportCount, booleanResult, blockedPacketCount, legitimateHarmResult } from '@/utils/dosPresentation'

const store = useSimulationStore()
const floodingRatePps = ref(80)
const floodingDurationS = ref(1.6)
const hydratedRunId = ref<string | null>(null)
const runMatches = computed(() => store.isRunFor('DOS'))
const plan = computed(() => runMatches.value ? store.attackPlanFor('DOS') : null)
const targetNodeId = computed(() => runMatches.value ? store.targetNodeForFamily('DOS') : null)
const currentConfiguredRate = computed(() => {
  const value = plan.value?.intensity?.value
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const currentConfiguredDuration = computed(() => {
  if (!plan.value) return null
  const value = Number(plan.value.end_s) - Number(plan.value.impact_start_s)
  return Number.isFinite(value) ? value : null
})
const targetDosReports = computed(() => {
  if (!runMatches.value || targetNodeId.value === null) return []
  return filterTargetDosReports(store.reportsForFamily('DOS'), targetNodeId.value)
})
const hmacReports = computed(() => runMatches.value
  ? store.reportsForFamily('DOS').filter((report) => String(report.category || '').toUpperCase() === 'AUTH_FAILURE')
  : [])
const executedDropCount = computed(() => hmacReports.value.filter((report) => report.action_result?.executed === true && report.action_result.request?.action === 'DROP_PACKET').length)
const authFailureCount = computed(() => authFailureReportCount(runMatches.value && store.runMetadata?.run_id === store.status?.run_id, store.runMetadata ? store.securityReports : null))
const latestTargetReport = computed(() => selectTargetDosReport(targetDosReports.value, targetNodeId.value))
const threshold = computed(() => {
  const value = latestTargetReport.value?.evidence?.flooding_threshold_pps
    ?? latestTargetReport.value?.evidence?.threshold_pps
    ?? (runMatches.value ? store.runMetadata?.run_config?.flooding_packet_rate_threshold_pps : null)
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const windowS = computed(() => {
  const value = latestTargetReport.value?.evidence?.statistics_window_s
    ?? latestTargetReport.value?.evidence?.window_s
    ?? (runMatches.value ? store.runMetadata?.run_config?.traffic_statistics_window_s : null)
  return typeof value === 'number' && Number.isFinite(value) ? value : null
})
const scopedAlarmHistory = computed(() => runMatches.value ? store.dosAlarmHistory : [])
const latestAlarmRate = computed(() => scopedAlarmHistory.value[0]?.packetRatePps ?? null)
const receiverObservation = computed(() => runMatches.value && targetNodeId.value !== null ? store.receiverRateObservations?.nodes.find((node) => node.node_id === targetNodeId.value) ?? null : null)
const receiverSamples = computed(() => receiverObservation.value?.samples ?? [])
const receiverRate = computed(() => receiverSamples.value[receiverSamples.value.length - 1]?.packet_rate_pps ?? null)
const peakRate = computed(() => receiverObservation.value?.peak_window_rate_pps ?? null)
const labels = computed(() => receiverSamples.value.map((point) => `${point.sim_time_s.toFixed(1)}s`))
const series = computed(() => [
  { name: '目标接收窗口速率', color: '#d94857', area: true, data: receiverSamples.value.map((point) => point.packet_rate_pps) },
  { name: '检测阈值', color: '#c88724', dashed: true, data: receiverSamples.value.map((point) => point.flooding_threshold_pps) },
])
const defenseEvidence = computed(() => store.episodeForFamily('DOS')?.defense_evidence ?? null)
const targetNodeLabel = computed(() => {
  if (targetNodeId.value === null) return '—'
  const role = store.runMetadata?.node_roles?.[String(targetNodeId.value)]
    ?? store.topology?.nodes.find((node) => node.id === targetNodeId.value)?.role
  return `${role || '节点'} ${targetNodeId.value}`
})
const detectorAction = computed(() => latestTargetReport.value?.action_result?.request?.action ?? null)
const dosDetected = computed(() => latestTargetReport.value !== null)

watch([() => store.runMetadata?.run_id, plan], ([runId, currentPlan]) => {
  if (!runMatches.value || !runId || !currentPlan || hydratedRunId.value === runId) return
  const rate = currentPlan.intensity?.value
  const duration = Number(currentPlan.end_s) - Number(currentPlan.impact_start_s)
  if (typeof rate === 'number' && Number.isFinite(rate)) floodingRatePps.value = rate
  if (Number.isFinite(duration)) floodingDurationS.value = duration
  hydratedRunId.value = runId
}, { immediate: true })

function valueWithUnit(value: number | null, unit: string): string {
  return value === null ? '—' : `${formatNumber(value, 1)} ${unit}`
}
</script>

<template>
  <div class="page-grid">
    <PageHeader eyebrow="Attack / Denial of Service" title="DoS攻击（应用层报文洪泛）" description="接收节点按所有来源的总体报文到达数量/速率检测 Flooding；非法攻击帧在普通 RX queue 前由 HMAC gate 丢弃。" detection-label="检测机制：Receiver Total Arrival Rate" protection-label="过滤机制：Application HMAC Gate" />
    <StageStepper :current="store.scenarioStage('DOS')" />
    <section class="panel">
      <div class="launch-caption"><strong>下一次启动参数</strong></div>
      <div class="controls-inline dos-controls"><label class="control-field">洪泛速率（pps）<input v-model.number="floodingRatePps" type="number" min="9" max="500" /></label><label class="control-field">攻击时长（s）<input v-model.number="floodingDurationS" type="number" min="0.4" max="29.2" step="0.2" /></label><RunControls scenario="dos" :options="{ floodingRatePps, floodingDurationS }" /></div>
      <div class="current-config"><span>当前运行配置</span><b>{{ plan ? humanizeAttackSubtype(plan.attack_subtype) : '—' }}</b><b>配置发送速率 {{ valueWithUnit(currentConfiguredRate, 'pps') }}</b><b>持续时间 {{ valueWithUnit(currentConfiguredDuration, 's') }}</b></div>
    </section>
    <PacketStatistics family="DOS" />
    
    <ScenarioContextNotice family="DOS" page-label="DoS/Flooding" />

    <section class="scenario-core">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景配置 / 仿真真值</span><h2 class="panel-title">Flooding 场景拓扑</h2></div><div class="enum-stack"><StatusBadge label="应用层报文洪泛" :tone="plan ? 'danger' : 'neutral'" /><code>FLOODING</code></div></div>
        <ScenarioTopology mode="dos" :topology="runMatches ? store.topology : null" :attack-plan="plan" :reports="targetDosReports" :primary-flow="store.primaryBusinessFlowFor('DOS')" :run-state="store.status?.state" :receiver-peak-rate="peakRate" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">在线 Runtime</span><h2 class="panel-title">攻击目标接收端的 Flooding 检测</h2></div></div>
        <div class="rate-gauge"><div><span>{{ store.status?.state === 'COMPLETED' ? '目标接收端最后采样窗口速率' : '目标接收端最近采样窗口速率' }}</span><strong data-rate="current">{{ valueWithUnit(receiverRate, 'pps') }}</strong></div><div><span>目标接收端峰值窗口速率</span><strong data-rate="peak">{{ valueWithUnit(peakRate, 'pps') }}</strong></div></div>
        <dl class="data-list">
          <div class="data-row"><dt>攻击目标 / 检测节点</dt><dd>{{ targetNodeLabel }}</dd></div>
          <div class="data-row"><dt>配置发送速率</dt><dd>{{ valueWithUnit(currentConfiguredRate, 'pps') }}</dd></div>
          <div class="data-row"><dt>检测阈值</dt><dd>{{ valueWithUnit(threshold, 'pps') }}</dd></div>
          <div class="data-row"><dt>首次告警触发速率</dt><dd>{{ valueWithUnit(latestAlarmRate, 'pps') }}</dd></div>
          <div class="data-row"><dt>{{ latestTargetReport ? '告警统计窗口' : '统计窗口（配置值）' }}</dt><dd>{{ valueWithUnit(windowS, 's') }}</dd></div>
          <div class="data-row"><dt>统计范围</dt><dd>接收端总体到达报文</dd></div>
          <div class="data-row"><dt>DOS 检测</dt><dd><StatusBadge :label="dosDetected ? '已检测' : '等待在线证据'" :tone="dosDetected ? 'danger' : 'neutral'" /></dd></div>
          <div class="data-row"><dt>检测处置请求</dt><dd>{{ detectorAction || '—' }}</dd></div>
          <div class="data-row"><dt>实际执行状态</dt><dd><StatusBadge :label="latestTargetReport?.action_result?.executed === true ? '已执行' : latestTargetReport?.action_result?.executed === false ? '未执行' : '—'" :tone="latestTargetReport?.action_result?.executed === true ? 'success' : 'neutral'" /></dd></div>
          <div class="data-row"><dt>认证失败报告数</dt><dd data-testid="dos-auth-count">{{ authFailureCount ?? '—' }}</dd></div>
        </dl>
      </article>
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">目标接收端观测</span><h2 class="panel-title">接收窗口速率与阈值</h2></div></div>
        <TimeSeriesChart :labels="labels" :series="series" unit="pps" :height="260" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">在线检测 / 数据面处置</span><h2 class="panel-title">两条真实防护链</h2></div></div>
        <div class="defense-stack"><div><b>1</b><div><strong>总体速率告警</strong><span>规则说明：总体速率达到阈值时请求 INCREASE_MONITORING；实际执行见目标报告</span></div></div><div><b>2</b><div><strong>Application HMAC 前置认证</strong><span>External 非法帧 → DROP_PACKET → 不进入普通接收队列</span></div></div></div>
      </article>
    </section>
    <section class="grid-2 dos-evidence-grid">
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">在线 Runtime</span><h2 class="panel-title">目标接收端 Flooding 事件</h2></div></div><EventTable :reports="targetDosReports" :limit="5" :node-roles="store.runMetadata?.node_roles" /></article>
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">数据面处置</span><h2 class="panel-title">HMAC 前置过滤</h2><p class="panel-subtitle">认证失败报告 {{ runMatches ? hmacReports.length : '—' }} 条；已执行 DROP_PACKET {{ runMatches ? executedDropCount : '—' }} 次。</p></div><StatusBadge :label="runMatches ? `${executedDropCount} 次已执行丢弃` : '等待当前场景'" :tone="executedDropCount ? 'success' : 'neutral'" /></div><EventTable :reports="hmacReports" :limit="5" :node-roles="store.runMetadata?.node_roles" /></article>
    </section>
    <AttackEvaluationPanel family="DOS" action-count-note="Episode主要动作；Gate丢弃另计。" />
    <section class="panel">
      <div class="panel-header"><div><span class="source-label source-offline">离线评价</span><h2 class="panel-title">Flooding 防御证据</h2></div></div>
      <dl v-if="defenseEvidence" class="data-list offline-evidence"><div class="data-row"><dt>总体速率达到阈值</dt><dd>{{ booleanResult(defenseEvidence.receiver_total_rate_exceeded) }}</dd></div><div class="data-row"><dt>恶意流量已阻断</dt><dd>{{ blockedPacketCount(defenseEvidence.malicious_traffic_blocked) }}</dd></div><div class="data-row"><dt>合法业务影响受控</dt><dd>{{ legitimateHarmResult(defenseEvidence) }}</dd></div></dl>
      <div v-else class="empty-state"><div><strong>仿真结束后生成</strong>尚无当前 DOS episode 的离线防御证据。</div></div>
    </section>
  </div>
</template>

<style scoped>
.launch-caption { display: flex; align-items: baseline; gap: 10px; margin-bottom: 11px; }.launch-caption strong { font-size: 11px; }.launch-caption span { color: #7c8999; font-size: 10px; }.dos-controls { grid-template-columns: 150px 150px minmax(340px,1fr); }.current-config { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 12px; padding-top: 10px; border-top: 1px solid #edf1f5; }.current-config span { color: #7b899b; font-size: 10px; }.current-config b { padding: 5px 8px; border-radius: 6px; color: #46627e; background: #edf5ff; font: 10px ui-monospace,monospace; }.rate-gauge { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }.rate-gauge > div { padding: 16px; border: 1px solid #e1e7ef; border-radius: 11px; background: #f8fbff; }.rate-gauge span,.rate-gauge strong { display: block; }.rate-gauge span { color: #718096; font-size: 10px; }.rate-gauge strong { margin-top: 8px; font-size: 22px; }.rate-gauge > div:first-child strong { color: #d94857; }.defense-stack { display: grid; gap: 10px; }.defense-stack > div { display: flex; align-items: center; gap: 12px; padding: 13px; border: 1px solid #dce5ed; border-radius: 10px; background: #f8fbff; }.defense-stack b { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 50%; color: white; background: #2773d3; }.defense-stack strong,.defense-stack span { display: block; }.defense-stack strong { font-size: 12px; }.defense-stack span { margin-top: 4px; color: #748398; font-size: 10px; }.offline-evidence { margin-top: 10px; }
.enum-stack { display: grid; justify-items: end; gap: 5px; }.enum-stack code { color: #8794a5; font-size: 10px; }
@media (max-width: 950px) { .dos-controls { grid-template-columns: 1fr 1fr; }.dos-controls :deep(.run-controls) { grid-column: 1 / -1; } }
</style>
