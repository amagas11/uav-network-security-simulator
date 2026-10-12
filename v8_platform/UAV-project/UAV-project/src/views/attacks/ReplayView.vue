<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import type { ReplaySubtype } from '@/config/scenarios'
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
import { displayValue, humanizeAttackSubtype, humanizeSecurityResult, reportReason } from '@/utils/runtimeFormat'
import { buildCumulativeReportSeries } from '@/utils/reportSeries'

const store = useSimulationStore()
const subtype = ref<ReplaySubtype>('IMMEDIATE_REPLAY')
const hydratedRunId = ref<string | null>(null)
const subtypeOptions: Array<{ value: ReplaySubtype; label: string }> = [
  { value: 'IMMEDIATE_REPLAY', label: '即时重放' },
  { value: 'DELAYED_REPLAY', label: '延迟重放' },
  { value: 'OLD_SESSION_REPLAY', label: '旧会话重放' },
]
const runMatches = computed(() => store.isRunFor('REPLAY'))
const plan = computed(() => runMatches.value ? store.attackPlanFor('REPLAY') : null)
const capture = computed(() => runMatches.value ? store.packetAccounting?.causal_evidence?.captures?.find((item) => item.family === 'REPLAY') ?? null : null)
const replayTransmission = computed(() => capture.value ? store.packetAccounting?.causal_evidence?.transmissions?.find(tx => tx.message_id === capture.value!.message_id && tx.actual_sender_id === plan.value?.attacker_node_id && tx.sent_time_s > capture.value!.capture_time_s) ?? null : null)
const originalAcceptance = computed(() => capture.value ? store.packetAccounting?.causal_evidence?.security_observations?.find(event => event.message_id === capture.value!.message_id && event.observer_node_id === capture.value!.receiver_id && event.security_state?.application_hmac_result === 'PASS' && event.security_state?.replay_check_result === 'PASS') ?? null : null)
const replayReports = computed(() => store.reportsForFamily('REPLAY'))
const latestReport = computed(() => replayReports.value[replayReports.value.length - 1] ?? null)
const replayEvents = computed(() => runMatches.value ? store.events.filter((event) => {
  const result = event.online_features.security_state?.replay_check_result
  return event.event_type === 'AUTH_RESULT' && result && !['PASS', 'UNAVAILABLE'].includes(result)
}) : [])
const latestReplayEvent = computed(() => replayEvents.value[replayEvents.value.length - 1] ?? null)
const rejection = computed(() => latestReport.value ? reportReason(latestReport.value) : latestReplayEvent.value?.online_features.security_state?.replay_check_result ?? null)
const onlineHmacResult = computed(() => latestReport.value?.evidence?.application_hmac_result ?? latestReplayEvent.value?.online_features.security_state?.application_hmac_result ?? null)
const sequenceNo = computed(() => latestReport.value?.evidence?.sequence_no ?? latestReplayEvent.value?.online_features.packet?.sequence_no ?? null)
const defenseAction = computed(() => latestReport.value?.action_result?.request?.action ?? null)
const defenseExecuted = computed(() => latestReport.value?.action_result?.executed ?? null)
const reportTrend = computed(() => buildCumulativeReportSeries({
  reports: replayReports.value,
  matchDetection: (report) => String(report.category || '').toUpperCase() === 'REPLAY',
  matchExecutedAction: (report) => report.action_result?.executed === true,
}))
const labels = computed(() => reportTrend.value.map((point) => point.label))
const series = computed(() => [
  { name: 'Replay 拒绝累计', color: '#d94857', area: true, step: 'end' as const, data: reportTrend.value.map((point) => point.detectedCount) },
  { name: '已执行 DROP_PACKET 累计', color: '#168a5b', step: 'end' as const, data: reportTrend.value.map((point) => point.executedCount) },
])

watch([() => store.runMetadata?.run_id, plan], ([runId, currentPlan]) => {
  if (!runMatches.value || !runId || !currentPlan || hydratedRunId.value === runId) return
  const value = String(currentPlan.attack_subtype || '')
  if (subtypeOptions.some((item) => item.value === value)) subtype.value = value as ReplaySubtype
  hydratedRunId.value = runId
}, { immediate: true })
</script>

<template>
  <div class="page-grid">
    <PageHeader eyebrow="Attack / Replay" title="重放攻击" description="攻击者捕获完整合法报文，并在之后原样重新发送。" detection-label="检测机制：新鲜度与重放校验" protection-label="处置策略：拒绝重放报文" />
    <StageStepper :current="store.scenarioStage('REPLAY')" />
    <section class="panel"><div class="launch-caption"><strong>下一次启动参数</strong></div><div class="controls-inline replay-controls"><label class="control-field">重放类型<select v-model="subtype"><option v-for="item in subtypeOptions" :key="item.value" :value="item.value">{{ item.label }}</option></select></label><RunControls scenario="replay" :options="{ replaySubtype: subtype }" /></div><div class="current-config"><span>当前运行配置</span><strong>{{ plan ? humanizeAttackSubtype(plan.attack_subtype) : '—' }}</strong></div></section>
    <PacketStatistics family="REPLAY" />
    <ScenarioContextNotice family="REPLAY" page-label="重放攻击" />

    <section class="scenario-core">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景设定</span><h2 class="panel-title">合法报文捕获与重放</h2></div><div class="enum-stack"><StatusBadge :label="plan ? humanizeAttackSubtype(plan.attack_subtype) : '等待场景'" :tone="plan ? 'danger' : 'neutral'" /></div></div>
        <ScenarioTopology mode="replay" :topology="runMatches ? store.topology : null" :attack-plan="plan" :reports="replayReports" :primary-flow="store.primaryBusinessFlowFor('REPLAY')" :run-state="store.status?.state" :capture="capture" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">仿真真值</span><h2 class="panel-title">原始合法报文 → 捕获 → 原样重放</h2></div></div>
        <dl class="data-list"><div class="data-row"><dt>原帧来源</dt><dd>{{ capture ? `节点 ${capture.sender_id} · ${capture.message_id}` : '等待捕获证据' }}</dd></div><div class="data-row"><dt>捕获时间</dt><dd>{{ capture ? `${capture.capture_time_s.toFixed(2)} s` : '—' }}</dd></div><div class="data-row"><dt>攻击者动作</dt><dd>截获、保存、单次原样重发</dd></div><div class="data-row"><dt>内容变化</dt><dd>无修改；HMAC 验证完整性，重放规则检查新鲜度与唯一性。</dd></div></dl>
        <details data-testid="replay-details"><summary>捕获 / 重放证据与完整保留字段</summary><p>任一检查拒绝后停止后续检查。单报文样本用于验证拒绝规则，不评价大规模业务稳定性。</p><dl class="data-list"><div class="data-row"><dt>原帧传输标识</dt><dd>{{ capture?.frame_emission_id || '—' }}</dd></div><div class="data-row"><dt>原件目标处理记录</dt><dd>{{ originalAcceptance ? 'HMAC PASS · Replay PASS' : '等待目标记录' }}</dd></div><div class="data-row"><dt>实际重放时间</dt><dd>{{ replayTransmission ? replayTransmission.sent_time_s.toFixed(2) + ' s' : '等待重放发送' }}</dd></div><div class="data-row"><dt>重放传输标识</dt><dd>{{ replayTransmission?.emission_id || '—' }}</dd></div></dl><div class="preserved-grid"><span v-for="field in ['device_id','packet_type','business_payload','payload_length','sequence_no','timestamp','application HMAC','session_id','key_epoch']" :key="field">{{ field }}<b>保持不变</b></span></div></details>
        <dl class="data-list">
          <div class="data-row"><dt>样本范围</dt><dd>单次已捕获合法报文重放</dd></div>
          <div class="data-row"><dt>Sequence No.</dt><dd>{{ displayValue(sequenceNo) }}</dd></div>
          <div class="data-row"><dt>Application HMAC</dt><dd><strong>{{ onlineHmacResult ? humanizeSecurityResult(onlineHmacResult) : '—' }}</strong><small v-if="onlineHmacResult" class="technical-value">{{ onlineHmacResult }}</small></dd></div>
          <div class="data-row"><dt>Replay Check</dt><dd><strong>{{ rejection ? humanizeSecurityResult(rejection) : '—' }}</strong><small v-if="rejection" class="technical-value">{{ rejection }}</small></dd></div>
          <div class="data-row"><dt>Defense</dt><dd>{{ displayValue(defenseAction) }}</dd></div>
          <div class="data-row"><dt>Action Executed</dt><dd>{{ defenseExecuted === null ? '—' : defenseExecuted ? '是' : '否' }}</dd></div>
        </dl>
      </article>
    </section>

    <section class="panel">
      <div class="panel-header"><div><span class="source-label source-truth">机制说明</span><h2 class="panel-title">重放检测流程</h2></div></div>
      <div class="mechanism-flow replay-flow"><div class="mechanism-node" :class="{ success: onlineHmacResult === 'PASS' }"><strong>{{ onlineHmacResult ? humanizeSecurityResult(onlineHmacResult) : '等待 HMAC 证据' }}</strong><span>{{ onlineHmacResult || 'Application HMAC' }} · 原始报文身份与完整性</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node"><strong>时间戳新鲜度</strong><span>Delayed → STALE_TIMESTAMP</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node"><strong>会话 / key_epoch</strong><span>Old session → WRONG_SESSION</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node"><strong>序列 ReplayWindow</strong><span>Immediate → DUPLICATE；合法乱序可 PASS</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node" :class="{ danger: rejection }"><strong>{{ rejection ? humanizeSecurityResult(rejection) : '等待在线拒绝证据' }}</strong><span>{{ rejection ? `${rejection} · ${defenseAction || '—'} · ${defenseExecuted === true ? '已执行' : defenseExecuted === false ? '未执行' : '—'}` : '等待在线拒绝证据' }}</span></div></div>
    </section>

    <section class="grid-2">
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">在线 Runtime</span><h2 class="panel-title">拒绝 / 处置趋势</h2></div></div><TimeSeriesChart :labels="labels" :series="series" /></article>
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">GCS 已接收</span><h2 class="panel-title">Replay 安全事件</h2></div></div><EventTable :reports="replayReports" :node-roles="store.runMetadata?.node_roles" /></article>
    </section>
    <AttackEvaluationPanel family="REPLAY" />

  </div>
</template>

<style scoped>
.launch-caption { display: flex; align-items: baseline; gap: 10px; margin-bottom: 11px; }.launch-caption strong { font-size: 11px; }.launch-caption span { color: #7c8999; font-size: 10px; }.replay-controls { grid-template-columns: 260px minmax(420px,1fr); }.current-config { display: flex; align-items: center; gap: 8px; margin-top: 12px; padding-top: 10px; border-top: 1px solid #edf1f5; }.current-config span { color: #7b899b; font-size: 10px; }.current-config strong { color: #435b75; font-size: 11px; }.current-config b { padding: 5px 8px; border-radius: 6px; color: #46627e; background: #edf5ff; font: 9px ui-monospace,monospace; }.preserved-grid { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 8px; margin-bottom: 14px; }.preserved-grid span { padding: 10px; border: 1px solid #dce5ee; border-radius: 8px; color: #506176; background: #f8fbff; font-size: 10px; }.preserved-grid b { display: block; margin-top: 5px; color: #3373bd; font-size: 10px; }.replay-flow .mechanism-node { min-width: 140px; }.enum-stack { display: grid; justify-items: end; gap: 5px; }.enum-stack code,.technical-value { color: #8794a5; font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }.technical-value { display: block; margin-top: 4px; overflow-wrap: anywhere; }
@media (max-width: 800px) { .replay-controls { grid-template-columns: 1fr; }.preserved-grid { grid-template-columns: repeat(2,minmax(0,1fr)); } }
</style>
