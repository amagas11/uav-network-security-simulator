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
import { humanizeSecurityResult, humanizeAttackSubtype, reportReason, formatNumber, shortId } from '@/utils/runtimeFormat'
import { spoofingEvidence } from '@/utils/messageEvidence'
import { buildCumulativeReportSeries } from '@/utils/reportSeries'

const store = useSimulationStore()
const runMatches = computed(() => store.isRunFor('SPOOFING'))
const plan = computed(() => runMatches.value ? store.runMetadata?.attack_plan?.find((item) => item.attack_family === 'SPOOFING') ?? null : null)
const capture = computed(() => runMatches.value ? store.packetAccounting?.causal_evidence?.captures?.find((item) => item.family === 'SPOOFING') ?? null : null)
const authReports = computed(() => store.reportsForFamily('SPOOFING'))
const details = computed(() => spoofingEvidence(runMatches.value ? store.packetAccounting : null, authReports.value))
const latestReport = computed(() => details.value[details.value.length - 1]?.report ?? null)
const detectionConfirmed = computed(() => latestReport.value !== null)
const defenseExecuted = computed(() => latestReport.value?.action_result?.executed === true)
const executedDefenseAction = computed(() => defenseExecuted.value
  ? latestReport.value?.action_result?.request?.action ?? '已执行安全处置'
  : null)
const attackerIdentity = computed(() => plan.value?.attacker_node_id == null ? '—' : `External ${plan.value.attacker_node_id}`)
const originalIdentity = computed(() => plan.value?.parameters?.legitimate_source_id == null ? '—' : `Follower ${plan.value.parameters.legitimate_source_id}`)
const derivation = computed(() => {
  const records = runMatches.value ? store.packetAccounting?.causal_evidence?.derivations : null
  return records?.[records.length - 1] ?? null
})
const claimedIdentity = computed(() => plan.value?.parameters?.claimed_src_id == null ? '—' : Number(plan.value.parameters.claimed_src_id) === 0 ? 'GCS（ID 0）' : `Device ${plan.value.parameters.claimed_src_id}`)
const hmacMetadata = computed(() => runMatches.value ? store.runMetadata?.application_hmac ?? null : null)
const onlineHmacResult = computed(() => latestReport.value ? reportReason(latestReport.value) : null)
const reportTrend = computed(() => buildCumulativeReportSeries({
  reports: authReports.value,
  matchDetection: (report) => String(report.category || '').toUpperCase() === 'AUTH_FAILURE',
  matchExecutedAction: (report) => report.action_result?.executed === true,
}))
const labels = computed(() => reportTrend.value.map((point) => point.label))
const series = computed(() => [
  { name: 'AUTH_FAILURE 累计', color: '#d94857', area: true, step: 'end' as const, data: reportTrend.value.map((point) => point.detectedCount) },
  { name: '已执行 DROP_PACKET 累计', color: '#218a61', step: 'end' as const, data: reportTrend.value.map((point) => point.executedCount) },
])
</script>

<template>
  <div class="page-grid">
    <PageHeader eyebrow="Attack / Spoofing" title="报文伪装攻击" description="合法源先签名并发送；External 捕获副本，仅改声明源身份后发送。" detection-label="检测机制：HMAC 身份校验" protection-label="处置策略：拒绝非法报文" />
    <StageStepper :current="store.scenarioStage('SPOOFING')" />
    <section class="panel"><RunControls scenario="spoofing" /></section>
    <PacketStatistics family="SPOOFING" />
    <ScenarioContextNotice family="SPOOFING" page-label="报文伪装" />

    <section class="scenario-core">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景配置 / 仿真真值</span><h2 class="panel-title">身份伪装拓扑</h2></div></div>
        <ScenarioTopology mode="spoofing" :topology="runMatches ? store.topology : null" :attack-plan="plan" :reports="authReports" :primary-flow="store.primaryBusinessFlowFor('SPOOFING')" :run-state="store.status?.state" :capture="capture" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景机制 / 派生记录</span><h2 class="panel-title">合法原报文 → 攻击副本</h2></div><div class="enum-stack"><StatusBadge :label="humanizeAttackSubtype(plan?.attack_subtype || 'KNOWN_ID_CONFLICT')" :tone="plan ? 'info' : 'neutral'" /></div></div>
        <div class="identity-diff">
          <div><small>签名与发送原报文</small><strong>{{ originalIdentity }}</strong><span>{{ attackerIdentity }} 捕获真实发送副本，不掌握设备密钥</span></div>
          <b>仅修改 ID →</b>
          <div class="changed"><small>报文声明源身份</small><strong>{{ claimedIdentity }}</strong><span>claimed_src_id；无法生成与被冒充身份匹配的 K_device 标签</span></div>
        </div>
        <dl class="data-list">
          <div class="data-row"><dt>来源报文 ID</dt><dd>{{ derivation?.original.message_id || '—' }}</dd></div>
          <div class="data-row"><dt>派生副本 ID</dt><dd>{{ derivation?.copy.message_id || '—' }}</dd></div>
          <div class="data-row"><dt>业务内容</dt><dd>保持不变</dd></div>
          <div class="data-row"><dt>报文类型 / 序列号</dt><dd>保持不变</dd></div>
          <div class="data-row"><dt>生成时间</dt><dd>保持不变</dd></div>
          <div class="data-row"><dt>HMAC 标签</dt><dd>原标签保留（攻击机制）</dd></div>
          <div class="data-row"><dt>接收端实际证据</dt><dd>{{ latestReport ? reportReason(latestReport) : '—' }}</dd></div>
        </dl>
        <details data-testid="spoofing-details"><summary>伪装详情（{{ details.length }} 条）</summary>
          <div class="table-scroll"><table class="event-table evidence-table"><thead><tr><th>原报文 / 攻击副本</th><th>捕获 / 副本发送</th><th>身份 / 序号</th><th>在线校验</th><th>处置 / 执行状态</th></tr></thead><tbody>
            <tr v-for="item in details" :key="item.copy.message_id" class="causal-detail-row" :data-message-id="item.copy.message_id">
              <td><span :title="item.original.message_id">{{ shortId(item.original.message_id) }}</span><br /><span :title="item.copy.message_id">{{ shortId(item.copy.message_id) }}</span></td>
              <td>{{ formatNumber(item.capture_time_s,2) }} s<br />{{ item.transmission ? `${formatNumber(item.transmission.sent_time_s,2)} s` : '等待发送' }}</td>
              <td>{{ item.original.claimed_src_id }} → {{ item.copy.claimed_src_id }}<br />seq {{ item.copy.sequence_no }} · HMAC 不重算</td>
              <td><span class="evidence-code">{{ item.report ? reportReason(item.report) : '等待报告' }}</span></td>
              <td><span class="evidence-code">{{ item.report?.action_result?.request?.action || '—' }}</span><span class="evidence-execution">{{ item.report?.action_result?.executed === true ? '已执行' : item.report?.action_result?.executed === false ? '未执行' : '—' }}</span></td>
            </tr>
          </tbody></table></div>
        </details>
      </article>
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-online">在线 Runtime</span><h2 class="panel-title">检测与防御机制</h2></div></div>
        <div class="mechanism-flow"><div class="mechanism-node"><strong>合法报文 → 伪装副本</strong><span>只改源身份；原标签保留</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node" :class="{ danger: detectionConfirmed }"><strong>{{ latestReport ? humanizeSecurityResult(reportReason(latestReport)) : '等待在线检测证据' }}</strong><span>接收端身份与完整性校验</span></div><div class="mechanism-arrow">›</div><div class="mechanism-node" :class="{ success: defenseExecuted }"><strong>{{ executedDefenseAction === 'DROP_PACKET' ? '实际丢弃' : executedDefenseAction || '等待安全处置' }}</strong><span>实际安全处置</span></div></div>
        <TimeSeriesChart :labels="labels" :series="series" :height="225" />
      </article>
      <article class="panel"><div class="panel-header"><div><span class="source-label source-online">GCS 已接收</span><h2 class="panel-title">实时安全事件</h2></div></div><EventTable :reports="authReports" :node-roles="store.runMetadata?.node_roles" /></article>
    </section>
    <ApplicationHmacCard
      mode="spoofing"
      :metadata="hmacMetadata"
      :original-identity="originalIdentity"
      :claimed-identity="claimedIdentity"
      :online-result="onlineHmacResult"
      :action="latestReport?.action_result?.request?.action"
      :action-executed="latestReport?.action_result?.executed"
      :hmac-recomputed="false"
    />

    <AttackEvaluationPanel family="SPOOFING" />
  </div>
</template>

<style scoped>
.identity-diff { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 12px; margin-bottom: 13px; }.identity-diff > div { padding: 16px; border: 1px solid #dae3ed; border-radius: 11px; background: #f8fbff; }.identity-diff > div.changed { border-color: #efb7bf; background: #fff5f6; }.identity-diff small,.identity-diff strong,.identity-diff span { display: block; }.identity-diff small { color: #7c8b9f; font-size: 10px; }.identity-diff strong { margin: 7px 0; font-size: 17px; }.identity-diff span { color: #718096; font-size: 10px; line-height: 1.5; }.identity-diff > b { color: #d94857; font-size: 11px; }
.enum-stack { display: grid; justify-items: end; gap: 5px; }.enum-stack code { color: #8794a5; font-size: 10px; }
@media (max-width: 700px) { .identity-diff { grid-template-columns: 1fr; }.identity-diff > b { text-align: center; } }
</style>
