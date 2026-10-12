<script setup lang="ts">
import { computed, ref } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import PageHeader from '@/components/common/PageHeader.vue'
import StageStepper from '@/components/common/StageStepper.vue'
import RunControls from '@/components/common/RunControls.vue'
import PacketStatistics from '@/components/common/PacketStatistics.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import MetricCard from '@/components/common/MetricCard.vue'
import ScenarioContextNotice from '@/components/common/ScenarioContextNotice.vue'
import ScenarioTopology from '@/components/topology/ScenarioTopology.vue'
import { formatPercent } from '@/utils/runtimeFormat'
import { eavesProtectionPresentation } from '@/utils/evaluationPresentation'
import { eavesBusinessSets } from '@/utils/messageEvidence'

const store = useSimulationStore()
const truthView = ref(true)
const runMatches = computed(() => store.isRunFor('EAVESDROPPING'))
const plan = computed(() => runMatches.value ? store.runMetadata?.attack_plan?.find((item) => item.attack_family === 'EAVESDROPPING') ?? null : null)
const providers = computed(() => runMatches.value ? store.runMetadata?.security_providers : null)
const eaves = computed(() => runMatches.value && store.status?.state === 'COMPLETED' ? store.evaluation?.eavesdropping ?? null : null)
const probeProfile = computed(() => runMatches.value ? store.runMetadata?.probe_profile ?? null : null)
const encryptionConfigured = computed(() => runMatches.value && store.runMetadata?.run_config?.encrypt_sensitive === true)
const protectionState = computed(() => eavesProtectionPresentation(runMatches.value, store.status?.state, store.evaluationState, eaves.value?.protection_effective))
const protectionLabel = computed(() => protectionState.value.label)
const protectionTone = computed(() => protectionState.value.tone)
const withheldForKey = computed(() => runMatches.value ? eavesBusinessSets(store.packetAccounting)?.withheld.filter(item => item.reason === 'KEY_UNAVAILABLE').length ?? null : null)
</script>

<template>
  <div class="page-grid">
    <PageHeader eyebrow="Attack / Passive Eavesdropping" title="窃听攻击" description="攻击者被动监听合法无线通信，截获数据但不主动发送或修改报文。" eavesdropping detection-label="直接检测 N/A" :protection-label="protectionLabel" :protection-tone="protectionTone" />
    <StageStepper :current="store.scenarioStage('EAVESDROPPING')" eavesdropping />
    <section class="panel"><RunControls scenario="eavesdropping" /></section>
    <PacketStatistics family="EAVESDROPPING" />
    <ScenarioContextNotice family="EAVESDROPPING" page-label="窃听攻击" />

    <section class="scenario-core">
      <article class="panel">
        <div class="panel-header"><div><span class="source-label source-truth">场景设定</span><h2 class="panel-title">{{ truthView ? '被动窃听场景' : '正常业务通信' }}</h2></div><button class="btn btn-ghost" @click="truthView = !truthView">{{ truthView ? '仅查看正常通信' : '窃听场景' }}</button></div>
        <ScenarioTopology mode="eavesdropping" :topology="runMatches ? store.topology : null" :attack-plan="plan" :reports="[]" :primary-flow="store.primaryBusinessFlowFor('EAVESDROPPING')" :run-state="store.status?.state" :show-truth="truthView" :encrypted="encryptionConfigured" />
      </article>
      <article class="panel">
        <div class="panel-header"><div><span class="source-label">保密机制</span><h2 class="panel-title">敏感业务加密流程</h2></div></div>
        <div class="crypto-flow" data-testid="static-crypto-mechanism"><div><b>1</b><strong>信道信息获取</strong><span>CSI 探测</span></div><i>›</i><div><b>2</b><strong>共享密钥生成</strong><span>SKG</span></div><i>›</i><div><b>3</b><strong>会话密钥建立</strong><span>会话协商</span></div><i>›</i><div><b>4</b><strong>敏感业务加密</strong><span>AES-GCM</span></div></div>
        <details><summary>技术配置</summary><p>保密结果针对敏感业务；协议控制信息与链路元数据不在此范围。</p><p>探测配置：{{ probeProfile || '—' }}</p>
        <dl class="data-list">
          <div class="data-row"><dt>密钥服务</dt><dd>{{ providers?.key_provider?.name || '—' }}</dd></div>
          <div class="data-row"><dt>加密服务</dt><dd>{{ providers?.crypto_provider?.name || '—' }}</dd></div>
          <div class="data-row"><dt>敏感业务加密配置</dt><dd>{{ encryptionConfigured ? 'AES-GCM' : '—' }}</dd></div>
          <div class="data-row"><dt>Application HMAC</dt><dd>完整性认证，不提供保密性</dd></div>
        </dl>
        </details>
      </article>
    </section>

    <section class="panel">
      <div class="panel-header"><div><span class="source-label source-offline">离线评价</span><h2 class="panel-title">保密保护结果</h2></div><StatusBadge :label="eaves ? '评价已生成' : protectionLabel" :tone="eaves ? 'info' : 'neutral'" /></div>
      <div class="eaves-metrics">
        <MetricCard label="直接检测" value="N/A" note="纯被动监听不作直接检测率评价" tone="slate" icon="—" />
        <MetricCard label="密文保护数量" :value="eaves?.ciphertext_protected_count ?? '—'" :note="eaves ? '受 AES-GCM 保护的敏感传输' : protectionLabel" :tone="eaves ? 'blue' : 'slate'" icon="C" />
        <MetricCard label="明文暴露数量" :value="eaves?.sensitive_plaintext_exposure_count ?? '—'" :note="eaves ? '来自完成后的保密效果评价' : protectionLabel" :tone="typeof eaves?.sensitive_plaintext_exposure_count === 'number' ? eaves.sensitive_plaintext_exposure_count === 0 ? 'green' : 'red' : 'slate'" icon="P" />
        <MetricCard label="内容恢复数量" :value="eaves?.content_recovery_count ?? '—'" :note="eaves ? '攻击者成功恢复的内容数' : protectionLabel" :tone="typeof eaves?.content_recovery_count === 'number' ? eaves.content_recovery_count === 0 ? 'green' : 'red' : 'slate'" icon="R" />
        <MetricCard label="保密保护结果" :value="typeof eaves?.protection_effective === 'boolean' ? eaves.protection_effective ? '有效' : '未达到' : protectionLabel" :note="eaves ? '当前敏感业务保密评价' : protectionLabel" :tone="typeof eaves?.protection_effective === 'boolean' ? eaves.protection_effective ? 'green' : 'red' : 'slate'" icon="✓" />
        <MetricCard label="评价窗口解码接收成功率" :value="eaves ? formatPercent(eaves.legitimate_service_availability) : '—'" :note="eaves ? '成功接收事件 / 全部接收事件；不是生成业务交付率' : protectionLabel" :tone="eaves ? 'blue' : 'slate'" icon="S" />
      </div>
      <details v-if="eaves" data-testid="availability-scope"><summary>接收成功率统计范围</summary>
        <p>分子为评价窗口内 RX_SUCCESS 事件数；分母为 RX_SUCCESS + RX_FAILURE。窗口按窃听 episode 的 impact_start_s 至 end_s（含端点）；覆盖全部节点及跳数，包含业务和协议控制接收，不按消息去重，也不表示应用认证成功。</p>
        <p v-if="withheldForKey !== null" data-testid="key-withheld">密钥未就绪导致未发送业务：{{ withheldForKey }} 条。源端未发送记录不属于上述接收事件分母；100% 不代表全部生成业务已交付。</p>
      </details>
    </section>
  </div>
</template>

<style scoped>
  .profile-note { margin-top: 12px; color: #758399; font-size: 11px; }.crypto-flow { display: grid; grid-template-columns: minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr); align-items: center; gap: 5px; margin-bottom: 13px; padding: 5px 0 10px; }.crypto-flow > div { min-width: 0; padding: 12px 7px; border: 1px solid #dce5ee; border-radius: 10px; background: #f8fbff; text-align: center; }.crypto-flow b { display: grid; place-items: center; width: 22px; height: 22px; margin: 0 auto 7px; border-radius: 50%; color: white; background: #2c74d2; font-size: 10px; }.crypto-flow strong,.crypto-flow span { display: block; }.crypto-flow strong { font-size: 12px; }.crypto-flow span { margin-top: 5px; color: #7d8a9b; font-size: 10px; overflow-wrap: anywhere; }.crypto-flow > i { color: #a5b0bd; }.eaves-metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }.eaves-boundary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); align-content: start; gap: 10px; }.eaves-boundary .panel-header { grid-column: 1 / -1; }.view-card { padding: 15px; border: 1px solid; border-radius: 10px; }.view-card strong,.view-card span,.view-card b { display: block; }.view-card span { margin: 7px 0; font-size: 11px; line-height: 1.6; }.view-card b { font-size: 10px; }.view-card.online { border-color: #c9def7; color: #385f89; background: #f1f7ff; }.view-card.truth { border-color: #ebd49f; color: #76571f; background: #fff9ed; }
  @media (max-width: 900px) { .eaves-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 620px) { .eaves-metrics, .eaves-boundary { grid-template-columns: 1fr; }.eaves-boundary .panel-header { grid-column: auto; } }
</style>
