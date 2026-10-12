<script setup lang="ts">
import { computed } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import { eavesBusinessSets } from '@/utils/messageEvidence'
import ReportScopeSummary from './ReportScopeSummary.vue'
const props = defineProps<{ family: string }>()
const store = useSimulationStore()
const view = computed(() => store.isRunFor(props.family) ? store.packetAccounting : null)
const attack = computed(() => view.value?.attacks.find(item => item.family === props.family))
const eavesSets = computed(() => props.family === 'EAVESDROPPING' ? eavesBusinessSets(view.value) : null)
const labels: Record<string, string> = {
  SPOOFING: '伪装副本已发送', FDI: '篡改副本已发送', DOS: '洪泛报文已发送',
  EAVESDROPPING: 'Eve 捕获总帧', REPLAY: '重放帧已发送（单次）',
}
const fields = computed(() => [
  ['仿真时长（s）', view.value?.simulation_duration_s, 'simulation_duration_s'],
  ['业务报文已生成', view.value?.business.generated_business_count, 'generated_business_count'],
  ['源业务报文已发送', view.value?.business.origin_business_sent_count, 'origin_business_sent_count'],
  [props.family === 'EAVESDROPPING' ? '捕获敏感业务密文帧' : '合法业务目标解码', props.family === 'EAVESDROPPING' ? attack.value?.counts.captured_sensitive_ciphertext_count : view.value?.business.target_business_received_count, props.family === 'EAVESDROPPING' ? 'captured_sensitive_ciphertext_count' : 'target_business_received_count'],
  [labels[props.family], attack.value?.counts[props.family === 'EAVESDROPPING' ? 'captured_frame_count' : 'sent_attack_count'], props.family === 'EAVESDROPPING' ? 'captured_frame_count' : 'sent_attack_count'],
  [props.family === 'EAVESDROPPING' ? '捕获协议控制明文' : '目标检测报告', props.family === 'EAVESDROPPING' ? attack.value?.counts.captured_protocol_control_plaintext_count : (props.family === 'DOS' ? attack.value?.counts.target_dos_alarm_count : attack.value?.counts.detected_report_count), props.family === 'EAVESDROPPING' ? 'captured_protocol_control_plaintext_count' : props.family === 'DOS' ? 'target_dos_alarm_count' : 'detected_report_count'],
  [props.family === 'EAVESDROPPING' ? '敏感明文暴露' : '已执行丢弃', props.family === 'EAVESDROPPING' ? attack.value?.counts.plaintext_exposure_count : attack.value?.counts.executed_drop_count, props.family === 'EAVESDROPPING' ? 'plaintext_exposure_count' : 'executed_drop_count'],
])
</script>
<template>
  <section class="panel packet-statistics" :data-family="family">
    <div class="packet-heading"><h2 class="panel-title">通信与攻击报文统计</h2><span class="source-label source-truth">运行统计</span></div>
    <div class="packet-grid"><div v-for="[label,value,key] in fields" :key="String(key)" :data-counter="key"><span>{{ label }}</span><strong>{{ value ?? '—' }}</strong></div></div>
    <ReportScopeSummary v-if="view && family !== 'DOS' && store.securityReports.some(report => report.category === 'DOS')" :reports="store.securityReports" cross-category />
    <details v-if="view && attack"><summary>计数详情</summary>
      <p>业务按源消息计数，捕获按传输帧计数。解码到达不等于认证通过；生成与捕获属于仿真统计，检测与处置来自接收端执行。</p>
      <div>业务计划：{{ view.business.planned_business_count }}</div>
      <dl><div><dt>源端初始未篡改版本已发送</dt><dd>{{ view.business.unmodified_business_sent_count }}</dd></div><div><dt>攻击有效时长（s）</dt><dd>{{ attack.attack_duration_s }}</dd></div>
      <div v-if="family !== 'EAVESDROPPING'"><dt>攻击尝试 / 条件命中</dt><dd>{{ family === 'FDI' ? attack.counts.eligible_count : attack.counts.attempt_count }}</dd></div>
      <div v-if="family === 'SPOOFING' || family === 'DOS'"><dt>攻击报文已生成</dt><dd>{{ attack.counts.generated_attack_count }}</dd></div>
      <div v-if="family === 'FDI'"><dt>攻击副本业务内容已修改</dt><dd>{{ attack.counts.modified_count }}</dd></div>
      <div v-if="family !== 'EAVESDROPPING'"><dt>攻击帧目标解码到达</dt><dd>{{ attack.counts.target_received_count }}</dd></div>
      <div v-if="family === 'DOS'"><dt>洪泛计划 / 配置pps</dt><dd>{{ attack.counts.planned_attack_count }} / {{ attack.configured_rate_pps }}</dd></div>
      <div v-if="family === 'DOS'"><dt>次生DOS告警</dt><dd>{{ attack.counts.secondary_dos_alarm_count }}</dd></div>
      <div v-if="family === 'REPLAY' || family === 'FDI'"><dt>已捕获合法报文</dt><dd>{{ attack.counts.captured_frame_count }}</dd></div>
      <div v-if="family === 'SPOOFING'"><dt>捕获合法原帧</dt><dd>{{ attack.counts.captured_frame_count }}</dd></div>
      <template v-if="family === 'EAVESDROPPING'"><div><dt>主动攻击发送</dt><dd>{{ attack.counts.sent_attack_count }}</dd></div><div><dt>敏感内容恢复</dt><dd>{{ attack.counts.content_recovery_count }}</dd></div><div><dt>直接检测</dt><dd>N/A</dd></div></template>
      <template v-if="family === 'EAVESDROPPING'"><div v-for="[key,label] in [['captured_sensitive_ciphertext_count','敏感密文'],['captured_sensitive_plaintext_count','敏感明文'],['captured_nonsensitive_ciphertext_count','非敏感密文'],['captured_nonsensitive_plaintext_count','非敏感明文']]" :key="key"><dt>{{ label }}</dt><dd :data-counter="key">{{ attack.counts[key!] }}</dd></div></template>
      </dl>
      <div v-if="eavesSets" class="set-relations">
        <p>业务生成 {{ eavesSets.generated.size }} 条；源端首跳发送 {{ eavesSets.sent.size }} 条。Eve 捕获总帧包含业务和控制帧，不等同于源业务发送集合。</p>
        <p>Eve 捕获 {{ attack.counts.captured_frame_count }} 帧，其中敏感业务密文 {{ attack.counts.captured_sensitive_ciphertext_count }} 帧、协议控制明文 {{ attack.counts.captured_protocol_control_plaintext_count }} 帧；敏感明文暴露 {{ attack.counts.plaintext_exposure_count }} 帧。这是实际捕获分类，不是全部源发送量。</p>
        <div>生成但未发送（{{ eavesSets.withheld.length }} 条）<ul><li v-for="item in eavesSets.withheld" :key="item.id">{{ item.id }} · {{ item.reason }}</li></ul></div>
        <div>已发送但未捕获为敏感密文（{{ eavesSets.sentNotCaptured.length }} 条）<ul><li v-for="id in eavesSets.sentNotCaptured" :key="id">{{ id }}</li></ul></div>
        <div>协议控制明文来源<ul><li v-for="frame in eavesSets.controlFrames" :key="frame.frame_emission_id">{{ frame.message_id }} · {{ frame.sender_id }} → {{ frame.receiver_id }} · SKG_CONTROL · 不属于源业务集合</li></ul></div>
      </div>
    </details>
  </section>
</template>
<style scoped>
.packet-heading { display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;flex-wrap:wrap; }
.packet-grid { display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:10px; }
.packet-grid > div { padding:10px;border-radius:8px;background:#f3f7fc;min-width:0; }
.packet-grid span { display:block;color:#6b7d94;font-size:12px;overflow-wrap:anywhere; }
.packet-grid strong { display:block;color:#244d80;font-size:22px;margin-top:5px; }
details { margin-top:10px;color:#6b7d94;font-size:12px; }
dl { display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px; }
dl > div { display:flex;justify-content:space-between;gap:8px; }dd { margin:0;color:#244d80; }
@media(max-width:1100px){.packet-grid { grid-template-columns:repeat(4,minmax(0,1fr)); }}
@media(max-width:700px){.packet-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }dl { grid-template-columns:1fr; }}
</style>
