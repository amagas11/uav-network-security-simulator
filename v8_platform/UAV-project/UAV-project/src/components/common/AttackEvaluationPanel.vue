<script setup lang="ts">
import { computed } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import { displayValue, formatDuration, formatPercent, humanizeDefensePolicy } from '@/utils/runtimeFormat'
import StatusBadge from './StatusBadge.vue'

const props = defineProps<{ family: string; eavesdropping?: boolean; actionCountNote?: string }>()
const store = useSimulationStore()
const runMatches = computed(() => store.isRunFor(props.family))
const familyMetrics = computed(() => store.familyMetricsFor(props.family))
const episode = computed(() => store.episodeForFamily(props.family))
const eaves = computed(() => runMatches.value ? store.evaluation?.eavesdropping ?? null : null)
const dosTarget = computed(() => runMatches.value && props.family === 'DOS' ? store.evaluation?.dos_target_receiver_evaluation ?? null : null)
const defenseEffectiveDisplay = computed(() => {
  if (props.family === 'DOS' && episode.value?.defense_evidence?.legitimate_harm_available !== true) return '—'
  return episode.value?.defense_effective === true ? '是' : episode.value?.defense_effective === false ? '否' : '—'
})
</script>

<template>
  <section class="panel evaluation-panel">
    <div class="panel-header"><div><span class="source-label source-offline">离线评价</span><h2 class="panel-title">效果评估</h2></div><StatusBadge v-if="store.evaluation && runMatches" label="已生成" tone="info" /></div>
    <div v-if="store.runMetadata && !runMatches" class="empty-state"><div><strong>当前运行不属于 {{ props.family }}</strong>评价按场景隔离。</div></div>
    <div v-else-if="!store.evaluation" class="empty-state"><div><strong>{{ runMatches && store.status?.state === 'COMPLETED' ? store.evaluationState === 'ERROR' ? '离线评价暂不可用' : '等待离线评价' : '仿真结束后生成' }}</strong>{{ runMatches && store.evaluationError ? store.evaluationError : '等待实际结果。' }}</div></div>
    <div v-else-if="eavesdropping && eaves" class="evaluation-grid">
      <div class="evaluation-item"><span>直接检测率</span><strong>N/A</strong></div>
      <div class="evaluation-item"><span>密文保护数</span><strong>{{ eaves.ciphertext_protected_count }}</strong></div>
      <div class="evaluation-item"><span>敏感明文暴露</span><strong>{{ eaves.sensitive_plaintext_exposure_count }}</strong></div>
      <div class="evaluation-item"><span>内容恢复数</span><strong>{{ eaves.content_recovery_count }}</strong></div>
      <div class="evaluation-item"><span>保密防护有效</span><strong>{{ eaves.protection_effective === true ? '是' : eaves.protection_effective === false ? '否' : '—' }}</strong></div>
      <div class="evaluation-item" title="窃听评价窗口内全部节点 RX_SUCCESS / (RX_SUCCESS + RX_FAILURE)，按接收事件计数，不含源端未发送业务。"><span>评价窗口解码接收成功率</span><strong>{{ formatPercent(eaves.legitimate_service_availability) }}</strong></div>
    </div>
    <div v-else-if="dosTarget?.applicable" class="evaluation-grid" data-testid="dos-target-evaluation">
      <div class="evaluation-item"><span>攻击目标接收端检出率</span><strong>{{ formatPercent(dosTarget.recall_pd) }}</strong></div>
      <div class="evaluation-item" title="完整目标节点正常窗口须有真实解码到达，并避开攻击及接收窗口尾部；没有足够窗口时不评价误报率。"><span>目标正常窗口误报率</span><strong>{{ dosTarget.pfa_fpr === null ? 'N/A' : formatPercent(dosTarget.pfa_fpr) }}</strong></div>
      <div class="evaluation-item"><span>目标正常观察窗口</span><strong>{{ dosTarget.normal_window_count }}</strong></div>
      <div class="evaluation-item"><span>目标接收端告警</span><strong>{{ dosTarget.target_alarm_count }}</strong></div>
      <div class="evaluation-item"><span>目标平均检测延迟</span><strong>{{ formatDuration(dosTarget.mean_detection_delay_s) }}</strong></div>
      <div class="evaluation-item"><span>当前 Episode 防御有效</span><strong>{{ defenseEffectiveDisplay }}</strong></div>
    </div>
    <div v-else-if="familyMetrics" class="evaluation-grid">
      <div class="evaluation-item"><span>攻击 Episode 检出率 (Recall/Pd)</span><strong>{{ formatPercent(familyMetrics.recall_pd) }}</strong></div>
      <div class="evaluation-item"><span>正常窗口误报率 (PFA/FPR)</span><strong>{{ formatPercent(familyMetrics.pfa_fpr) }}</strong></div>
      <div class="evaluation-item"><span>当前 Episode 防御有效</span><strong>{{ defenseEffectiveDisplay }}</strong></div>
      <div class="evaluation-item"><span>当前攻击族告警总数</span><strong>{{ familyMetrics.alarm_count }}</strong></div>
      <div class="evaluation-item"><span>平均 Episode 检测延迟</span><strong>{{ formatDuration(familyMetrics.mean_detection_delay_s) }}</strong></div>
      <div class="evaluation-item action-count"><span>攻击 Episode 防御动作数</span><strong>{{ displayValue(episode?.executed_defense_count) }}</strong><small>{{ actionCountNote || '仅统计与当前攻击 episode 匹配的已执行动作。' }}</small></div>
    </div>
    <div v-else-if="store.evaluation?.detector_applicability?.[props.family]?.applicable === false" class="empty-state"><div><strong>检测评价 N/A</strong>本轮未启用此专项检测，不评价检出率或误报率。</div></div>
    <div v-else class="empty-state"><div><strong>无对应攻击 episode</strong>当前运行没有此类攻击评价记录。</div></div>
    <details v-if="dosTarget && familyMetrics" class="episode-policy" data-testid="dos-network-evaluation"><summary>全网告警与原评价</summary><dl class="data-list"><div class="data-row"><dt>全网 DOS 告警</dt><dd>{{ familyMetrics.alarm_count }}</dd></div><div class="data-row"><dt>非目标节点告警</dt><dd>{{ dosTarget.non_target_alarm_count }}</dd></div><div class="data-row"><dt>全网 TP / FP / FN / TN</dt><dd>{{ familyMetrics.TP }} / {{ familyMetrics.FP }} / {{ familyMetrics.FN }} / {{ familyMetrics.TN }}</dd></div><div class="data-row"><dt>全网正常判决误报率</dt><dd>{{ formatPercent(familyMetrics.pfa_fpr) }}</dd></div><div class="data-row"><dt>目标 TP / FP / FN / TN</dt><dd>{{ dosTarget.TP }} / {{ dosTarget.FP }} / {{ dosTarget.FN }} / {{ dosTarget.TN }}</dd></div></dl></details>
    <dl v-if="episode" class="data-list episode-policy"><div class="data-row"><dt>防御策略</dt><dd>{{ humanizeDefensePolicy(episode.defense_policy) }}</dd></div><div class="data-row"><dt>动作延迟</dt><dd>{{ formatDuration(episode.action_delay_s) }}</dd></div><div class="data-row"><dt>报告延迟</dt><dd>{{ formatDuration(episode.report_delay_s) }}</dd></div><div class="data-row"><dt>匹配的已执行动作</dt><dd>{{ displayValue(episode.executed_defense_count) }}</dd></div></dl>
  </section>
</template>

<style scoped>
.panel-header .panel-title { margin-top: 10px; }.episode-policy { margin-top: 15px; padding-top: 5px; border-top: 1px solid #edf1f5; }
.action-count small { display: block; max-width: 230px; margin-top: 5px; color: #8592a3; font-size: 10px; line-height: 1.4; }
.technical-policy { display: block; margin-top: 4px; overflow-wrap: anywhere; color: #8592a3; font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }
</style>
