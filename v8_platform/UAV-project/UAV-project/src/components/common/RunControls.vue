<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useSimulationStore } from '@/stores/simulation'
import { SCENARIOS, DEFAULT_DURATION_S, buildScenarioRequest, type ScenarioKey, type ScenarioLaunchOptions } from '@/config/scenarios'

const props = withDefaults(defineProps<{
  scenario: ScenarioKey
  options?: ScenarioLaunchOptions
  launchLabel?: string
}>(), { options: () => ({}), launchLabel: '启动攻击' })

const store = useSimulationStore()
const simulationDurationS = ref(DEFAULT_DURATION_S[props.scenario])
let hydratedRunId: string | null = null
watch(() => store.runMetadata, (metadata) => {
  if (!metadata?.run_id || hydratedRunId === metadata.run_id || !store.isRunFor(SCENARIOS[props.scenario].family ?? 'BASELINE')) return
  const value = metadata.run_config?.duration_s
  if (typeof value === 'number') simulationDurationS.value = value
  hydratedRunId = metadata.run_id
}, { immediate: true })
const launchOptions = computed(() => ({ ...props.options, simulationDurationS: simulationDurationS.value }))
const validationError = computed(() => {
  try { buildScenarioRequest(props.scenario, launchOptions.value); return '' }
  catch (cause) { return cause instanceof Error ? cause.message : '参数无效' }
})
const pauseText = computed(() => store.isPaused ? '继续' : '暂停')
const scenario = computed(() => SCENARIOS[props.scenario])
const pageFamily = computed(() => scenario.value.family)
const isGlobalControl = computed(() => props.scenario === 'overview')
const ownsActiveRun = computed(() => isGlobalControl.value
  || Boolean(pageFamily.value && store.isRunFor(pageFamily.value)))
const requestedScenarioIsActive = computed(() => {
  if (!store.runMetadata) return false
  return pageFamily.value === null
    ? store.activeRunFamily === null
    : store.isRunFor(pageFamily.value)
})
const lifecycleLocksLaunch = computed(() => requestedScenarioIsActive.value
  && ['INITIALIZED', 'RUNNING', 'PAUSED'].includes(store.status?.state ?? ''))
const canPauseOrResume = computed(() => ownsActiveRun.value && (store.isRunning || store.isPaused))
const canReset = computed(() => ownsActiveRun.value && store.runAvailable)
const activeRunText = computed(() => store.runMetadata
  ? `${store.activeRunLabel || '基础通信'} · ${({INITIALIZED:'等待启动',RUNNING:'运行中',PAUSED:'已暂停',COMPLETED:'已完成',STOPPED:'已停止'} as Record<string,string>)[store.status?.state ?? ''] || '未知状态'}`
  : '无')
const launchText = computed(() => {
  if (store.runMetadata && !requestedScenarioIsActive.value) return '切换并启动本场景'
  if (requestedScenarioIsActive.value && ['COMPLETED', 'STOPPED'].includes(store.status?.state ?? '')) return '重新运行本场景'
  return props.launchLabel
})
const progressText = computed(() => store.status
  ? `${store.status.sim_time_s.toFixed(1)} / ${store.status.duration_s.toFixed(1)} s`
  : '— / — s')

async function launch() {
  if (store.runMetadata && !requestedScenarioIsActive.value) {
    const accepted = window.confirm(
      `当前活动运行为“${store.activeRunLabel || '基础通信'}”。\n启动“${scenario.value.shortTitle}”将替换当前运行，是否继续？`,
    )
    if (!accepted) return
  }
  if (!validationError.value) await store.launchScenario(props.scenario, launchOptions.value)
}
</script>

<template>
  <div class="run-controls-shell">
    <div v-if="scenario.family" class="duration-controls">
      <label>下一次仿真时长（s）<input v-model.number="simulationDurationS" data-testid="simulation-duration" type="number" :min="DEFAULT_DURATION_S[props.scenario]" max="30" :step="props.scenario === 'eavesdropping' ? 0.1 : 0.2" /></label>
      <button v-for="value in [DEFAULT_DURATION_S[props.scenario], 5, 10, 20, 30]" :key="value" class="btn btn-ghost" type="button" @click="simulationDurationS = value">{{ value }}s</button>
      <small v-if="ownsActiveRun && store.status">当前 {{ store.status.duration_s }}s</small>
    </div>
    <div v-if="validationError" class="input-error" role="alert">{{ validationError }}</div>
    <div class="run-context" :class="{ mismatch: store.runMetadata && !ownsActiveRun && !isGlobalControl }">
      <span>当前运行</span><strong>{{ activeRunText }}</strong>
      <small v-if="store.runMetadata && !ownsActiveRun && !isGlobalControl">本页不会暂停或重置其他场景</small>
      <details v-if="store.runMetadata && ownsActiveRun" class="detection-config" data-testid="detection-configuration"><summary>本轮检测配置</summary>基础安全：HMAC 认证、报文新鲜度与重放校验。洪泛专项告警：{{ store.runMetadata.run_config?.flooding_detection_enabled === false ? '未启用（检测评价 N/A）' : '已启用' }}。接收速率观测独立保留。</details>
    </div>
    <div class="run-controls">
    <button class="btn" :class="isGlobalControl ? 'btn-primary' : 'btn-danger'" :disabled="store.loading || lifecycleLocksLaunch || Boolean(validationError)" @click="launch">{{ launchText }}</button>
    <button class="btn" :disabled="store.loading || !canPauseOrResume" @click="store.pauseOrResume">{{ pauseText }}</button>
    <button class="btn" :disabled="store.loading || !canReset" @click="store.resetCurrentRun">重置</button>
    <button v-if="store.status?.state === 'INITIALIZED' && ownsActiveRun" class="btn btn-ghost" :disabled="store.loading" @click="store.startCurrentRun">启动当前运行</button>
    <div class="control-progress"><span>{{ progressText }}</span><div class="progress-track"><i :style="{ width: `${store.progress}%` }"></i></div></div>
    </div>
  </div>
</template>

<style scoped>
.run-controls-shell { display: grid; gap: 6px; width: 100%; }
.detection-config { margin-left:auto; max-width:650px; font-size:11px; line-height:1.6; }
.duration-controls { display:flex; align-items:center; flex-wrap:wrap; gap:6px; font-size:12px; }.duration-controls label { display:flex; align-items:center; gap:8px; }.duration-controls input { width:78px; padding:6px; border:1px solid #dce3eb; border-radius:6px; }.duration-controls .btn { padding:5px 8px; }.input-error { color:#b63c49; font-size:12px; }
.run-context { display: flex; align-items: center; gap: 8px; min-height: 23px; color: #758399; font-size: 10px; }
.run-context strong { color: #34475d; font-size: 11px; }
.run-context small { margin-left: auto; color: #9b6b18; }
.run-context.mismatch { padding-bottom: 8px; border-bottom: 1px solid #edf1f5; }
.run-controls { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; }
.control-progress { min-width: 190px; margin-left: auto; color: #748398; font-size: 11px; text-align: right; }
.control-progress .progress-track { margin-top: 7px; }
@media (max-width: 760px) { .control-progress { width: 100%; margin-left: 0; text-align: left; }.run-context { align-items: flex-start; flex-wrap: wrap; }.run-context small { width: 100%; margin-left: 0; } }
</style>
