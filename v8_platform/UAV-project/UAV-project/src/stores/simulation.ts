import { computed, ref } from 'vue'
import { eavesStageFromEvidence } from '@/utils/eavesStage'
import { defineStore } from 'pinia'

import {
  ApiError,
  createRun,
  getCurrentRun,
  getEvaluation,
  getHealth,
  getRuntime,
  pauseRun,
  resetRun,
  resumeRun,
  startRun,
  stopRun,
  type CreateRunRequest,
  type EvaluationEpisode,
  type EvaluationFamilyMetrics,
  type EvaluationView,
  type OnlineEvent,
  type PacketAccounting,
  type ReceiverRateObservations,
  type RunMetadata,
  type RunStatus,
  type RuntimeMetrics,
  type ScenarioTopology,
  type SecurityReport,
} from '@/api'
import {
  buildScenarioRequest,
  SCENARIOS,
  type ScenarioKey,
  type ScenarioLaunchOptions,
} from '@/config/scenarios'
import {
  resolvePrimaryBusinessFlow,
  type PrimaryBusinessFlow,
} from '@/config/topologySemantics'
import { friendlyError } from '@/utils/runtimeFormat'
import {
  accumulateRuntimeEvents,
  createRuntimeCumulativeCounters,
  type RuntimeCumulativeCounters,
} from '@/utils/runtimeCounters'

export interface RuntimeHistoryPoint {
  simTimeS: number
  throughputMbps: number | null
  latencyMs: number | null
  deliveryRate: number | null
  packetRatePps: number | null
  securityReportCount: number
}

export interface DosAlarmHistoryPoint {
  reportKey: string
  simTimeS: number
  packetRatePps: number
  thresholdPps: number | null
  windowS: number | null
}

export type RuntimeConnectionState = 'UNKNOWN' | 'CONNECTED' | 'DISCONNECTED'

const familyToScenario: Record<string, ScenarioKey> = {
  SPOOFING: 'spoofing',
  FDI: 'fdi',
  DOS: 'dos',
  EAVESDROPPING: 'eavesdropping',
  REPLAY: 'replay',
}

export const useSimulationStore = defineStore('simulation', () => {
  const status = ref<RunStatus | null>(null)
  const runMetadata = ref<RunMetadata | null>(null)
  const events = ref<OnlineEvent[]>([])
  const securityReports = ref<SecurityReport[]>([])
  const metrics = ref<RuntimeMetrics>({})
  const packetAccounting = ref<PacketAccounting | null>(null)
  const receiverRateObservations = ref<ReceiverRateObservations | null>(null)
  const evaluation = ref<EvaluationView | null>(null)
  const evaluationState = ref<'IDLE' | 'PENDING' | 'ERROR' | 'READY'>('IDLE')
  const evaluationError = ref('')
  const topology = ref<ScenarioTopology | null>(null)
  const history = ref<RuntimeHistoryPoint[]>([])
  const dosAlarmHistory = ref<DosAlarmHistoryPoint[]>([])
  const cumulativeCounters = ref<RuntimeCumulativeCounters>(createRuntimeCumulativeCounters())
  const cursor = ref(0)
  const loading = ref(false)
  const error = ref('')
  const currentScenarioKey = ref<ScenarioKey>('overview')
  const currentRequest = ref<CreateRunRequest | null>(null)
  const initialized = ref(false)
  const runtimeConnectionState = ref<RuntimeConnectionState>('UNKNOWN')

  let timer: ReturnType<typeof setInterval> | null = null
  let pollInFlight = false
  let consecutiveConnectionFailures = 0
  let trackedRunId: string | null = null
  let historyRunId: string | null = null
  let nextEvaluationAttemptAt = 0
  const seenDosReportKeys = new Set<string>()
  const processedEventIds = new Set<string>()
  const METRIC_HISTORY_PREFIX = 'uav-sim-v21:runtime-metric-history:'

  function markRuntimeConnected() {
    consecutiveConnectionFailures = 0
    runtimeConnectionState.value = 'CONNECTED'
  }

  async function recordConnectionFailure(cause: unknown) {
    // Vite's development/preview proxy can turn an upstream connection
    // refusal into an ordinary HTTP 500.  Probe the explicit health endpoint
    // before deciding that any HTTP response proves backend reachability.
    // This also keeps application-level 409/422/500 responses CONNECTED.
    try {
      await getHealth()
      markRuntimeConnected()
      return
    } catch {
      // The service health probe failed as well: count a transport/backend
      // failure, with two consecutive failures preventing status flicker.
    }
    consecutiveConnectionFailures += 1
    if (consecutiveConnectionFailures >= 2) runtimeConnectionState.value = 'DISCONNECTED'
  }

  const currentScenario = computed(() => SCENARIOS[currentScenarioKey.value])
  const progress = computed(() => {
    if (!status.value?.duration_s) return 0
    return Math.min(100, Math.max(0, status.value.sim_time_s / status.value.duration_s * 100))
  })
  const executedDefenseCount = computed(() => securityReports.value.filter((report) => report.action_result?.executed === true).length)
  const activeRunFamilies = computed(() => Array.from(new Set(
    (runMetadata.value?.attack_plan ?? [])
      .map((item) => String(item.attack_family || '').toUpperCase())
      .filter(Boolean),
  )))
  const activeRunFamily = computed(() => activeRunFamilies.value[0] ?? null)
  const activeRunLabel = computed(() => {
    const family = activeRunFamily.value
    if (!family) return runMetadata.value ? '基础通信' : null
    const scenarioKey = familyToScenario[family]
    return scenarioKey ? SCENARIOS[scenarioKey].shortTitle : family
  })

  function isRunFor(family: string): boolean {
    return activeRunFamilies.value.includes(family.toUpperCase())
  }

  function attackPlanFor(family: string) {
    const normalized = family.toUpperCase()
    return runMetadata.value?.attack_plan?.find(
      (item) => String(item.attack_family || '').toUpperCase() === normalized,
    ) ?? null
  }

  function targetNodeForFamily(family: string): number | null {
    const value = attackPlanFor(family)?.target_node_ids?.[0]
    return typeof value === 'number' && Number.isFinite(value) ? value : null
  }

  function primaryBusinessFlowFor(family: string): PrimaryBusinessFlow | null {
    if (!isRunFor(family)) return null
    return resolvePrimaryBusinessFlow(runMetadata.value?.run_config?.traffic_specs)
  }

  function reportsForFamily(family: string): SecurityReport[] {
    const normalized = family.toUpperCase()
    if (!isRunFor(normalized)) return []
    const categories: Record<string, string[]> = {
      SPOOFING: ['AUTH_FAILURE'],
      FDI: ['AUTH_FAILURE'],
      DOS: ['DOS', 'AUTH_FAILURE'],
      REPLAY: ['REPLAY'],
      EAVESDROPPING: [],
    }
    const accepted = categories[normalized] ?? [normalized]
    return securityReports.value.filter((report) => accepted.includes(String(report.category || '').toUpperCase()))
  }

  function familyMetricsFor(family: string): EvaluationFamilyMetrics | null {
    if (!isRunFor(family) || !evaluation.value) return null
    if (evaluation.value.detector_applicability?.[family.toUpperCase()]?.applicable === false) return null
    return evaluation.value.per_attack_family[family.toUpperCase()] ?? null
  }

  function episodeForFamily(family: string): EvaluationEpisode | null {
    if (!isRunFor(family) || !evaluation.value) return null
    return evaluation.value.episodes.find((episode) => episode.attack_family === family.toUpperCase()) ?? null
  }

  function scenarioStage(family: string): number {
    const normalized = family.toUpperCase()
    if (!isRunFor(normalized) || !status.value || status.value.state === 'INITIALIZED') return 0
    if (status.value?.state === 'COMPLETED' && evaluation.value) return 4

    if (normalized === 'EAVESDROPPING') {
      const running = status.value !== null
        && ['RUNNING', 'PAUSED', 'STOPPED', 'COMPLETED'].includes(status.value.state)
      if (!running) return 0
      return eavesStageFromEvidence(status.value.state, packetAccounting.value, Boolean(evaluation.value))
    }

    const reports = reportsForFamily(normalized)
    if (reports.some((report) => report.action_result?.executed === true)) return 3
    if (reports.length > 0) return 2
    return 1
  }

  const familyMetrics = computed(() => activeRunFamily.value ? familyMetricsFor(activeRunFamily.value) : null)
  const currentEpisode = computed(() => activeRunFamily.value ? episodeForFamily(activeRunFamily.value) : null)
  const stage = computed(() => activeRunFamily.value ? scenarioStage(activeRunFamily.value) : 0)
  const runAvailable = computed(() => status.value !== null)
  const isRunning = computed(() => status.value?.state === 'RUNNING')
  const isPaused = computed(() => status.value?.state === 'PAUSED')
  const acceptedTotal = computed(() => cumulativeCounters.value.acceptedTotal)
  const gcsLocalHmacRejectedTotal = computed(() => cumulativeCounters.value.gcsLocalHmacRejectedTotal)
  const gcsLocalReplayRejectedTotal = computed(() => cumulativeCounters.value.gcsLocalReplayRejectedTotal)

  function metricHistoryKey(runId: string): string {
    return `${METRIC_HISTORY_PREFIX}${runId}`
  }

  function readStoredMetricHistory(runId: string): RuntimeHistoryPoint[] {
    if (typeof sessionStorage === 'undefined') return []
    try {
      const raw = sessionStorage.getItem(metricHistoryKey(runId))
      if (!raw) return []
      const parsed = JSON.parse(raw) as unknown
      if (!Array.isArray(parsed)) return []
      return parsed.filter((point): point is RuntimeHistoryPoint => {
        if (!point || typeof point !== 'object') return false
        return typeof (point as RuntimeHistoryPoint).simTimeS === 'number'
      }).slice(-160)
    } catch {
      return []
    }
  }

  function persistMetricHistory() {
    if (!historyRunId || typeof sessionStorage === 'undefined') return
    try {
      sessionStorage.setItem(metricHistoryKey(historyRunId), JSON.stringify(history.value.slice(-160)))
    } catch {
      // Storage may be unavailable or full; the online Runtime remains usable.
    }
  }

  function removeStoredMetricHistory(runId: string | null | undefined) {
    if (!runId || typeof sessionStorage === 'undefined') return
    try {
      sessionStorage.removeItem(metricHistoryKey(runId))
    } catch {
      // A storage failure must not block reset.
    }
  }

  function resetRunCollections() {
    events.value = []
    securityReports.value = []
    metrics.value = {}
    packetAccounting.value = null
    receiverRateObservations.value = null
    evaluation.value = null
    evaluationState.value = 'IDLE'
    evaluationError.value = ''
    nextEvaluationAttemptAt = 0
    history.value = []
    dosAlarmHistory.value = []
    cumulativeCounters.value = createRuntimeCumulativeCounters()
    processedEventIds.clear()
    seenDosReportKeys.clear()
    cursor.value = 0
  }

  function clearRunData(options: { removeStoredHistoryForRunId?: string | null } = {}) {
    removeStoredMetricHistory(options.removeStoredHistoryForRunId)
    resetRunCollections()
    trackedRunId = null
    historyRunId = null
    runMetadata.value = null
    topology.value = null
  }

  function prepareRun(runId: string) {
    if (trackedRunId === runId) return
    resetRunCollections()
    trackedRunId = runId
    historyRunId = runId
    history.value = readStoredMetricHistory(runId)
  }

  function appendRuntimeEvents(incoming: OnlineEvent[]) {
    const incomingIds = new Set<string>()
    const unseen = incoming.filter((event) => {
      if (!event.event_id || processedEventIds.has(event.event_id) || incomingIds.has(event.event_id)) return false
      incomingIds.add(event.event_id)
      return true
    })
    cumulativeCounters.value = accumulateRuntimeEvents(
      cumulativeCounters.value,
      incoming,
      processedEventIds,
    )
    events.value = [...events.value, ...unseen].slice(-600)
  }

  function appendHistory() {
    if (!status.value) return
    const point: RuntimeHistoryPoint = {
      simTimeS: status.value.sim_time_s,
      throughputMbps: typeof metrics.value.mean_throughput_mbps === 'number' ? metrics.value.mean_throughput_mbps : null,
      latencyMs: typeof metrics.value.mean_latency_ms === 'number' ? metrics.value.mean_latency_ms : null,
      deliveryRate: typeof metrics.value.delivery_rate === 'number' ? metrics.value.delivery_rate : null,
      packetRatePps: null,
      securityReportCount: securityReports.value.length,
    }
    const previous = history.value[history.value.length - 1]
    if (previous?.simTimeS === point.simTimeS) history.value[history.value.length - 1] = point
    else history.value.push(point)
    history.value = history.value.slice(-160)
    persistMetricHistory()
  }

  function dosReportKey(report: SecurityReport): string {
    const id = report.report_id || report.summary_id || 'dos-report'
    const time = report.latest_detection_time_s ?? report.detection_time_s ?? report.event_time_s ?? 'unknown-time'
    return `${id}:${time}`
  }

  function appendDosAlarmHistory(reports: SecurityReport[]) {
    const targetNodeId = targetNodeForFamily('DOS')
    if (!isRunFor('DOS') || targetNodeId === null) return
    for (const report of reports) {
      if (String(report.category || '').toUpperCase() !== 'DOS') continue
      const detectorNodeId = report.evidence?.detector_node_id ?? report.source_node_id
      if (detectorNodeId !== targetNodeId) continue
      const key = dosReportKey(report)
      if (seenDosReportKeys.has(key)) continue
      seenDosReportKeys.add(key)
      const rawRate = report.evidence?.observed_packet_rate_pps ?? report.evidence?.packet_rate_pps
      if (typeof rawRate !== 'number' || !Number.isFinite(rawRate)) continue
      const rawThreshold = report.evidence?.flooding_threshold_pps ?? report.evidence?.threshold_pps
      const rawWindow = report.evidence?.window_s ?? report.evidence?.statistics_window_s
      dosAlarmHistory.value.push({
        reportKey: key,
        simTimeS: Number(report.latest_detection_time_s ?? report.detection_time_s ?? report.event_time_s ?? status.value?.sim_time_s ?? 0),
        packetRatePps: rawRate,
        thresholdPps: typeof rawThreshold === 'number' && Number.isFinite(rawThreshold) ? rawThreshold : null,
        windowS: typeof rawWindow === 'number' && Number.isFinite(rawWindow) ? rawWindow : null,
      })
    }
    dosAlarmHistory.value = dosAlarmHistory.value.slice(-160)
  }

  function inferScenario(metadata: RunMetadata) {
    const family = metadata.attack_plan?.[0]?.attack_family
    currentScenarioKey.value = family ? familyToScenario[family] ?? 'overview' : 'overview'
  }

  async function pollRuntime() {
    if (pollInFlight) return
    pollInFlight = true
    try {
      if (!status.value) {
        try {
          const current = await getCurrentRun()
          markRuntimeConnected()
          if (!current.run) {
            error.value = ''
            return
          }
          status.value = current.run
        } catch (cause) {
          await recordConnectionFailure(cause)
          error.value = friendlyError(cause)
          return
        }
      }
      const requestedCursor = cursor.value
      let view = await getRuntime(requestedCursor)
      markRuntimeConnected()
      if (trackedRunId && trackedRunId !== view.status.run_id && requestedCursor !== 0) {
        clearRunData()
        view = await getRuntime(0)
        markRuntimeConnected()
      }
      prepareRun(view.status.run_id)
      status.value = view.status
      cursor.value = view.next_cursor
      appendRuntimeEvents(view.events)
      securityReports.value = view.security_reports
      metrics.value = view.metrics
      runMetadata.value = view.run_metadata
      packetAccounting.value = view.packet_accounting?.run_id === view.status.run_id ? view.packet_accounting : null
      receiverRateObservations.value = view.receiver_rate_observations ?? null
      if (view.scenario_topology) topology.value = view.scenario_topology
      inferScenario(view.run_metadata)
      appendDosAlarmHistory(view.security_reports)
      appendHistory()
      error.value = ''
      if (view.status.state === 'COMPLETED' && !evaluation.value) {
        if (evaluationState.value === 'IDLE') evaluationState.value = 'PENDING'
        if (Date.now() >= nextEvaluationAttemptAt) {
          // Evaluation availability is independent of the online run lifecycle.
          // Retry at most once per five seconds, not on every Runtime poll.
          nextEvaluationAttemptAt = Date.now() + 5000
          const evaluationRunId = view.status.run_id
          try {
            const result = await getEvaluation()
            if (status.value?.run_id === evaluationRunId) {
              evaluation.value = result
              evaluationState.value = 'READY'
              evaluationError.value = ''
            }
            markRuntimeConnected()
          } catch (cause) {
            await recordConnectionFailure(cause)
            if (status.value?.run_id === evaluationRunId) {
              evaluationState.value = cause instanceof ApiError && cause.status === 409 ? 'PENDING' : 'ERROR'
              evaluationError.value = evaluationState.value === 'ERROR' ? friendlyError(cause) : ''
            }
          }
        }
      }
    } catch (cause) {
      await recordConnectionFailure(cause)
      if (cause instanceof ApiError && cause.status === 409) {
        // A Runtime business error alone is not proof that the run disappeared.
        try {
          const current = await getCurrentRun()
          markRuntimeConnected()
          if (!current.run) {
            clearRunData()
            status.value = null
            currentRequest.value = null
            error.value = ''
          } else {
            if (current.run.run_id !== status.value?.run_id) clearRunData()
            status.value = current.run
            error.value = friendlyError(cause)
          }
        } catch (confirmationError) {
          error.value = friendlyError(confirmationError)
        }
      } else {
        error.value = friendlyError(cause)
      }
    } finally {
      pollInFlight = false
    }
  }

  function startPolling() {
    if (timer) return
    timer = setInterval(() => void pollRuntime(), 700)
  }

  function stopPolling() {
    if (!timer) return
    clearInterval(timer)
    timer = null
  }

  async function bootstrap() {
    if (initialized.value) return
    initialized.value = true
    try {
      await pollRuntime()
    } finally {
      startPolling()
    }
  }

  async function launchScenario(key: ScenarioKey, options: ScenarioLaunchOptions = {}) {
    stopPolling()
    loading.value = true
    error.value = ''
    try {
      const request = buildScenarioRequest(key, options)
      const response = await createRun(request)
      markRuntimeConnected()
      clearRunData()
      currentScenarioKey.value = key
      currentRequest.value = request
      status.value = response.run
      topology.value = {
        scope: 'SIMULATOR_SCENARIO_CONFIGURATION',
        nodes: response.nodes,
        links: response.links,
        total_nodes: response.total_nodes,
        total_links: response.total_links,
      }
      status.value = await startRun()
      markRuntimeConnected()
      await pollRuntime()
    } catch (cause) {
      await recordConnectionFailure(cause)
      error.value = friendlyError(cause)
    } finally {
      loading.value = false
      startPolling()
    }
  }

  async function pauseOrResume() {
    if (!status.value) return
    loading.value = true
    error.value = ''
    try {
      status.value = status.value.state === 'PAUSED' ? await resumeRun() : await pauseRun()
      markRuntimeConnected()
      await pollRuntime()
    } catch (cause) {
      await recordConnectionFailure(cause)
      error.value = friendlyError(cause)
    } finally {
      loading.value = false
    }
  }

  async function resetCurrentRun() {
    if (!status.value) return
    stopPolling()
    loading.value = true
    error.value = ''
    try {
      const resetRunId = status.value.run_id
      const result = await resetRun()
      markRuntimeConnected()
      const preservedTopology = topology.value
      clearRunData({ removeStoredHistoryForRunId: resetRunId })
      topology.value = preservedTopology
      status.value = result
      await pollRuntime()
    } catch (cause) {
      await recordConnectionFailure(cause)
      error.value = friendlyError(cause)
    } finally {
      loading.value = false
      startPolling()
    }
  }

  async function startCurrentRun() {
    if (!status.value || status.value.state !== 'INITIALIZED') return
    loading.value = true
    try {
      status.value = await startRun()
      markRuntimeConnected()
      await pollRuntime()
    } catch (cause) {
      await recordConnectionFailure(cause)
      error.value = friendlyError(cause)
    } finally {
      loading.value = false
    }
  }

  async function stopCurrentRun() {
    if (!status.value) return
    loading.value = true
    try {
      status.value = await stopRun()
      markRuntimeConnected()
      await pollRuntime()
    } catch (cause) {
      await recordConnectionFailure(cause)
      error.value = friendlyError(cause)
    } finally {
      loading.value = false
    }
  }

  return {
    status, runMetadata, events, securityReports, metrics, packetAccounting, receiverRateObservations, evaluation, evaluationState, evaluationError, topology, history, dosAlarmHistory,
    cumulativeCounters, acceptedTotal, gcsLocalHmacRejectedTotal, gcsLocalReplayRejectedTotal,
    cursor, loading, error, currentScenarioKey, currentRequest, currentScenario,
    runtimeConnectionState,
    progress, executedDefenseCount, familyMetrics, currentEpisode, stage,
    activeRunFamilies, activeRunFamily, activeRunLabel,
    runAvailable, isRunning, isPaused,
    isRunFor, attackPlanFor, targetNodeForFamily, primaryBusinessFlowFor,
    reportsForFamily, familyMetricsFor, episodeForFamily, scenarioStage,
    bootstrap, startPolling, stopPolling, pollRuntime, launchScenario,
    pauseOrResume, resetCurrentRun, startCurrentRun, stopCurrentRun,
  }
})
