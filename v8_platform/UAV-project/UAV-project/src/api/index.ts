const BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api"

export type JsonPrimitive = string | number | boolean | null
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[]
export interface JsonObject { [key: string]: JsonValue }

export type RunState = "INITIALIZED" | "RUNNING" | "PAUSED" | "STOPPED" | "COMPLETED"

export interface RunStatus {
  schema_version: string
  software_version: string
  run_id: string
  state: RunState
  sim_time_s: number
  duration_s: number
  seed: number
  event_count: number
  pending_attacks: number
  calibration_status: string
  dataset_maturity: "DEVELOPMENT" | "PRELIMINARY" | "FORMAL"
}

export interface CurrentRunView {
  runtime_available: true
  run: RunStatus | null
}

export interface HealthView {
  status: string
  schema_version: string
  software_version: string
}

export interface AttackSpec {
  attack_family: string
  attack_subtype: string
  scheduled_start_s: number
  impact_start_s: number
  end_s: number
  attacker_node_id?: number | null
  target_node_ids: number[]
  target_link_ids: string[]
  intensity: Record<string, JsonValue>
  parameters: Record<string, JsonValue>
  attack_id?: string | null
}

export interface TrafficSpec {
  source_node_id: number
  target_node_id: number
  packet_type: string
  start_s: number
  payload: Record<string, JsonValue>
  interval_s?: number
  count?: number
  sensitive?: boolean
  encrypt?: boolean | null
  session_id?: string | null
  sequence_start?: number
  measurement_model?: { name: 'BOUNDED_ALTITUDE_SENSOR'; amplitude_m: number; period_s: number }
}

export interface SessionLifecycleSpec {
  sender_node_id: number
  receiver_node_id: number
  rotate_at_s: number
  old_session_id: string
  new_session_id: string
}

export interface CreateRunRequest {
  flooding_detection_enabled?: boolean
  demo_profile?: 'V17'
  seed?: number
  duration_s?: number
  step_s?: number
  node_count?: number
  node_roles?: Record<number, string>
  auto_traffic?: boolean
  encrypt_sensitive?: boolean
  queue_capacity?: number
  tx_service_per_step?: number
  rx_service_per_step?: number
  phy_sample_interval_s?: number
  traffic_statistics_window_s?: number
  flooding_packet_rate_threshold_pps?: number
  replay_timestamp_freshness_s?: number
  replay_reorder_window_size?: number
  attack_specs?: AttackSpec[]
  normal_disturbance_specs?: Record<string, JsonValue>[]
  traffic_specs?: TrafficSpec[]
  session_lifecycle_specs?: SessionLifecycleSpec[]
  auto_advance?: boolean
  wall_interval_s?: number
}

export interface TopologyNode {
  id: number
  role: string
  pos: [number, number, number] | null
  state?: string
  position_available?: boolean
}

export interface TopologyLink {
  id: string
  src: number
  dst: number
  status: "active" | "blocked" | string
}

export interface ScenarioTopology {
  scope: "SIMULATOR_SCENARIO_CONFIGURATION" | string
  nodes: TopologyNode[]
  links: TopologyLink[]
  total_nodes: number
  total_links: number
}

export interface CreateRunResponse extends ScenarioTopology {
  status: string
  message: string
  run: RunStatus
}

export interface ApplicationHmacMetadata {
  enabled: boolean
  algorithm: string
  tag_length_bytes: number
  key_scope: string
  covered_fields: string[]
  implementation_status: string
  excluded_control_packet_types?: string[]
}

export interface ProviderMetadata {
  name: string
  version: string
  status: string
}

export interface RunMetadata {
  schema_version?: string
  software_version?: string
  run_id?: string
  seed?: number
  duration_s?: number
  step_s?: number
  node_count?: number
  legitimate_node_count?: number
  node_roles?: Record<string, string>
  legitimate_node_roles?: Record<string, string>
  external_participants?: Array<{ node_id: number; role: string }>
  attack_plan?: AttackSpec[]
  requested_attack_plan?: AttackSpec[]
  run_config?: CreateRunRequest & Record<string, unknown>
  probe_profile?: string
  application_hmac?: ApplicationHmacMetadata
  security_providers?: {
    key_provider?: ProviderMetadata
    crypto_provider?: ProviderMetadata
    terminal_credential_provider?: ProviderMetadata
  }
  [key: string]: unknown
}

export interface PacketFeatures {
  packet_type?: string | null
  encrypted?: boolean | null
  sequence_no?: number | null
  session_id?: string | null
  key_epoch?: number | string | null
  link_id?: string | null
  claimed_src_id?: number | null
  claimed_dst_id?: number | null
  [key: string]: unknown
}

export interface TrafficFeatures {
  latency_ms?: number | null
  throughput_mbps?: number | null
  packet_rate_pps?: number | null
  total_packet_count?: number | null
  statistics_window_s?: number | null
  flooding_threshold_pps?: number | null
  [key: string]: unknown
}

export interface SecurityStateFeatures {
  auth_result?: string | null
  auth_failure_reason?: string | null
  application_hmac_result?: string | null
  application_hmac_failure_reason?: string | null
  application_hmac_key_id?: string | null
  replay_check_result?: string | null
  key_state?: string | null
  [key: string]: unknown
}

export interface OnlineFeatures {
  packet?: PacketFeatures
  traffic?: TrafficFeatures
  security_state?: SecurityStateFeatures
  phy?: Record<string, unknown>
  node?: Record<string, unknown>
  [key: string]: Record<string, unknown> | undefined
}

export interface ActionRequest {
  action?: string | null
  reason?: string | null
  requester_node_id?: number | null
  target_node_id?: number | null
  target_link_id?: string | null
  [key: string]: unknown
}

export interface ActionResult {
  request?: ActionRequest
  allowed?: boolean
  executed?: boolean
  executed_time_s?: number | null
  failure_reason?: string | null
  outcome?: Record<string, unknown>
  target?: Record<string, unknown>
  [key: string]: unknown
}

export interface SecurityReportEvidence {
  reason?: string | null
  application_hmac_result?: string | null
  replay_check_result?: string | null
  sequence_no?: number | null
  packet_rate_pps?: number | null
  observed_packet_rate_pps?: number | null
  total_packet_count?: number | null
  threshold_pps?: number | null
  flooding_threshold_pps?: number | null
  window_s?: number | null
  statistics_window_s?: number | null
  application_hmac_passed?: boolean | null
  replay_rejection_reason?: string | null
  scope?: string | null
  detector_node_id?: number | null
  detection_time_s?: number | null
  source_report_id?: string | null
  [key: string]: unknown
}

export interface SecurityReport {
  schema_version?: string
  run_id?: string
  report_id?: string
  summary_id?: string
  report_type?: string
  source_node_id?: number
  event_time_s?: number
  detection_time_s?: number
  latest_detection_time_s?: number
  action_time_s?: number | null
  report_received_time_s?: number | null
  report_delay_s?: number | null
  category?: string
  severity?: string
  evidence?: SecurityReportEvidence
  action_result?: ActionResult | null
  count?: number
  source_event_ids?: string[]
  source_report_ids?: string[]
  [key: string]: unknown
}

export interface OnlineEvent {
  event_id: string
  message_id: string | null
  sim_time_s: number
  event_type: string
  observer_node_id: number
  observer_role: string
  online_features: OnlineFeatures
  availability: Record<string, unknown>
  extensions: {
    defense_result?: ActionResult
    model_result?: Record<string, unknown>
    [key: string]: unknown
  }
}

export interface RuntimeMetrics {
  scope?: string
  received_success?: number
  received_failure?: number
  delivery_rate?: number
  packet_loss_rate?: number
  mean_latency_ms?: number
  mean_throughput_mbps?: number
  security_report_count?: number
  missing_or_delayed_reports?: number
  [key: string]: number | string | undefined
}

export interface RuntimeView {
  receiver_rate_observations?: ReceiverRateObservations
  packet_accounting?: PacketAccounting
  scope: "GCS_RECEIVED_RUNTIME_VIEW"
  status: RunStatus
  run_metadata: RunMetadata
  node_roles: Record<string, string>
  events: OnlineEvent[]
  next_cursor: number
  security_reports: SecurityReport[]
  missing_or_delayed_reports: number
  metrics: RuntimeMetrics
  scenario_topology?: ScenarioTopology
}

export interface ReceiverRateObservations {
  scope: 'TARGET_RECEIVER_RUNTIME_OBSERVATIONS'
  nodes: Array<{ node_id: number; peak_window_rate_pps: number; statistics_window_s: number; samples: Array<{ sim_time_s: number; packet_rate_pps: number; total_packet_count: number; statistics_window_s: number; flooding_threshold_pps: number }> }>
}

export interface CausalFrameIdentity {
  message_id: string
  claimed_src_id: number
  sequence_no: number
  sender_id: number
  receiver_id: number
  hop_index: number
  packet_type: string
  sensitive: boolean
  encrypted: boolean
}
export interface CausalCapture extends CausalFrameIdentity {
  message_id: string
  frame_emission_id: string
  family: string
  attack_id: string
  capture_time_s: number
  sender_id: number
  receiver_id: number
}

export interface PacketAccounting {
    causal_evidence?: {
      scope: 'SIMULATOR_AUDIT_TRUTH'
      derivations: Array<{ original: CausalFrameIdentity; copy: CausalFrameIdentity; capture_time_s: number; modified_time_s: number }>
      captures?: CausalCapture[]
      generations?: Array<{ message_id: string; source_id: number; target_id: number; sensitive: boolean }>
      transmissions?: Array<CausalFrameIdentity & { sent_time_s: number; emission_id: string; decoded: boolean; actual_sender_id: number }>
      interceptions?: Array<{ message_id: string; attacker_id: number; original_emission_id: string; capture_time_s: number; replacement_queued: boolean; replacement_emission_id: string | null; replacement_sent_time_s: number | null; target_decoded?: boolean; original_target_delivery_suppressed: boolean }>
      mutations?: Array<{ message_id: string; original_message_id?: string; capture_time_s?: number; sequence_no: number; stage?: string; modified_time_s: number; original_payload: Record<string, JsonValue>; payload: Record<string, JsonValue>; changed_fields: string[]; hmac_recomputed: boolean }>
      security_observations?: Array<{ event_id: string; message_id: string | null; observer_node_id: number; event_time_s?: number; security_state?: { application_hmac_result?: string; replay_check_result?: string }; extensions?: { crypto_send_failure?: { withheld_message_ref: string; error_code: string } } }>
    }
  schema_version: string
  run_id: string
  scope: 'SIMULATOR_GENERATION_AND_EXECUTION_ACCOUNTING'
  simulation_duration_s: number
  business: Record<string, number>
  attacks: Array<{
    attack_id: string
    family: string
    attack_duration_s: number
    configured_rate_pps?: number
    counts: Record<string, number | null>
  }>
}

export interface EvaluationFamilyMetrics {
  TP: number
  FP: number
  FN: number
  TN: number
  precision: number
  recall_pd: number
  pfa_fpr: number
  f1: number
  alarm_count: number
  matched_alarm_count: number
  duplicate_alarm_count: number
  normal_alarm_count: number
  normal_window_count: number
  mean_detection_delay_s: number | null
  mean_action_delay_s: number | null
}

export interface EvaluationEpisode {
  attack_id?: string | null
  attack_family: string
  attack_subtype: string
  impact_start_s: number
  end_s: number
  episode_detected: boolean
  alarm_count: number
  detection_delay_s: number | null
  action_executed: boolean
  action_delay_s: number | null
  defense_attempts: Array<{
    event_id?: string | null
    sim_time_s: number
    allowed: boolean
    executed: boolean
    action?: string | null
    failure_reason?: string | null
    source?: string | null
  }>
  executed_defense_count: number
  defense_effective: boolean
  defense_policy: string
  defense_evidence: Record<string, unknown>
  attack_effective: boolean
  report_delay_s?: number | null
  [key: string]: unknown
}

export interface EavesdroppingEvaluation {
  detection_evaluation_applicable: false
  sensitive_plaintext_exposure_count: number
  ciphertext_protected_count: number
  content_recovery_count: number
  sensitive_data_exposed: boolean
  protection_effective: boolean
  legitimate_service_availability: number | null
  online_detection_rate: null
  note: string
}

export interface EvaluationView {
  dos_target_receiver_evaluation?: {
    scope: 'ATTACK_TARGET_RECEIVER'; applicable: boolean; target_node_ids: number[]
    TP: number | null; FP: number | null; FN: number | null; TN: number | null
    recall_pd: number | null; pfa_fpr: number | null; normal_window_count: number
    mean_detection_delay_s: number | null; target_alarm_count: number; non_target_alarm_count: number
  }
  detector_applicability?: Record<string, { applicable: boolean; reason: string }>
  scope: "GROUND_TRUTH_OFFLINE_EVALUATION"
  attack_episode_count: number
  detection_attack_episode_count: number
  normal_window_count: number
  per_attack_family: Record<string, EvaluationFamilyMetrics>
  episodes: EvaluationEpisode[]
  attack_effective_rate: number | null
  defense_effective_rate: number | null
  legitimate_service_damage: number | null
  mean_detection_delay_s: number | null
  mean_time_to_action_s: number | null
  report_delay_s: number | null
  service_recovery_time_s: number | null
  eavesdropping: EavesdroppingEvaluation
  metric_definitions?: Record<string, string | number>
}

export class ApiError extends Error {
  readonly status: number
  readonly detail: unknown

  constructor(status: number, message: string, detail?: unknown) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.detail = detail
  }
}

async function parseJson<T>(response: Response): Promise<T> {
  let data: unknown = null
  try {
    data = await response.json()
  } catch {
    data = null
  }
  if (!response.ok) {
    const body = data as { message?: unknown; msg?: unknown; detail?: unknown } | null
    const detail = body?.message ?? body?.msg ?? body?.detail ?? `HTTP ${response.status}`
    const message = typeof detail === "string" ? detail : JSON.stringify(detail)
    throw new ApiError(response.status, message || "请求失败", detail)
  }
  return data as T
}

function get<T>(path: string): Promise<T> {
  return fetch(`${BASE_URL}${path}`, { headers: { Accept: "application/json" } }).then(parseJson<T>)
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: body === undefined ? { Accept: "application/json" } : { "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(parseJson<T>)
}

export const createRun = (body: CreateRunRequest) => post<CreateRunResponse>("/runs", body)
export const startRun = () => post<RunStatus>("/runs/start")
export const pauseRun = () => post<RunStatus>("/runs/pause")
export const resumeRun = () => post<RunStatus>("/runs/resume")
export const stopRun = () => post<RunStatus>("/runs/stop")
export const resetRun = () => post<RunStatus>("/runs/reset")
export const getRunStatus = () => get<RunStatus>("/runs/status")
export const getCurrentRun = () => get<CurrentRunView>("/runs/current")
export const getHealth = () => get<HealthView>("/health")
export const getRuntime = (cursor = 0) => get<RuntimeView>(`/runtime?cursor=${encodeURIComponent(cursor)}`)
export const getEvaluation = () => get<EvaluationView>("/evaluation")
export const scheduleAttack = (body: AttackSpec) => post<Record<string, unknown>>("/attacks/schedule", body)

// Compatibility exports remain for unmounted historical components. The six
// formal routes never use these legacy endpoints.
export const initSimulation = (numUavs = 12) => post<Record<string, unknown>>("/init", { num_uavs: numUavs })
export const startAttack = (body: Record<string, unknown>) => post<Record<string, unknown>>("/attack", body)
export const getTopology = () => get<Record<string, unknown>>("/topology")
export const getCommands = () => get<Record<string, unknown>>("/commands")
export const startListen = (type: string, duration = 10) => post<Record<string, unknown>>("/listen/start", { type, duration })
export const stopListen = (type: string) => post<Record<string, unknown>>("/listen/stop", { type, duration: 1 })
export const getListenData = (type: string) => get<Record<string, unknown>>(`/listen/data/${encodeURIComponent(type)}`)
export const getStats = () => get<Record<string, unknown>>("/stats")
export const getPacketLossMetrics = () => get<Record<string, unknown>>("/metrics/packet_loss")
export const getMetricsSummary = () => get<Record<string, unknown>>("/metrics/summary")
export const getMetricsHistory = (lastN = 100) => get<Record<string, unknown>>(`/metrics/history?last_n=${lastN}`)
export const getNodeMetrics = (nodeId: number | null = null) => get<Record<string, unknown>>(`/metrics/node${nodeId === null ? "" : `/${nodeId}`}`)
export const getLinkMetrics = () => get<Record<string, unknown>>("/metrics/links")
export const resetStats = () => post<Record<string, unknown>>("/stats/reset")
export const getDefenseStatus = (nodeId: number | null = null) => get<Record<string, unknown>>(`/defense/status${nodeId === null ? "" : `?node_id=${nodeId}`}`)
export const configDefenseGlobal = (attackType: string, enabled: boolean) => post<Record<string, unknown>>("/defense/config/global", { attack_type: attackType, enabled })
export const configDefenseNode = (nodeId: number, attackType: string, enabled: boolean) => post<Record<string, unknown>>("/defense/config", { node_id: nodeId, attack_type: attackType, enabled })
export const configDefenseNodeBatch = (nodeId: number, config: Record<string, boolean>) => post<Record<string, unknown>>("/defense/config/batch", { node_id: nodeId, config })
export const getCurrentWindowStats = getStats
export const getWindowHistory = getMetricsHistory
export const getWindowTrend = getMetricsHistory
