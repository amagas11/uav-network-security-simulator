import type { AttackSpec, CreateRunRequest, TrafficSpec } from '@/api'

export type ScenarioKey = 'overview' | 'spoofing' | 'fdi' | 'dos' | 'eavesdropping' | 'replay'
export type ReplaySubtype = 'IMMEDIATE_REPLAY' | 'DELAYED_REPLAY' | 'OLD_SESSION_REPLAY'

// Retained thresholds; formal non-DoS demos explicitly disable the optional
// Flooding alarm rather than inflating its threshold. Old API callers keep
// comprehensive detection unless they opt out via the real run configuration.
export const DEMO_NON_DOS_FLOODING_THRESHOLD_PPS = 12
export const DEMO_DOS_FLOODING_THRESHOLD_PPS = 8

export interface ScenarioLaunchOptions {
  simulationDurationS?: number
  seed?: number
  floodingRatePps?: number
  floodingDurationS?: number
  replaySubtype?: ReplaySubtype
}

export interface ScenarioDefinition {
  key: ScenarioKey
  family: string | null
  subtype: string | null
  title: string
  shortTitle: string
  description: string
  mechanism: string
  encryption: 'ON' | 'OFF'
  route: string
}

export const SCENARIOS: Record<ScenarioKey, ScenarioDefinition> = {
  overview: {
    key: 'overview', family: null, subtype: null, title: '系统总览', shortTitle: '系统总览',
    description: '查看当前编队通信、真实 Runtime 指标、安全报告与离线评估。',
    mechanism: 'GCS / Leader / Follower 逐跳通信', encryption: 'OFF', route: '/',
  },
  spoofing: {
    key: 'spoofing', family: 'SPOOFING', subtype: 'KNOWN_ID_CONFLICT', title: '报文伪装攻击', shortTitle: '报文伪装',
    description: '攻击者只修改声明源身份 ID；业务载荷、报文类型、序列号和时间戳保持不变。',
    mechanism: '声明源 ID 伪造 → Application HMAC mismatch → DROP_PACKET', encryption: 'OFF', route: '/spoofing',
  },
  fdi: {
    key: 'fdi', family: 'FDI', subtype: 'TELEMETRY_ABRUPT_CHANGE', title: 'FDI攻击（虚假数据注入）', shortTitle: 'FDI攻击',
    description: 'External 捕获合法遥测报文，修改业务内容后额外注入副本；合法原报文继续传输，原 HMAC 不重算。',
    mechanism: '捕获合法报文 → 业务内容篡改副本注入 → HMAC_MISMATCH → DROP', encryption: 'OFF', route: '/fdi',
  },
  dos: {
    key: 'dos', family: 'DOS', subtype: 'FLOODING', title: 'DoS攻击（应用层报文洪泛）', shortTitle: 'DoS攻击',
    description: '接收端按所有来源的总体到达速率检测 Flooding，非法报文在普通 RX queue 前被 HMAC gate 丢弃。',
    mechanism: 'Receiver total arrivals → DOS alarm → Application HMAC gate', encryption: 'OFF', route: '/dos',
  },
  eavesdropping: {
    key: 'eavesdropping', family: 'EAVESDROPPING', subtype: 'CIPHERTEXT_ONLY', title: '窃听攻击', shortTitle: '窃听攻击',
    description: '攻击者被动监听合法无线通信，截获数据但不主动发送或修改报文。',
    mechanism: 'CSI → Person-A SKG → session key → AES-GCM', encryption: 'ON', route: '/eavesdropping',
  },
  replay: {
    key: 'replay', family: 'REPLAY', subtype: 'IMMEDIATE_REPLAY', title: '重放攻击', shortTitle: '重放攻击',
    description: '攻击者捕获历史真实合法完整报文，之后原样重新发送。',
    mechanism: 'HMAC PASS → timestamp → session / key epoch → Replay Window', encryption: 'OFF', route: '/replay',
  },
}

const attack = (family: string, subtype: string, updates: Partial<AttackSpec> = {}): AttackSpec => ({
  attack_family: family,
  attack_subtype: subtype,
  scheduled_start_s: 0,
  impact_start_s: 0.4,
  end_s: 2.4,
  attacker_node_id: -1,
  target_node_ids: [1],
  target_link_ids: [],
  intensity: {},
  parameters: {},
  ...updates,
})

const traffic = (updates: Partial<TrafficSpec> = {}): TrafficSpec => ({
  source_node_id: 2,
  target_node_id: 1,
  packet_type: 'STATUS',
  start_s: 0.2,
  payload: { status_code: 1, value: 42 },
  interval_s: 0.4,
  count: 6,
  sensitive: false,
  encrypt: false,
  session_id: 'frontend-demo-session',
  sequence_start: 100,
  ...updates,
})

const baseRun = (seed = 42): CreateRunRequest => ({
  demo_profile: 'V17',
  seed,
  duration_s: 3.2,
  step_s: 0.2,
  node_count: 4,
  auto_traffic: false,
  encrypt_sensitive: false,
  queue_capacity: 128,
  tx_service_per_step: 64,
  rx_service_per_step: 64,
  phy_sample_interval_s: 0.2,
  traffic_statistics_window_s: 1,
  flooding_packet_rate_threshold_pps: DEMO_NON_DOS_FLOODING_THRESHOLD_PPS,
  flooding_detection_enabled: false,
  replay_timestamp_freshness_s: 2,
  replay_reorder_window_size: 32,
  attack_specs: [],
  traffic_specs: [],
  session_lifecycle_specs: [],
  auto_advance: true,
  wall_interval_s: 0.08,
})

/**
 * Build only scenarios already exercised by the Python acceptance matrix.
 * Values here are configuration/truth inputs, never fabricated outcomes.
 */
function buildDefaultScenarioRequest(key: ScenarioKey, options: ScenarioLaunchOptions = {}): CreateRunRequest {
  const request = baseRun(options.seed ?? 42)

  if (key === 'overview') {
    request.auto_traffic = true
    request.traffic_specs = [traffic()]
    return request
  }

  if (key === 'spoofing') {
    request.attack_specs = [attack('SPOOFING', 'KNOWN_ID_CONFLICT', {
      parameters: { claimed_src_id: 0, source_copy_mode: 'LEGITIMATE_FRAME_COPY', legitimate_source_id: 2 },
    })]
    request.traffic_specs = [traffic()]
    return request
  }

  if (key === 'fdi') {
    request.attack_specs = [attack('FDI', 'TELEMETRY_ABRUPT_CHANGE', {
      attacker_node_id: -1,
      target_link_ids: ['link-2-1'],
      parameters: { injection_mode: 'CAPTURE_MODIFY_INJECT', legitimate_source_id: 2, field: 'altitude_m', absolute_offset: 0.1, bias_model: 'BOUNDED_PERIODIC', bias_amplitude_m: 0.04, bias_period_packets: 11 },
    })]
    request.traffic_specs = [traffic({
      packet_type: 'TELEMETRY',
      payload: {},
      measurement_model: { name: 'BOUNDED_ALTITUDE_SENSOR', amplitude_m: 0.04, period_s: 2 },
      interval_s: 0.2,
      count: 10,
      session_id: 'frontend-fdi-session',
    })]
    return request
  }

  if (key === 'dos') {
    const rate = options.floodingRatePps ?? 80
    const attackDuration = options.floodingDurationS ?? 1.6
    request.flooding_packet_rate_threshold_pps = DEMO_DOS_FLOODING_THRESHOLD_PPS
    request.flooding_detection_enabled = true
    request.attack_specs = [attack('DOS', 'FLOODING', {
      end_s: 0.4 + attackDuration,
      intensity: { value: rate, unit: 'pps' },
      parameters: { packet_type: 'STATUS', target_packet_size_bytes: 192 },
    })]
    request.traffic_specs = [traffic({ count: 8, interval_s: 0.3, session_id: 'frontend-dos-legitimate' })]
    return request
  }

  if (key === 'eavesdropping') {
    // This is the same no-preloaded-key Person-A scenario exercised by the
    // official FastAPI acceptance test.
    return {
      ...request,
      seed: options.seed ?? 31,
      duration_s: 4,
      step_s: 0.1,
      encrypt_sensitive: true,
      tx_service_per_step: 32,
      rx_service_per_step: 32,
      phy_sample_interval_s: 10,
      attack_specs: [attack('EAVESDROPPING', 'CIPHERTEXT_ONLY', {
        impact_start_s: 0.1,
        end_s: 3.8,
        target_link_ids: ['link-2-1'],
        parameters: { receiver_radius_m: 1000 },
      })],
      traffic_specs: [traffic({
        start_s: 0.1,
        interval_s: 0.2,
        count: 18,
        sensitive: true,
        encrypt: true,
        session_id: 'official-web-eaves-session',
      })],
    }
  }

  const subtype = options.replaySubtype ?? 'IMMEDIATE_REPLAY'
  let impactStart = 0.6
  let sessionId = 'frontend-replay-live'
  let parameters: Record<string, string | number | boolean> = { max_capture_age_s: 0.8 }
  if (subtype === 'DELAYED_REPLAY') {
    impactStart = 0.4
    // Keep the captured business frame old enough to be rejected while
    // leaving enough freshness budget for its real security report to reach
    // GCS without creating a secondary control-traffic Replay alarm.
    parameters = { delay_s: 0.8 }
    request.replay_timestamp_freshness_s = 0.5
  } else if (subtype === 'OLD_SESSION_REPLAY') {
    impactStart = 0.8
    sessionId = 'frontend-replay-old'
    parameters = { stale_session_id: sessionId }
    request.session_lifecycle_specs = [{
      sender_node_id: 2,
      receiver_node_id: 1,
      rotate_at_s: 0.6,
      old_session_id: sessionId,
      new_session_id: 'frontend-replay-new',
    }]
  }
  request.attack_specs = [attack('REPLAY', subtype, {
    impact_start_s: impactStart,
    end_s: 2.4,
    parameters,
  })]
  request.traffic_specs = [traffic({
    packet_type: 'TELEMETRY',
    payload: { altitude_m: 100 },
    count: 1,
    session_id: sessionId,
    sequence_start: 100,
  })]
  return request
}

export const DEFAULT_DURATION_S: Record<ScenarioKey, number> = {
  overview: 3.2, spoofing: 3.2, fdi: 3.2, dos: 3.2, eavesdropping: 4, replay: 3.2,
}
export const MAX_SIMULATION_DURATION_S = 30
export const MAX_PLANNED_FLOOD_PACKETS = 5000

/** Extend actual schedules, not animation time. Default schedules remain exact. */
export function buildScenarioRequest(key: ScenarioKey, options: ScenarioLaunchOptions = {}): CreateRunRequest {
  const request = buildDefaultScenarioRequest(key, options)
  const duration = options.simulationDurationS ?? DEFAULT_DURATION_S[key]
  const step = request.step_s!
  if (!Number.isFinite(duration) || duration < DEFAULT_DURATION_S[key] || duration > MAX_SIMULATION_DURATION_S
      || Math.abs(duration / step - Math.round(duration / step)) > 1e-8) {
    throw new Error(`仿真时长须为 ${DEFAULT_DURATION_S[key]}–30 秒，且为 ${step} 秒的整数倍`)
  }
  request.duration_s = duration
  if (key === 'dos') {
    const rate = options.floodingRatePps ?? 80
    const attackDuration = options.floodingDurationS ?? 1.6
    if (!Number.isFinite(rate) || rate < 9 || rate > 500 || !Number.isFinite(attackDuration)
        || attackDuration < 0.4 || Math.abs(attackDuration / step - Math.round(attackDuration / step)) > 1e-8
        || 0.4 + attackDuration > duration - 0.4 + 1e-8) {
      throw new Error('Flooding 须为9–500pps；攻击时长须按0.2秒步长，且保留至少0.4秒观察期')
    }
    if (Math.floor(rate * attackDuration + 1e-9) > MAX_PLANNED_FLOOD_PACKETS) {
      throw new Error('超过5000条洪泛报文的演示资源预算，请缩短攻击时间或降低速率')
    }
  }
  if (duration !== DEFAULT_DURATION_S[key] && key !== 'overview') {
    if (key !== 'replay') {
      const buffer = { spoofing: 1, fdi: 1.2, dos: 0.9, eavesdropping: 0.5 }[key]
      for (const spec of request.traffic_specs ?? []) {
        spec.count = Math.floor((duration - buffer - spec.start_s + 1e-9) / spec.interval_s!) + 1
      }
    }
    const plan = request.attack_specs![0]!
    if (key === 'spoofing' || key === 'fdi') {
      const align = (value: number) => Number((Math.round(value / step) * step).toFixed(9))
      plan.impact_start_s = align(0.4 * duration / 3.2)
      plan.end_s = align(2.4 * duration / 3.2)
    } else if (key === 'eavesdropping') {
      plan.end_s = Number((duration - 0.2).toFixed(9))
    }
    // Replay capture/delay/rotation stay ordered and single-shot; extra time
    // is observation time. DoS keeps its separately selected attack duration.
  }
  return request
}
