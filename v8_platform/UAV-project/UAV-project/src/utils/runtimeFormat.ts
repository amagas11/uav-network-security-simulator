import { ApiError, type EvaluationEpisode, type OnlineEvent, type SecurityReport } from '@/api'

export function displayValue(value: unknown, suffix = ''): string {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'number' && !Number.isFinite(value)) return '—'
  return `${String(value)}${suffix}`
}

export function formatNumber(value: unknown, digits = 1): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—'
}

export function formatPercent(value: unknown, digits = 1): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(digits)}%` : 'N/A'
}

export function formatDuration(value: unknown, digits = 2): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—'
  if (value !== 0 && Math.abs(value) < 10 ** -digits) return `<${(10 ** -digits).toFixed(digits)}s`
  return `${value.toFixed(digits)}s`
}

export function formatReportTime(report: SecurityReport): string {
  const candidates = [report.detection_time_s, report.latest_detection_time_s, report.event_time_s]
  const value = candidates.find((candidate) => typeof candidate === 'number' && Number.isFinite(candidate))
  return typeof value === 'number' ? `${value.toFixed(1)}s` : '—'
}

export function shortId(value: string | null | undefined, length = 12): string {
  if (!value) return '—'
  return value.length <= length ? value : `…${value.slice(-length)}`
}

export function eventSecurityResult(event: OnlineEvent): string {
  const state = event.online_features.security_state
  return state?.application_hmac_failure_reason
    || state?.replay_check_result
    || state?.application_hmac_result
    || state?.auth_result
    || '—'
}

export function reportReason(report: SecurityReport): string {
  return String(
    report.evidence?.reason
    || report.evidence?.replay_check_result
    || report.evidence?.application_hmac_result
    || report.action_result?.request?.reason
    || '—',
  )
}

export function reportAction(report: SecurityReport): string {
  return String(report.action_result?.request?.action || '—')
}

const attackSubtypeLabels: Record<string, string> = {
  KNOWN_ID_CONFLICT: '身份冲突型伪装',
  TELEMETRY_ABRUPT_CHANGE: '遥测数据篡改',
  FLOODING: '应用层报文洪泛',
  CIPHERTEXT_ONLY: '密文旁路监听',
  IMMEDIATE_REPLAY: '即时重放',
  DELAYED_REPLAY: '延迟重放',
  OLD_SESSION_REPLAY: '旧会话重放',
}

const securityResultLabels: Record<string, string> = {
  PASS: '校验通过',
  HMAC_MISMATCH: 'HMAC 校验不匹配',
  UNKNOWN_DEVICE_KEY: '未知设备认证密钥',
  DUPLICATE: '重复报文',
  STALE_TIMESTAMP: '时间戳过期',
  STALE: '报文已过期',
  WRONG_SESSION: '会话不匹配',
}

const defensePolicyLabels: Record<string, string> = {
  SPOOFED_IDENTITY_REJECTION: '伪装身份拒绝',
  FDI_POST_HMAC_REJECTION_AND_NO_UPDATE: 'HMAC 后篡改拒绝且不更新业务状态',
  FLOODING_RECEIVER_RATE_AND_HMAC_GATE: '接收端总体速率检测与 HMAC 前置过滤',
  REPLAY_REJECTION_WITH_LEGITIMATE_CONTINUITY: '重放拒绝并保持合法业务连续性',
}

const categoryLabels: Record<string, string> = {
  AUTH_FAILURE: '应用认证失败',
  DOS: '洪泛告警',
  REPLAY: '重放拒绝',
}

export function humanizeAttackSubtype(value: unknown): string {
  const key = String(value || '')
  return attackSubtypeLabels[key] || displayValue(value)
}

export function humanizeSecurityResult(value: unknown): string {
  const key = String(value || '')
  return securityResultLabels[key] || displayValue(value)
}

export function humanizeDefensePolicy(value: unknown): string {
  const key = String(value || '')
  return defensePolicyLabels[key] || displayValue(value)
}

export function humanizeReportCategory(value: unknown): string {
  const key = String(value || '')
  return categoryLabels[key] || displayValue(value)
}

export function nodeDisplayName(nodeId: number | null | undefined, nodeRoles?: Record<string, string>): string {
  if (typeof nodeId !== 'number' || !Number.isFinite(nodeId)) return '—'
  const role = String(nodeRoles?.[String(nodeId)] || '').toUpperCase()
  if (role === 'GCS') return 'GCS'
  if (role === 'LEADER') return `Leader ${nodeId}`
  if (role === 'FOLLOWER') return `Follower ${nodeId}`
  if (role === 'EXTERNAL') return `External ${nodeId}`
  return `节点 ${nodeId}`
}

export function episodeForFamily(episodes: EvaluationEpisode[] | undefined, family: string): EvaluationEpisode | null {
  return episodes?.find((episode) => episode.attack_family === family) ?? null
}

export function friendlyError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error)
  if (error instanceof ApiError && error.status === 409) {
    return '当前运行状态不允许执行该操作，请先创建场景或检查运行状态。'
  }
  if (error instanceof ApiError && error.status === 422) {
    return `场景配置未通过后端校验：${raw}`
  }
  if (raw.includes('仿真未初始化')) return '尚未创建仿真运行，请先启动一个场景。'
  if (raw.includes('409')) return '当前运行状态不允许执行该操作，请检查是否已创建或暂停。'
  if (raw.includes('422')) return '场景配置未通过后端校验，请检查参数后重试。'
  if (raw.includes('Failed to fetch')) return '无法连接仿真后端，请确认 FastAPI 服务已启动。'
  return raw || '请求失败，请稍后重试。'
}
