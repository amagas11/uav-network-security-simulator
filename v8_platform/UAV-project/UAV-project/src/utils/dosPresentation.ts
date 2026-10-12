import type { SecurityReport } from '@/api'

// Reports are the complete current-run GCS inbox, never the retained event window.
export function authFailureReportCount(matches: boolean, reports: SecurityReport[] | null | undefined): number | null {
  if (!matches || !Array.isArray(reports)) return null
  return reports.filter(r => r.category === 'AUTH_FAILURE').length
}
export function booleanResult(value: unknown): string {
  return value === true ? '是' : value === false ? '否' : '—'
}
export function blockedPacketCount(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value}条` : '—'
}
export function legitimateHarmResult(evidence: Record<string, unknown> | null | undefined): string {
  return evidence?.legitimate_harm_available === true ? booleanResult(evidence.legitimate_harm_bounded) : '—'
}
