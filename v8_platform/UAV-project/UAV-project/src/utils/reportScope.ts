import type { SecurityReport } from '@/api'

// A delivered summary is one visible document, not one per local alarm.
export function visibleReportScope(reports: SecurityReport[]) {
  const seen = new Set<string>()
  const categories: Record<string, number> = {}
  const actions: Record<string, number> = {}
  let total = 0
  for (const report of reports) {
    const id = report.report_id || report.summary_id
    if (id && seen.has(String(id))) continue
    if (id) seen.add(String(id))
    total++
    const category = String(report.category || report.report_type || '未知')
    categories[category] = (categories[category] || 0) + 1
    if (report.action_result?.executed === true) {
      const action = String(report.action_result.request?.action || '未标明动作')
      actions[action] = (actions[action] || 0) + 1
    }
  }
  return { total, categories, actions, executed: Object.values(actions).reduce((a, b) => a + b, 0) }
}
