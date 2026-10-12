import type { SecurityReport } from '@/api'

export interface CumulativeReportPoint {
  label: string
  simTimeS: number | null
  detectedCount: number
  executedCount: number
}

export interface CumulativeReportSeriesOptions {
  reports: SecurityReport[]
  matchDetection: (report: SecurityReport) => boolean
  matchExecutedAction: (report: SecurityReport) => boolean
}

function reportTime(report: SecurityReport): number | null {
  const candidates = [
    report.detection_time_s,
    report.latest_detection_time_s,
    report.event_time_s,
    report.action_time_s,
  ]
  const value = candidates.find((candidate) => typeof candidate === 'number' && Number.isFinite(candidate))
  return typeof value === 'number' ? value : null
}

function reportKey(report: SecurityReport): string {
  const id = report.report_id || report.summary_id
  if (id) return String(id)
  return JSON.stringify([
    report.category,
    report.source_node_id,
    reportTime(report),
    report.evidence?.reason,
    report.evidence?.replay_check_result,
    report.action_result?.request?.action,
  ])
}

/** Rebuild a whole cumulative attack timeline from GCS-delivered reports. */
export function buildCumulativeReportSeries(
  options: CumulativeReportSeriesOptions,
): CumulativeReportPoint[] {
  const unique = new Map<string, SecurityReport>()
  for (const report of options.reports) {
    if (!options.matchDetection(report)) continue
    unique.set(reportKey(report), report)
  }

  const ordered = [...unique.entries()]
    .map(([key, report]) => ({ key, report, time: reportTime(report) }))
    .sort((left, right) => {
      const leftTime = left.time ?? Number.POSITIVE_INFINITY
      const rightTime = right.time ?? Number.POSITIVE_INFINITY
      return leftTime - rightTime || left.key.localeCompare(right.key)
    })

  if (!ordered.length) return []

  const points: CumulativeReportPoint[] = [{
    label: '开始',
    simTimeS: null,
    detectedCount: 0,
    executedCount: 0,
  }]
  let detectedCount = 0
  let executedCount = 0

  for (let index = 0; index < ordered.length;) {
    const first = ordered[index]
    if (!first) break
    const time = first.time
    let nextIndex = index
    while (nextIndex < ordered.length) {
      const item = ordered[nextIndex]
      if (!item || item.time !== time) break
      detectedCount += 1
      if (options.matchExecutedAction(item.report)) executedCount += 1
      nextIndex += 1
    }
    points.push({
      label: time === null ? '时间未知' : `${time.toFixed(1)}s`,
      simTimeS: time,
      detectedCount,
      executedCount,
    })
    index = nextIndex
  }

  return points
}
