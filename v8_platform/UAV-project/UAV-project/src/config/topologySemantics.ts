export interface PrimaryBusinessFlow {
  sourceId: number
  targetId: number
}

interface TrafficSpecLike {
  source_node_id?: unknown
  target_node_id?: unknown
}

interface DosEvidenceLike {
  detector_node_id?: unknown
  [key: string]: unknown
}

export interface DosReportLike {
  category?: unknown
  source_node_id?: unknown
  report_id?: unknown
  summary_id?: unknown
  latest_detection_time_s?: unknown
  detection_time_s?: unknown
  event_time_s?: unknown
  evidence?: DosEvidenceLike | null
}

function finiteNodeId(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

/**
 * The primary arrow is a business-flow fact, not a physical-link rendering
 * choice.  It is derived only from the run's configured traffic specs.
 */
export function resolvePrimaryBusinessFlow(
  trafficSpecs: readonly TrafficSpecLike[] | null | undefined,
): PrimaryBusinessFlow | null {
  for (const spec of trafficSpecs ?? []) {
    const sourceId = finiteNodeId(spec.source_node_id)
    const targetId = finiteNodeId(spec.target_node_id)
    if (sourceId !== null && targetId !== null) return { sourceId, targetId }
  }
  return null
}

export function dosDetectorNodeId(report: DosReportLike): number | null {
  const evidenceDetector = finiteNodeId(report.evidence?.detector_node_id)
  if (evidenceDetector !== null) return evidenceDetector
  return finiteNodeId(report.source_node_id)
}

export function filterTargetDosReports<T extends DosReportLike>(
  reports: readonly T[],
  targetNodeId: number | null,
): T[] {
  if (targetNodeId === null) return []
  return reports.filter((report) => (
    String(report.category || '').toUpperCase() === 'DOS'
    && dosDetectorNodeId(report) === targetNodeId
  ))
}

function reportTime(report: DosReportLike): number {
  for (const value of [
    report.latest_detection_time_s,
    report.detection_time_s,
    report.event_time_s,
  ]) {
    const parsed = typeof value === 'number' ? value : Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return Number.NEGATIVE_INFINITY
}

/**
 * Filter by detector provenance before selecting a presentation report.
 * Sorting a copy makes the result independent of the GCS/target report order.
 */
export function selectTargetDosReport<T extends DosReportLike>(
  reports: readonly T[],
  targetNodeId: number | null,
): T | null {
  const matching = filterTargetDosReports(reports, targetNodeId)
  if (!matching.length) return null
  return [...matching].sort((left, right) => {
    const timeDelta = reportTime(right) - reportTime(left)
    if (timeDelta !== 0) return timeDelta
    const leftId = String(left.report_id ?? left.summary_id ?? '')
    const rightId = String(right.report_id ?? right.summary_id ?? '')
    return leftId.localeCompare(rightId)
  })[0] ?? null
}

