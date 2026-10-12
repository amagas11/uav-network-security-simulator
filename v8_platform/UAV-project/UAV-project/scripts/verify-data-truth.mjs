import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { createJiti } from 'jiti'

const root = resolve(import.meta.dirname, '..')
const read = (relative) => readFileSync(resolve(root, relative), 'utf8')
const failures = []
const expect = (condition, message) => { if (!condition) failures.push(message) }
const jiti = createJiti(import.meta.url, { alias: { '@': resolve(root, 'src') } })
const {
  accumulateRuntimeEvents,
  createRuntimeCumulativeCounters,
} = await jiti.import('../src/utils/runtimeCounters.ts')
const { buildCumulativeReportSeries } = await jiti.import('../src/utils/reportSeries.ts')
const { formatReportTime } = await jiti.import('../src/utils/runtimeFormat.ts')

function onlineEvent(index, accepted) {
  return {
    event_id: `event-${index}`,
    message_id: null,
    sim_time_s: index / 10,
    event_type: accepted ? 'AUTH_RESULT' : 'RX_SUCCESS',
    observer_node_id: 0,
    observer_role: 'GCS',
    online_features: accepted
      ? { security_state: { application_hmac_result: 'PASS', replay_check_result: 'PASS' } }
      : {},
    availability: {},
    extensions: {},
  }
}

const fullEvents = Array.from({ length: 1641 }, (_, index) => onlineEvent(index, index < 801))
const processed = new Set()
let counters = accumulateRuntimeEvents(createRuntimeCumulativeCounters(), fullEvents, processed)
expect(counters.acceptedTotal === 801, 'run cumulative accepted total must count all 801 events before retention')
expect(fullEvents.slice(-600).length === 600, 'retained event details must remain capped at 600')
counters = accumulateRuntimeEvents(counters, fullEvents, processed)
expect(counters.acceptedTotal === 801, 'a repeated cursor delta must not double-count event IDs')

const refreshed = accumulateRuntimeEvents(createRuntimeCumulativeCounters(), fullEvents, new Set())
expect(refreshed.acceptedTotal === 801, 'cursor=0 refresh bootstrap must rebuild the full accepted total')
const newRun = accumulateRuntimeEvents(createRuntimeCumulativeCounters(), [onlineEvent(0, true)], new Set())
expect(newRun.acceptedTotal === 1, 'a new run must start with a fresh cumulative counter')

function report(index, category = 'AUTH_FAILURE') {
  return {
    report_id: `${category}-${index}`,
    category,
    detection_time_s: 0.2 + index * 0.2,
    source_node_id: 1,
    evidence: { reason: category === 'REPLAY' ? 'DUPLICATE' : 'HMAC_MISMATCH' },
    action_result: { executed: true, request: { action: 'DROP_PACKET' } },
  }
}

function finalCounts(reports, category) {
  const points = buildCumulativeReportSeries({
    reports,
    matchDetection: (item) => item.category === category,
    matchExecutedAction: (item) => item.action_result?.executed === true,
  })
  return points.at(-1)
}

const spoofingReports = Array.from({ length: 10 }, (_, index) => report(index))
const fdiReports = Array.from({ length: 9 }, (_, index) => report(index))
const replayReports = [report(0, 'REPLAY')]
expect(finalCounts(spoofingReports, 'AUTH_FAILURE')?.detectedCount === 10, 'Spoofing trend must end at 10 detections')
expect(finalCounts(spoofingReports, 'AUTH_FAILURE')?.executedCount === 10, 'Spoofing trend must end at 10 executed actions')
expect(finalCounts([...fdiReports].reverse(), 'AUTH_FAILURE')?.detectedCount === 9, 'FDI trend must be order-independent and end at 9')
expect(finalCounts([...fdiReports].reverse(), 'AUTH_FAILURE')?.executedCount === 9, 'FDI executed trend must end at 9')
expect(finalCounts(replayReports, 'REPLAY')?.detectedCount === 1, 'Replay trend must end at one rejection')
expect(finalCounts(replayReports, 'REPLAY')?.executedCount === 1, 'Replay trend must end at one executed drop')
expect(finalCounts([...spoofingReports, spoofingReports[0]], 'AUTH_FAILURE')?.detectedCount === 10, 'duplicate report IDs must not be counted twice')

expect(formatReportTime({ report_id: 'missing-time' }) === '—', 'missing report time must render as an em dash')
expect(formatReportTime({ report_id: 'timed', detection_time_s: 1.2 }) === '1.2s', 'real report time must retain its value')

const store = read('src/stores/simulation.ts')
expect(store.includes('appendRuntimeEvents(view.events)'), 'polling must pass each cursor delta through the independent accumulator')
expect(store.includes('events.value = [...events.value, ...unseen].slice(-600)'), 'retained event details must remain capped after accumulation')
expect(store.includes('processedEventIds'), 'store must deduplicate cumulative events by event_id')
expect(store.includes('uav-sim-v21:runtime-metric-history:'), 'metric samples must be persisted per run in the isolated V21 browser session')
expect(store.includes('readStoredMetricHistory(runId)'), 'refresh must restore browser-session metric samples')
expect(!store.includes('point.hmacRejectedCount'), 'metric history must not masquerade as attack-rejection history')

for (const path of ['src/views/attacks/SpoofingView.vue', 'src/views/attacks/FdiView.vue', 'src/views/attacks/ReplayView.vue']) {
  const source = read(path)
  expect(source.includes('buildCumulativeReportSeries'), `${path} must rebuild attack trends from SecurityReport`)
  expect(!source.includes('store.history'), `${path} must not use metric samples as attack rejection totals`)
}

const table = read('src/components/common/EventTable.vue')
expect(table.includes('最近 ${rows.value.length} 条 / 共 ${props.reports.length} 条'), 'EventTable must disclose displayed and total report counts')
expect(table.includes('检测/上报节点'), 'EventTable source column must name detector/reporter semantics')
expect(table.includes('formatReportTime(report)'), 'EventTable must render unknown time as unavailable')
expect(table.includes("report.action_result?.executed === true) return '已执行'"), 'EventTable success must require executed=true')
expect(table.includes("report.action_result?.executed === false) return '未执行'"), 'EventTable must distinguish an explicit unexecuted action')
expect(table.includes("return '—'"), 'EventTable must keep unknown execution state unavailable')
expect(!table.includes("report.report_type === 'SECURITY_SUMMARY' ? '汇总'"), 'EventTable must not infer execution state from report type')
expect(table.includes('nodeDisplayName(report.source_node_id, nodeRoles)'), 'EventTable must prefer a verified Runtime role label for the reporting node')

const overview = read('src/views/OverviewView.vue')
expect(overview.includes('secondary-unit="条"'), 'Overview mixed units must use a secondary count axis')
expect(!overview.includes('本浏览器会话采样') && read('src/stores/simulation.ts').includes('uav-sim-v21:runtime-metric-history:'), 'Overview removes tooltip while preserving run-scoped session history')

const hmacCard = read('src/components/security/ApplicationHmacCard.vue')
for (const token of ['HMAC-SHA-256-128', '16', 'PER_LEGITIMATE_DEVICE', 'business_payload', '隐藏，不传给前端', 'Trunc128(HMAC-SHA256(K_device, canonical_mac_data))', '设备级独立认证密钥']) {
  expect(hmacCard.includes(token), `HMAC explanation must include ${token}`)
}
expect(!/0x[0-9a-f]{4,}/i.test(hmacCard), 'HMAC explanation must not contain fabricated hexadecimal tags')
expect(!hmacCard.includes('secret key bytes'), 'HMAC explanation must not expose secret key bytes')
expect(hmacCard.includes('actionExecuted === true'), 'HMAC scenario evidence must mark an action executed only from the online action result')

const evaluationPanel = read('src/components/common/AttackEvaluationPanel.vue')
expect(evaluationPanel.includes('攻击 Episode 防御动作数'), 'episode action count must disclose its evaluation scope')
expect(evaluationPanel.includes('仅统计与当前攻击 episode 匹配的已执行动作'), 'episode action count must explain what is excluded')
const dos = read('src/views/attacks/DosView.vue')
expect(dos.includes('Gate丢弃另计'), 'DoS must separate episode actions from HMAC gate drops')
expect(evaluationPanel.includes('dosTarget && familyMetrics') && evaluationPanel.includes('dosTarget.non_target_alarm_count'), 'DoS secondary-alarm details must use real scoped evaluation data')
const replay = read('src/views/attacks/ReplayView.vue')
expect(replay.includes('HMAC 验证完整性，重放规则检查新鲜度与唯一性'), 'Replay must explain why HMAC PASS does not imply freshness without a duplicate banner')
expect(replay.includes('时间戳新鲜度') && replay.includes('会话 / key_epoch') && replay.includes('序列 ReplayWindow'), 'Replay HMAC PASS explanation must preserve the replay-check boundary')

const formalViews = [
  'src/views/OverviewView.vue',
  'src/views/attacks/SpoofingView.vue',
  'src/views/attacks/FdiView.vue',
  'src/views/attacks/DosView.vue',
  'src/views/attacks/EavesdroppingView.vue',
  'src/views/attacks/ReplayView.vue',
]
for (const path of formalViews) {
  const source = read(path)
  for (const forbidden of ['7a2c', '92bf', '800 pkt/s', '420ms', '65ms', '队列占用92%']) {
    expect(!source.includes(forbidden), `${path} must not contain reference-prototype fake value ${forbidden}`)
  }
}

const eaves = read('src/views/attacks/EavesdroppingView.vue')
expect(!eaves.includes('展示里程碑'), 'Eavesdropping must not use presentation milestones as evidence')
expect(eaves.includes('static-crypto-mechanism') && read('src/stores/simulation.ts').includes('eavesStageFromEvidence'), 'Eavesdropping must separate static mechanism from actual transmission progress')

if (failures.length) {
  console.error(`Frontend data-truth checks failed (${failures.length}):`)
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Frontend data-truth checks passed: 600-event retention, run totals, report trends, table semantics, HMAC disclosure, and session history')
