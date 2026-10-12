import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { createJiti } from 'jiti'

const root = resolve(import.meta.dirname, '..')
const read = (relative) => readFileSync(resolve(root, relative), 'utf8')
const failures = []
const expect = (condition, message) => { if (!condition) failures.push(message) }
const jiti = createJiti(import.meta.url)
const { buildSemanticLayout } = await jiti.import('../src/config/topologyLayouts.ts')
const {
  resolvePrimaryBusinessFlow,
  selectTargetDosReport,
} = await jiti.import('../src/config/topologySemantics.ts')

const chart = read('src/components/charts/TimeSeriesChart.vue')
expect(chart.includes('<div ref="root" class="time-chart">'), 'chart container must always exist')
expect(!chart.includes('v-if="hasData" ref="root"'), 'chart container must not be gated by hasData')
expect(chart.includes('echarts.getInstanceByDom'), 'chart must reuse an existing ECharts instance')
expect(chart.includes('resizeObserver?.disconnect()'), 'chart ResizeObserver must be disposed')

const topology = read('src/components/topology/ScenarioTopology.vue')
const topologyNode = read('src/components/topology/TopologyNode.vue')
const topologyLayouts = read('src/config/topologyLayouts.ts')
expect(topology.includes("type TopologyMode"), 'topology must be driven by an explicit scenario mode')
expect(topology.includes("mode === 'fdi' && !externalFdi && primaryGeometry"), 'legacy FDI topology must retain its in-link injection marker')
expect(topology.includes("mode === 'dos' && floodPackets.length"), 'DoS topology must render a packet-flood visual on the real attack path')
expect(topology.includes("!props.showTruth") && topology.includes("['spoofing', 'replay', 'eavesdropping']"), 'Eavesdropping topology must gate passive truth evidence')
expect(topology.includes('passiveGeometry'), 'Eavesdropping topology must use a passive intercept edge')
expect(topology.includes("mode === 'replay'"), 'Replay topology must render legal and replay paths')
expect(topology.includes('class="normal-edge primary primary-business-flow"'), 'attack topologies must render an explicit primary business-flow edge')
expect(topology.includes(':data-source-id="layout.primaryFlow.sourceId"'), 'primary business-flow source must be inspectable from Runtime traffic metadata')
expect(topology.includes(':data-logical-target-id="layout.primaryFlow.targetId"'), 'logical business-flow target must be inspectable separately from the controlled relay physical hop')
expect(topology.includes(':marker-end="`url(#${markerPrefix}-blue-arrow)`"'), 'primary-flow marker must terminate at the target end of the SVG path')
expect(topology.includes('selectTargetDosReport(props.reports, layout.value.targetId)'), 'DoS topology must select evidence by configured attack target')
expect(topology.includes('节点位置用于展示通信关系，不按实际物理距离比例绘制'), 'topology must disclose semantic, non-GIS layout')
expect(topologyNode.includes('drone-icon') && topologyNode.includes('station-icon'), 'topology nodes must use role-specific UAV/GCS symbols')
expect(!topologyNode.includes('DISARMED'), 'device arm state must not dominate topology labels')
expect(topologyLayouts.includes('addRow(leaders, spread(leaders.length, 310, 450), 75)'), 'overview leaders must occupy the upper semantic tier')
expect(topologyLayouts.includes('addRow(followers, spread(followers.length, 120, followerEnd), 185)'), 'overview followers must fan out below leaders')
expect(topologyLayouts.includes('addRow(ground, spread(ground.length, 250, 510), 306)'), 'GCS/real ground nodes must occupy the ground tier')
expect(topologyLayouts.includes("mode !== 'fdi'"), 'FDI layout must not create a separate attacker node')
for (const fakeEntity of ["'SRV'", "'UAV-03'", "'ATK-G'"]) {
  expect(!topologyLayouts.includes(fakeEntity), `semantic layout must not invent reference-prototype entity ${fakeEntity}`)
}

const familyViews = {
  SPOOFING: 'src/views/attacks/SpoofingView.vue',
  FDI: 'src/views/attacks/FdiView.vue',
  DOS: 'src/views/attacks/DosView.vue',
  EAVESDROPPING: 'src/views/attacks/EavesdroppingView.vue',
  REPLAY: 'src/views/attacks/ReplayView.vue',
}
for (const [family, path] of Object.entries(familyViews)) {
  const source = read(path)
  expect(source.includes(`store.isRunFor('${family}')`), `${path} must gate Runtime data by ${family}`)
  expect(source.includes(`store.scenarioStage('${family}')`), `${path} must use a family-scoped stage`)
  expect(source.includes('ScenarioContextNotice'), `${path} must show mismatched-run context`)
  expect(!source.includes(':current="store.stage"'), `${path} must not use the global stage`)
  expect(source.includes(`:primary-flow="store.primaryBusinessFlowFor('${family}')"`), `${path} must pass the real directed traffic flow into the topology`)
}

const requiredModes = {
  SPOOFING: 'spoofing', FDI: 'fdi', DOS: 'dos', EAVESDROPPING: 'eavesdropping', REPLAY: 'replay',
}
for (const [family, mode] of Object.entries(requiredModes)) {
  expect(read(familyViews[family]).includes(`mode=\"${mode}\"`), `${family} page must select its semantic topology mode`)
}
expect(read('src/views/OverviewView.vue').includes('mode="overview"'), 'overview must select the formation topology mode')
expect(!read('src/views/OverviewView.vue').includes(':primary-flow='), 'overview connectivity must remain independent of a single directed business flow')

const topologyNodes = [
  { id: -1, role: 'EXTERNAL', state: 'READY', pos: [0, 0, 0] },
  { id: 0, role: 'GCS', state: 'READY', pos: [0, 0, 0] },
  { id: 1, role: 'LEADER', state: 'READY', pos: [0, 0, 0] },
  { id: 2, role: 'FOLLOWER', state: 'READY', pos: [0, 0, 0] },
]
const forwardFirstLinks = [
  { id: 'link-1-2', src: 1, dst: 2, status: 'active' },
  { id: 'link-2-1', src: 2, dst: 1, status: 'active' },
]
const reverseFirstLinks = [...forwardFirstLinks].reverse()
const fdiPlan = {
  attack_family: 'FDI', attack_subtype: 'TELEMETRY_ABRUPT_CHANGE',
  start_s: 0, impact_start_s: 0.2, end_s: 1, attacker_node_id: null,
  target_node_ids: [1], target_link_ids: [], intensity: {},
}
const realTrafficFlow = resolvePrimaryBusinessFlow([{ source_node_id: 2, target_node_id: 1 }])
expect(realTrafficFlow?.sourceId === 2 && realTrafficFlow?.targetId === 1, 'traffic metadata must resolve the directed primary flow as 2 -> 1')
for (const links of [forwardFirstLinks, reverseFirstLinks]) {
  const fdiLayout = buildSemanticLayout('fdi', topologyNodes, links, fdiPlan, realTrafficFlow)
  expect(fdiLayout.primaryFlow?.sourceId === 2 && fdiLayout.primaryFlow?.targetId === 1, 'bidirectional physical-link order must not reverse the FDI primary flow')
}

const gcsSecondaryDos = {
  report_id: 'report-gcs-secondary', category: 'DOS', source_node_id: 0,
  evidence: { observed_packet_rate_pps: 8, flooding_threshold_pps: 8 },
}
const targetReceiverDos = {
  report_id: 'summary-target-receiver', category: 'DOS', source_node_id: 1,
  evidence: { detector_node_id: 1, observed_packet_rate_pps: 8, flooding_threshold_pps: 8 },
}
for (const reports of [[gcsSecondaryDos, targetReceiverDos], [targetReceiverDos, gcsSecondaryDos]]) {
  const selected = selectTargetDosReport(reports, 1)
  expect(selected?.report_id === 'summary-target-receiver', 'DoS evidence selection must remain target-scoped when report order changes')
}

const store = read('src/stores/simulation.ts')
expect(store.includes('activeRunFamilies'), 'store must derive active families from run metadata')
expect(store.includes('reportsForFamily'), 'store must expose family-scoped reports')
expect(store.includes('episodeForFamily'), 'store must expose family-scoped episodes')
expect(store.includes('seenDosReportKeys'), 'DOS alarm-window reports must be deduplicated')
expect(store.includes("RuntimeConnectionState = 'UNKNOWN' | 'CONNECTED' | 'DISCONNECTED'"), 'store must expose a real Runtime connection state')
expect(store.includes('consecutiveConnectionFailures'), 'Runtime disconnect must require consecutive transport failures')
expect(store.includes("cause instanceof ApiError"), 'HTTP business errors must still prove Runtime connectivity')
expect(store.includes('await getCurrentRun()'), 'idle bootstrap must use the non-error current-run endpoint')
expect(store.includes('await getHealth()'), 'business/proxy errors must be resolved with an explicit health probe')
expect(store.includes("targetNodeForFamily('DOS')"), 'DOS alarm history must be scoped to the configured target receiver')
expect(store.includes('detector_node_id ?? report.source_node_id'), 'DOS history must use real detector provenance')

const controls = read('src/components/common/RunControls.vue')
expect(controls.includes('ownsActiveRun'), 'attack-page controls must own only their family run')
expect(controls.includes('!canPauseOrResume'), 'pause/resume must be disabled outside the page family')
expect(controls.includes('!canReset'), 'reset must be disabled outside the page family')
expect(controls.includes('window.confirm'), 'scenario replacement must require explicit confirmation')
expect(controls.includes('本页不会暂停或重置其他场景'), 'mismatched controls must explain their scope')

const scenarios = read('src/config/scenarios.ts')
expect(scenarios.includes('DEMO_NON_DOS_FLOODING_THRESHOLD_PPS = 12'), 'non-DoS demo threshold must be 12 pps')
expect(scenarios.includes('DEMO_DOS_FLOODING_THRESHOLD_PPS = 8'), 'DoS demo threshold must remain 8 pps')
expect(scenarios.includes("parameters = { delay_s: 0.8 }"), 'delayed Replay must retain a target-visible stale frame')
expect(scenarios.includes('request.replay_timestamp_freshness_s = 0.5'), 'delayed Replay freshness must not reject its own report path')

const dos = read(familyViews.DOS)
expect(dos.includes('首次告警触发速率') && dos.includes('目标接收端峰值窗口速率'), 'DoS must distinguish initial alarm and actual receiver load')
expect(dos.includes('source-label source-offline'), 'DoS defense evidence must be marked offline')
expect(dos.includes('targetDosReports'), 'DoS primary event table must be target-detector scoped')
expect(dos.includes(':reports="targetDosReports"'), 'DoS topology must receive only target-receiver DOS evidence')
expect(dos.includes('filterTargetDosReports'), 'DoS view must filter evidence by detector provenance before presentation')
expect(dos.includes('selectTargetDosReport'), 'DoS latest evidence selection must be independent of report array order')
expect(dos.includes('hmacReports'), 'DoS must summarize HMAC ingress rejection separately')
expect(dos.includes('下一次启动参数'), 'DoS editable values must be labeled as next-launch parameters')
expect(dos.includes('hydratedRunId'), 'DoS controls must hydrate from current run metadata after refresh')

const spoofing = read(familyViews.SPOOFING)
expect(spoofing.includes(':class="{ danger: detectionConfirmed }"'), 'Spoofing detection must become danger only after online evidence exists')
expect(spoofing.includes(':class="{ success: defenseExecuted }"'), 'Spoofing defense must become success only after executed=true')
expect(spoofing.includes("'等待在线检测证据'"), 'Spoofing must expose a neutral detection waiting state')
expect(spoofing.includes("'等待安全处置'"), 'Spoofing must expose a neutral defense waiting state')
expect(!spoofing.includes('class="mechanism-node success"><strong>{{ latestReport'), 'Spoofing must not use a static success class for pending defense')

const fdi = read(familyViews.FDI)
expect(fdi.includes(':class="{ danger: detectionConfirmed }"'), 'FDI detection must become danger only after online evidence exists')
expect(fdi.includes(':class="{ success: defenseExecuted }"'), 'FDI defense must become success only after executed=true')
expect(fdi.includes("'等待在线检测证据'"), 'FDI must expose a neutral detection waiting state')
expect(fdi.includes("'等待安全处置'"), 'FDI must expose a neutral defense waiting state')
expect(!fdi.includes('class="mechanism-node success"><strong>{{ authReport'), 'FDI must not use a static success class for pending defense')

const replay = read(familyViews.REPLAY)
expect(!replay.includes('currentEpisode'), 'Replay online evidence must not fall back to evaluation episode')
expect(replay.includes('latestReplayEvent'), 'Replay online reason must come from Runtime events/reports')
expect(replay.includes('latestReport.value?.evidence?.application_hmac_result'), 'Replay HMAC result must prefer online SecurityReport evidence')
expect(replay.includes('latestReport.value?.evidence?.sequence_no'), 'Replay must display the real online sequence number')
expect(replay.includes('hydratedRunId'), 'Replay subtype must hydrate from current run metadata after refresh')
expect(replay.includes('下一次启动参数'), 'Replay selector must state next-launch semantics')

const eaves = read(familyViews.EAVESDROPPING)
expect(eaves.includes('eavesProtectionPresentation'), 'Eavesdropping must use lifecycle-aware neutral pending/error presentation (behaviour verified by verify-presentation)')
expect(eaves.includes("scenarioStage('EAVESDROPPING')"), 'Eavesdropping must use its dedicated stage semantics')
expect(!eaves.includes('TimeSeriesChart'), 'Eavesdropping final protection result must not be rendered as a single-point line chart')
for (const label of ['密文保护数量', '明文暴露数量', '内容恢复数量', '保密保护结果', '评价窗口解码接收成功率']) {
  expect(eaves.includes(label), `Eavesdropping result cards must include ${label}`)
}

const sidebar = read('src/components/common/Sidebar.vue')
expect(sidebar.includes('无人机网络攻防仿真平台'), 'Sidebar must use the formal Chinese project name')
expect(sidebar.includes('store.runtimeConnectionState'), 'Sidebar status must be driven by the Runtime connection state')
expect(!sidebar.includes('无随机图表 · 无硬编码结果'), 'Sidebar must not display developer verification copy')

const evaluation = read('src/components/common/AttackEvaluationPanel.vue')
expect(evaluation.includes('{{ props.family }}'), 'empty evaluation state must name the requested family')
expect(evaluation.includes('store.isRunFor(props.family)'), 'evaluation must be gated by the active run family')
expect(evaluation.includes('攻击 Episode 防御动作数'), 'evaluation action count must disclose episode scope')

const eventTable = read('src/components/common/EventTable.vue')
expect(eventTable.includes('报告ID'), 'security event table must use a precise report-id header')
expect(eventTable.includes('执行状态'), 'security event table must label action execution precisely')
expect(eventTable.includes('nodeDisplayName(report.source_node_id, nodeRoles)'), 'security event table must map reporting nodes through Runtime roles')
expect(!eventTable.includes("report.report_type === 'SECURITY_SUMMARY'"), 'security summary type must not masquerade as an execution state')

const formalVisibleFiles = [
  'src/views/OverviewView.vue',
  ...Object.values(familyViews),
  'src/components/common/AttackEvaluationPanel.vue',
]
for (const path of formalVisibleFiles) {
  const source = read(path)
  for (const internalCopy of ['/api/runtime', '/api/evaluation', 'CreateRunRequest', 'acceptance 已验证', 'GROUND_TRUTH_OFFLINE_EVALUATION']) {
    expect(!source.includes(internalCopy), `${path} must not expose internal implementation copy: ${internalCopy}`)
  }
}

const router = read('src/router/index.ts')
for (const legacyName of ['Dashboard', 'HomeView', 'AttackControl', 'Assessment', 'Main.vue', 'Map.vue']) {
  expect(!router.includes(legacyName), `formal router must not import legacy surface: ${legacyName}`)
}

if (failures.length) {
  console.error(`Frontend closure checks failed (${failures.length}):`)
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log(`Frontend closure checks passed: directed topology + target DoS evidence + chart lifecycle + ${Object.keys(familyViews).length} family views + truth/evaluation boundaries`)
