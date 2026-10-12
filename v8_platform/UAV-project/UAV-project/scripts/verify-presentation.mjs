import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { createJiti } from 'jiti'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from './fixtures/presentation-api.mjs'

const root = resolve(import.meta.dirname, '..')
const jiti = createJiti(import.meta.url, { alias: {
  '@/api': resolve(root, 'scripts/fixtures/presentation-api.mjs'),
  '@': resolve(root, 'src'),
} })
const { useSimulationStore } = await jiti.import('../src/stores/simulation.ts')
const { eavesProtectionPresentation } = await jiti.import('../src/utils/evaluationPresentation.ts')
const { visibleQuadraticPath } = await jiti.import('../src/utils/topologyGeometry.ts')
setActivePinia(createPinia())
const store = useSimulationStore()
const realNow = Date.now
let now = 0, evaluationFailure = 409
Date.now = () => now
const report = { report_id: 'online-1', category: 'AUTH_FAILURE', source_node_id: 1,
  detection_time_s: 0.4, evidence: { reason: 'HMAC_MISMATCH' },
  action_result: { executed: true, request: { action: 'DROP_PACKET' } } }
const event = { event_id: 'event-1', event_type: 'AUTH_RESULT', observer_node_id: 0,
  online_features: { security_state: { application_hmac_result: 'PASS', replay_check_result: 'PASS' } } }
const status = { run_id: 'run-test', state: 'COMPLETED', sim_time_s: 3.2, duration_s: 3.2 }
const metadata = { run_id: status.run_id, attack_plan: [{ attack_family: 'SPOOFING', target_node_ids: [1] }], run_config: {} }
let evaluationCalls = 0
globalThis.__presentationApi = {
  getHealth: async () => ({ status: 'ok' }),
  getCurrentRun: async () => ({ run: status }),
  getRuntime: async () => ({ status: { ...status }, next_cursor: 1, events: [event],
    security_reports: [report], metrics: {}, run_metadata: metadata }),
  getEvaluation: async () => { evaluationCalls++; if (evaluationFailure) throw new ApiError(evaluationFailure);
    return { per_attack_family: {}, episodes: [] } },
}
try {
  assert.equal(store.scenarioStage('SPOOFING'), 0)
  await store.pollRuntime()
  assert.equal(store.status.state, 'COMPLETED')
  assert.equal(store.evaluationState, 'PENDING')
  assert.equal(store.acceptedTotal, 1)
  assert.equal(store.securityReports.length, 1)
  await store.pollRuntime()
  assert.equal(evaluationCalls, 1, 'no 700ms evaluation retry storm')
  now = 5001; evaluationFailure = 500
  await store.pollRuntime()
  assert.equal(store.evaluationState, 'ERROR')
  assert.equal(store.status.run_id, 'run-test')
  assert.equal(store.acceptedTotal, 1)
  assert.equal(store.runtimeConnectionState, 'CONNECTED')
  now = 10002; evaluationFailure = 0
  await store.pollRuntime()
  assert.equal(store.evaluationState, 'READY')
  assert.equal(store.acceptedTotal, 1, 'recovery does not duplicate events')
  assert.equal(store.scenarioStage('SPOOFING'), 4)
  assert.equal(store.scenarioStage('FDI'), 0)
  store.evaluation = null; store.status.state = 'INITIALIZED'
  assert.equal(store.scenarioStage('SPOOFING'), 0)
  store.status.state = 'RUNNING'; store.securityReports = []
  assert.equal(store.scenarioStage('SPOOFING'), 1)
  store.securityReports = [{ ...report, action_result: { executed: false } }]
  assert.equal(store.scenarioStage('SPOOFING'), 2)
  store.securityReports = [report]; store.status.state = 'PAUSED'
  assert.equal(store.scenarioStage('SPOOFING'), 3)
  for (const [lifecycle, evalState, label] of [
    ['INITIALIZED','IDLE','等待启动'], ['RUNNING','IDLE','保密流程运行中'],
    ['PAUSED','IDLE','保密流程已暂停'], ['COMPLETED','PENDING','等待离线评价'],
    ['COMPLETED','ERROR','离线评价暂不可用'],
  ]) assert.equal(eavesProtectionPresentation(true,lifecycle,evalState,null).label,label)
  assert.equal(eavesProtectionPresentation(false,'RUNNING','IDLE',null).tone,'neutral')
  assert.equal(eavesProtectionPresentation(true,'COMPLETED','READY',true).tone,'success')
  assert.equal(eavesProtectionPresentation(true,'COMPLETED','READY',false).tone,'danger')
  const path = visibleQuadraticPath({x:0,y:0},{x:200,y:0},{x:100,y:0})
  assert.equal(path, 'M43 0 Q100 0 157 0')
  console.log('Presentation regression: real Pinia polling, stage, 409/500/recovery, retry interval, dedup, lifecycle and SVG clipping PASS')
} finally { Date.now = realNow; store.stopPolling(); delete globalThis.__presentationApi }
