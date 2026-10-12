import assert from 'node:assert/strict'
import { createJiti } from 'jiti'
const jiti = createJiti(import.meta.url)
const { buildScenarioRequest } = await jiti.import('../src/config/scenarios.ts')
const { eavesStageFromEvidence } = await jiti.import('../src/utils/eavesStage.ts')
for (const family of ['overview','spoofing','fdi','eavesdropping','replay']) {
  assert.equal(buildScenarioRequest(family).flooding_detection_enabled, false)
}
assert.equal(buildScenarioRequest('dos').flooding_detection_enabled, true)
const accounting = frames => ({causal_evidence:{transmissions:frames}})
for (const state of ['RUNNING','PAUSED','COMPLETED']) {
  assert.equal(eavesStageFromEvidence(state, accounting([]), false), 1, 'clock/config cannot prove encryption')
  assert.equal(eavesStageFromEvidence(state, accounting([{packet_type:'SKG_CONTROL'}]), false), 2)
  assert.equal(eavesStageFromEvidence(state, accounting([{packet_type:'TELEMETRY',sensitive:true,encrypted:false,hop_index:0}]), false), 1)
  assert.equal(eavesStageFromEvidence(state, accounting([{packet_type:'TELEMETRY',sensitive:true,encrypted:true,hop_index:0}]), false), 3)
}
assert.equal(eavesStageFromEvidence('INITIALIZED', accounting([{sensitive:true,encrypted:true,hop_index:0}]), false), 0)
assert.equal(eavesStageFromEvidence(undefined, null, false), 0)
assert.equal(eavesStageFromEvidence('COMPLETED', null, true), 4)
console.log('V20 FINAL REVISED: explicit detector scope and evidence-only Eaves progress PASS')
