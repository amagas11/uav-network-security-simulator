import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createJiti } from 'jiti'
const jiti = createJiti(import.meta.url)
const { buildScenarioRequest, DEFAULT_DURATION_S } = await jiti.import('../src/config/scenarios.ts')
const cases = []
for (const key of ['overview','spoofing','fdi','dos','eavesdropping','replay']) {
  for (const duration of key === 'overview' ? [3.2] : [DEFAULT_DURATION_S[key],5,10,20,30]) {
    const options = { simulationDurationS: duration }
    const request = buildScenarioRequest(key,options)
    assert.equal(request.duration_s,duration)
    for(const t of request.traffic_specs)assert(t.start_s+(t.count-1)*t.interval_s <= duration+1e-9)
    for(const a of request.attack_specs)assert(a.impact_start_s<a.end_s && a.end_s<=duration)
    for(const s of request.session_lifecycle_specs)assert(s.rotate_at_s<duration)
    if(key==='replay')assert.equal(request.traffic_specs[0].count,1)
    else if(duration>DEFAULT_DURATION_S[key])assert(request.traffic_specs[0].count>buildScenarioRequest(key).traffic_specs[0].count)
    cases.push({name:`${key}-${duration}`,key,options,request})
  }
}
for(const subtype of ['DELAYED_REPLAY','OLD_SESSION_REPLAY'])cases.push({name:subtype,key:'replay',options:{replaySubtype:subtype},request:buildScenarioRequest('replay',{replaySubtype:subtype})})
for(const rate of [9,500])cases.push({name:`dos-${rate}pps`,key:'dos',options:{floodingRatePps:rate},request:buildScenarioRequest('dos',{floodingRatePps:rate})})
for(const key of ['spoofing','fdi','dos','eavesdropping','replay']) {
  for(const value of [0,-1,NaN,Infinity,31,3.21])assert.throws(()=>buildScenarioRequest(key,{simulationDurationS:value}))
}
assert.throws(()=>buildScenarioRequest('dos',{simulationDurationS:30,floodingRatePps:500,floodingDurationS:20}),/资源预算/)
assert.throws(()=>buildScenarioRequest('dos',{simulationDurationS:5,floodingDurationS:5}))
assert.throws(()=>buildScenarioRequest('dos',{floodingRatePps:1}))
const output = new URL('../../../../audit/',import.meta.url)
fs.mkdirSync(output,{recursive:true})
fs.writeFileSync(new URL('SCENARIO_REQUESTS.json',output),JSON.stringify(cases,null,2))
console.log(`V17 actual builders: ${cases.length} schedules and invalid-input assertions PASS`)
