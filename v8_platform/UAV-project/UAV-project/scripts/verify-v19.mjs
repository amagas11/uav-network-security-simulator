import assert from 'node:assert/strict'
import {createJiti} from 'jiti'
import {resolve} from 'node:path'
import fs from 'node:fs'
const jiti=createJiti(import.meta.url,{alias:{'@':resolve(import.meta.dirname,'../src')}})
const {spoofingEvidence,eavesBusinessSets}=await jiti.import('../src/utils/messageEvidence.ts')
const {buildScenarioRequest}=await jiti.import('../src/config/scenarios.ts')
const d=[0,1,2].map(n=>({original:{message_id:'original'+n},copy:{message_id:'copy'+n},capture_time_s:n,modified_time_s:n+.2}))
const c={causal_evidence:{derivations:[d[2],d[0],d[1]],transmissions:d.map((r,n)=>({message_id:r.copy.message_id,sent_time_s:n+.4})),security_observations:d.map((r,n)=>({message_id:r.copy.message_id,event_id:'e'+n}))}}
const reports=d.map((r,n)=>({report_id:'r'+n,category:'AUTH_FAILURE',source_event_ids:['e'+n],action_result:{executed:n!==1}}))
const rows=spoofingEvidence(c,reports)
assert.equal(rows.length,3);assert.deepEqual(rows.map(r=>r.copy.message_id),['copy0','copy1','copy2'])
assert.deepEqual(rows.map(r=>r.report?.report_id),['r0','r1','r2'])
assert.equal(spoofingEvidence(c,[{...reports[0],source_event_ids:['other-family']}])[0].report,null)
assert.equal(spoofingEvidence(null,reports).length,0)
const generations=Array.from({length:23},(_,n)=>({message_id:'b'+n}))
const transmissions=generations.slice(2).flatMap(g=>[{...g,hop_index:0},{...g,hop_index:1}])
const captures=[...generations.slice(4).map(g=>({...g,family:'EAVESDROPPING',sensitive:true,encrypted:true})),...[0,1].map(n=>({message_id:'control'+n,family:'EAVESDROPPING',packet_type:'SKG_CONTROL',sensitive:false,encrypted:false}))]
const sets=eavesBusinessSets({causal_evidence:{generations,transmissions,captures,security_observations:[{extensions:{crypto_send_failure:{withheld_message_ref:'b0',error_code:'KEY_NOT_READY'}}}]}})
assert.equal(sets.generated.size,23);assert.equal(sets.sent.size,21);assert.equal(sets.captured.size,19);assert.equal(sets.controlFrames.length,2)
assert.deepEqual(sets.sentNotCaptured,['b2','b3']);assert.deepEqual(sets.withheld,[{id:'b0',reason:'KEY_NOT_READY'},{id:'b1',reason:'未核实'}])
const requests=[]
for(const key of ['spoofing','fdi','dos','eavesdropping','replay'])for(const duration of [5,10,20,30]){
 const options={simulationDurationS:duration,...(key==='dos'?{floodingRatePps:80,floodingDurationS:duration===5?3.2:duration===10?8:duration===20?12:20}:{})}
 const request=buildScenarioRequest(key,options)
 if(key==='fdi'){assert.equal(request.attack_specs[0].attacker_node_id,-1);assert.equal(request.attack_specs[0].parameters.injection_mode,'CAPTURE_MODIFY_INJECT');assert.deepEqual(request.attack_specs[0].target_link_ids,['link-2-1'])}
 requests.push({name:key+'-'+duration,key,options,request})
}
requests.push({name:'dos-9pps',key:'dos',options:{floodingRatePps:9},request:buildScenarioRequest('dos',{floodingRatePps:9})})
if(process.env.V19_AUDIT_REQUESTS) fs.writeFileSync(process.env.V19_AUDIT_REQUESTS,JSON.stringify(requests,null,2))
console.log('V19 real builders + per-message joins + disjoint business/frame sets PASS')
