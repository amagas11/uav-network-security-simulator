import assert from 'node:assert/strict'
import {createJiti} from 'jiti'
import {resolve} from 'node:path'
const jiti=createJiti(import.meta.url,{alias:{'@':resolve(import.meta.dirname,'../src')}})
const {fdiEvidence}=await jiti.import('../src/utils/fdiEvidence.ts')
const mutation={message_id:'message-1',modified_time_s:.4,original_payload:{altitude_m:100},payload:{altitude_m:100.14}}
const report={report_id:'r1',category:'AUTH_FAILURE',source_event_ids:['auth1'],action_result:{executed:true}}
const accounting={causal_evidence:{mutations:[mutation],security_observations:[{event_id:'auth1',message_id:'message-1'}]}}
assert.equal(fdiEvidence(accounting,[report])[0].report,report)
assert.equal(fdiEvidence(accounting,[{...report,source_event_ids:['different-message']}])[0].report,null)
assert.equal(fdiEvidence(null,[report]).length,0)
assert.equal(fdiEvidence(accounting,[])[0].report,null)
console.log('FDI per-message truth/online join: matched event IDs only, no unrelated latest-report fallback PASS')
