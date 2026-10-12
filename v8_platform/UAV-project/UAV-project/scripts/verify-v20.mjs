import assert from 'node:assert/strict'
import {createJiti} from 'jiti'
const jiti=createJiti(import.meta.url)
const {fdiEvidence}=await jiti.import('../src/utils/fdiEvidence.ts')
const causal={mutations:[{message_id:'copy-2',original_message_id:'original-2',modified_time_s:2},{message_id:'copy-1',original_message_id:'original-1',modified_time_s:1}],
 derivations:[{copy:{message_id:'copy-1'},original:{message_id:'original-1'}}],
 transmissions:[{message_id:'copy-1',sent_time_s:1}],security_observations:[{message_id:'copy-1',event_id:'auth-1'}]}
const report={category:'AUTH_FAILURE',source_event_ids:['auth-1'],action_result:{executed:true,request:{action:'DROP_PACKET'}}}
const rows=fdiEvidence({causal_evidence:causal},[report])
assert.deepEqual(rows.map(r=>r.message_id),['copy-1','copy-2'])
assert.equal(rows[0].derivation.original.message_id,'original-1')
assert.equal(rows[0].report,report)
assert.equal(rows[1].report,null)
assert.equal(rows[1].interception,null)
assert.equal(fdiEvidence(null,[report]).length,0)
console.log('V20 per-copy origin, transmission, online report and waiting isolation PASS')
