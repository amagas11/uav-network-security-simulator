import assert from 'node:assert/strict'
import { createJiti } from 'jiti'
const jiti = createJiti(import.meta.url)
const { visibleReportScope } = await jiti.import('../src/utils/reportScope.ts')
const drop = { report_id:'auth',category:'AUTH_FAILURE',action_result:{executed:true,request:{action:'DROP_PACKET'}} }
const monitor = { summary_id:'summary',category:'DOS',count:2,action_result:{executed:true,request:{action:'INCREASE_MONITORING'}} }
const pending = { report_id:'pending',category:'AUTH_FAILURE',action_result:{executed:false,request:{action:'DROP_PACKET'}} }
assert.deepEqual(visibleReportScope([]),{total:0,categories:{},actions:{},executed:0})
const scope = visibleReportScope([drop, monitor, pending, drop])
assert.equal(scope.total,3)
assert.deepEqual(scope.categories,{AUTH_FAILURE:2,DOS:1})
assert.deepEqual(scope.actions,{DROP_PACKET:1,INCREASE_MONITORING:1})
assert.equal(scope.executed,2) // summary count is not expanded into visible executed actions.
assert.deepEqual(visibleReportScope([pending, monitor, drop]),scope)
console.log('V20 FINAL GCS report/summary/action scope, retries, requested-not-executed PASS')
