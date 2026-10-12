import assert from 'node:assert/strict'
import fs from 'node:fs'
const views=['OverviewView.vue',...['Spoofing','Fdi','Dos','Eavesdropping','Replay'].map(n=>'attacks/'+n+'View.vue')]
const text=views.map(n=>fs.readFileSync(new URL('../src/views/'+n,import.meta.url),'utf8')).join('\n')
for(const phrase of ['只展示已送达 GCS 的在线安全报告。','红色虚线来自已配置的攻击计划，不表示在线定位到攻击节点。','GCS已接收报告累计','攻击副本的实际检测与处置，不表示目标业务已被改变。','应用层防护：监控提升不消除无线拥塞','Eve 是场景设定的监听者，不是在线定位结果。','HMAC → 时间戳 → 会话 → ReplayWindow；拒绝后短路。此处为规则，不是逐步执行记录。','依据当前场景已送达 GCS 的 REPLAY SecurityReport 重建。'])assert(!text.includes(phrase),phrase)
const panel=fs.readFileSync(new URL('../src/components/common/AttackEvaluationPanel.vue',import.meta.url),'utf8')
assert(panel.includes('dos_target_receiver_evaluation'));assert(panel.includes('全网 TP / FP / FN / TN'))
assert(panel.includes("dosTarget.pfa_fpr === null ? 'N/A'"));assert(text.includes('重放检测流程'))
for(const n of ['Spoofing','Fdi'])assert(fs.readFileSync(new URL('../src/views/attacks/'+n+'View.vue',import.meta.url),'utf8').includes('evidence-table'))
console.log('V21: scoped additive target evaluation, N/A, eight removals and retained causal details PASS')
