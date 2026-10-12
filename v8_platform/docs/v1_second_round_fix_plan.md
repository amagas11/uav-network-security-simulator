# V1 第二轮精准修复计划与完成记录

审计基线：当前工程根目录（唯一修改基线），2026-09-07。原始需求文档 `分工安排.md`、`A_B_无线观测字段说明.md`、`c需求文档.md` 始终只读。本轮顺序为“理解旧行为 → 新增失败测试 → 最小修改 → 局部测试 → 相关模块测试 → 全量回归”。这里的 `IMPLEMENTED` 仅表示已进入 `PlatformRuntime` 等真实路径、需求语义完整且需求级测试通过。

| Issue ID | Requirement Source | Current Behavior（审计时） | Expected Behavior | Affected Files | Acceptance Test | Implementation Status | Final Verification |
|---|---|---|---|---|---|---|---|
| FIX-REPLAY-001 | C §4.1/§5.4；本轮 §3 | 只有泛化 replay；旧 session 会自建窗口；延迟/合法乱序无独立语义 | immediate/delayed/old-session 与 normal reorder 分离；活动 session；窗口按 sender/receiver/session/key epoch 隔离；reset 清空 | `attacks.py`, `security.py`, `runtime.py`, `normal.py`, schema/docs | `test_v1_second_round_replay_fdi.py`：7 个 Replay 场景 | IMPLEMENTED | PASS：默认每计划重放 1 次；same `message_id`、new `event_id`；`DUPLICATE`/`WRONG_SESSION`/合法 `PASS` 均实测 |
| FIX-FDI-001 | 分工 §4；C §4.1/§5.4；本轮 §4 | 缺 abrupt；gradual 每包固定 `+delta`，无独立状态/清理 | 五子型；明文业务值先修改再合法认证；gradual 对当前 baseline 累积；结束/reset/新计划隔离 | `attacks.py`, `runtime.py`, schema/docs | 同文件：5 个 FDI 场景及多项断言 | IMPLEMENTED | PASS：`100 → 105,110,115`；移动 baseline `100,102,104 → 105,112,119`；auth 均 PASS |
| FIX-TRAFFIC-001 | C §3.3/§3.5/§5.3；本轮 §5 | 多个 traffic 字段长期 null | observer-local 可配置窗口；真实 inter-arrival/rates/duplicate/gap/queue/drop/latency/throughput；reset | `traffic.py`, `events.py`, `runtime.py`, schema/docs | `test_v1_second_round_traffic_normal.py`：前 5 项 | IMPLEMENTED | PASS：示例 2 pps、42 B/s、0.4 s inter-arrival、0.119067 ms、0.000336 Mbit/s |
| FIX-TOPO-001 | C §3.5/§9.8；本轮 §7 | 只有初始化更新；节点复制全局 version | link down/up/add/reroute 只刷新相关节点 local view/version 并发事件；无关节点不获知图；路径改变 | `runtime.py`, `network.py`, `security.py` | `test_v1_second_round_topology.py`：3 tests | IMPLEMENTED | PASS：故障/恢复各产生本地更新，2→0 路径可从 `2-1-0` 改为 `2-3-1-0` |
| FIX-NORMAL-001 | C §5.4/§6.5/§9.6；本轮 §6 | 无可配置 attack-like normal controls | low-SNR/loss/burst/out-of-order/state-change/congestion 走真实路径，永不创建攻击 label | `normal.py`, `phy.py`, `runtime.py`, API/schema/docs | traffic/normal 文件后 4 项 + API test | IMPLEMENTED | PASS：高合法速率、低 SNR、自然丢包、乱序、状态/拥塞均无 attack label |
| FIX-RL-001 | C §6；本轮 §8 | reset/step 外壳存在但 state/outcome 语义不足 | 2 s/5 s、PHY trend、security/model/node/defense/resource、availability；主要本地业务值可计算；无 truth/reward | `rl.py`, `runtime.py`, `traffic.py`, API/docs | `test_v1_second_round_rl_evaluation.py`：前 4 tests + API readonly | IMPLEMENTED（B 环境） | PASS：模型缺失为 UNAVAILABLE/null；动作改变 state；throughput/latency 非 null；训练/奖励仍属 C |
| FIX-EVAL-001 | 分工 §7.8；C §4/§6；本轮 §9 | 按 alarm 数量算混淆矩阵；重复正确告警成为 FP；TN 依赖 NORMAL prediction；executed 等同 effective | episode TP/FN + 每 family 正常窗口 FP/TN；重复 alarm 单列；分离 detection/action/report/recovery；真实效果与服务损伤 | `evaluation.py`, `runtime.py`, `reporting.py`, docs | RL/evaluation 文件后 8 tests | IMPLEMENTED | PASS：样例 TP=1/FP=1/FN=0/TN=2，重复告警=1；完全 normal 和 wrong-family FP 均覆盖 |
| FIX-RFF-001 | C §3.4/§7；本轮 §10 | 无 event RF ref；manifest 缺 5 个字段仍 valid | nullable、hop-local `rf_sample_ref`；非空引用必须存在；18 字段、类型、UTC、路径严格验证 | `events.py`, `runtime.py`, `validation.py`, schema/docs | `test_v1_second_round_contracts.py`：前 6 tests | IMPLEMENTED（数据契约） | PASS：完整 fixture valid；缺字段/坏类型/越界路径/悬空引用 invalid；Follower sample 不冒充 GCS hop |
| FIX-REDUNDANCY-001 | 分工 §3.2.7；本轮 §11 | 类和直接单测存在，runtime 未使用 | 安全决策经 3 个逻辑副本、裁决、health degrade、switch/recovery event | `redundancy.py`, `runtime.py`, docs | `test_v1_second_round_runtime_integration.py`：2 tests | IMPLEMENTED（logical baseline） | PASS：1 个 inconsistent/raising replica 时仍 CONSENSUS=SPOOFING，并依次记录 degraded/recovered |
| FIX-AUTHZ-001 | 分工 §3.2.8；本轮 §12 | authorizer 未接生命周期 | start/init、join、sensitive command 都授权；copy profile 阻止 ACTIVE/入网/执行；不记录 credential/key | `domain.py`, `terminal.py`, `runtime.py`, docs | runtime integration：3 tests | IMPLEMENTED（仿真行为） | PASS：默认节点 ACTIVE；copy 为 AUTHORIZATION_DENIED 且 message rejected；变更 profile 后命令不执行 |
| FIX-REKEY-001 | 分工 §3.1/§3.2.5；本轮 §13 | executor 无条件 `key_epoch += 1` | `KeyProvider.request_rekey` 返回 success/failure/new epoch/state transition/reason；mock 明示 TEST ONLY | `adapters.py`, `security.py`, `runtime.py`, API/docs | runtime integration：2 tests | IMPLEMENTED（adapter semantics） | PASS：成功 `1→2`，状态 AVAILABLE→UPDATING→AVAILABLE；失败 epoch 不变且返回原因 |
| FIX-PROBE-001 | A/B 字段 §1–§3；本轮 §14 | 双端 measurement 不复制，但 SNR 复制 forward 值 | 每端从本地 measurement 与本地 receiver noise 独立推导 SNR；不可用时 null | `probe.py`, schema/docs | contracts：2 tests | IMPLEMENTED | PASS：measurement 相关但不相同、noise variance 和 SNR 均不同；非直邻全为 explicit missing |
| FIX-CAL-001 | 分工 §3.2.1；C §2.3；本轮 §15 | 注入 profile 后 provenance version 仍 null | baseline 诚实 simulation；加载 profile 写 dataset/calibration/channel profile version | `simulation.py`, `calibration.py`, `runtime.py`, schema/docs | contracts：synthetic provenance fixture + 原 baseline tests | IMPLEMENTED（provenance） | PASS：synthetic metadata 保存 `fixture-v2`/`synthetic-cal-v2`，未冒充真实校准 |
| FIX-SCHEMA-001 | C §2–§4/§7/§8/§12；本轮 §16 | schema 只列顶层枚举和单位 | runs/events/labels/rf/model/LocalPhyObservation/nested features 字段级 name/type/required/nullable/unit/enum/semantic | `dataset.py`, `dataset/schema.json`, `validation.py`, docs | contracts schema test + export validation | IMPLEMENTED | PASS：13 个对象定义；代码读取与磁盘 contract 完全一致；validator 拒绝非 frozen schema |
| FIX-LEADER-001 | 分工 §3.2.6；本轮 §17 | Leader 原样 forwarding | 按 source/category/severity/窗口聚合；紧急旁路；保留 evidence；断链缓存/恢复上传 | `reporting.py`, `runtime.py`, docs | `test_v1_second_round_reporting_e2e.py`：前 3 tests | IMPLEMENTED | PASS：多报告汇总 count≥2；两跳 TX；紧急旁路；Leader-GCS 断链缓存后上传且 report delay>0 |

## 失败测试证据

在实现修改前，新增 Replay/FDI 测试首轮为 `8 failed, 4 passed`；其余当时可收集的新测试为 `28 failed, 2 passed`，normal 模块尚不存在的测试在 collection 阶段失败。这些失败分别暴露了不支持的新子型、无 drift 历史、无动态拓扑 API、RL/evaluator 语义缺失、RF 校验过松、冗余/授权/rekey 未接 runtime 等问题。随后新增的“完全正常运行 false alarm”和 normal/RL REST 路径测试也先分别以缺 family 结果与 HTTP 404 失败，再修改实现。

## 最终分层验证

- L1 Unit：ReplayWindow、FDI state、traffic accumulator、manifest/schema、probe、evaluator。
- L2 Integration：runtime/network/security/rekey/redundancy/terminal/reporting。
- L3 Acceptance：第二轮新增 58 tests；各 FIX-ID 均有需求级断言，detector 不读取 label/truth。
- L4 Regression：全量 `119 passed`；coverage 87%；dataset batch/validator、API readonly、前端 type-check/build 通过。

## 外部边界

A 正式 SKG、C 的 BiLSTM/Dueling-Q/RFF 模型与权重、真实 RF IQ、真实无线测量校准继续为 `INTERFACE_READY`/`BLOCKED_EXTERNAL`。这些内容没有用 mock、随机 placeholder 或 synthetic metadata 冒充完成。
