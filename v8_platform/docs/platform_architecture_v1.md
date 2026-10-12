# 平台架构（V10 五类攻击 HMAC Closure；文件名兼容保留）

## 设计边界

平台 B 提供仿真世界、逐跳网络、PHY、攻击、规则、防御、报告、数据、RL 环境、API/UI 与 A/C 接入点；不实现 A 的正式 SKG/密钥算法，不训练 C 的 BiLSTM、Dueling Q 或 RFF，不伪造真实数据、IQ 或校准结果。

## 在线链路

```text
Scenario/RunConfig
  -> SimulationClock + RunContext + deterministic RNG streams
  -> role-aware TrafficService
  -> per-device application HMAC
  -> post-HMAC attack mutation hook (FDI / identity-only Spoofing)
  -> optional KeyProvider/CryptoProvider adapter (Eavesdropping AES profile)
  -> route + per-hop TX queue
  -> persistent direct-link PHY
  -> per-hop RX_SUCCESS/RX_FAILURE + forwarding queue
  -> receiver-total arrival statistics (before HMAC gate)
  -> crypto open -> application HMAC -> timestamp/session/ReplayWindow
  -> authenticated forwarding/business handler
  -> append event store -> OnlineEventDispatcher -> SafeModelAdapterRunner -> subscribed ModelAdapter
  -> node-local RuleEngine + model results
  -> B-owned DecisionFusion (status/quality/confidence/rule priority/permission)
  -> 3-replica logical decision + adjudication/health
  -> authorized DefenseExecutor
  -> correlated SecurityOutcomeReport -> local result/cache
  -> Leader emergency bypass or window aggregation
  -> GCS received/runtime view
```

`events.jsonl` 只来自每个 observer 当时真实可见的数据。`GCS` 对象不是 `SimulationManager` 的别名；断链期间未成功上报的信息只能留在节点本地缓存。

## 离线真值链路

```text
AttackPlan + simulator physical truth
  -> labels.jsonl
  -> ExperimentEvaluator(events/results + labels)
  -> Offline Evaluation API/View
```

在线 `RuleEngine` 和 `ModelAdapter` 不持有 label store 引用。真实发射机、攻击类型、原值、攻击引擎干扰功率和未来结果不进入 `online_features`。

## A 接口链路

```text
direct neighboring persistent PHY
  -> ProbeService(common reciprocal latent channel)
  -> terminal A local observation + independent receiver noise A
  -> terminal B local observation + independent receiver noise B
  -> LocalPhyObservation
  -> external A KeyProvider
```

当前 A probe baseline 仅输出 `rssi_dbm` 序列；missing 为 `true` 时 `measurement=null`，不补零、不伪造 CSI。Mock key/crypto 仅用于平台联调并明确 `TEST_ONLY_NOT_SKG`。

## C 接口链路

- 连续 schema 3.2 events + 独立 labels + 完整 requested/resolved/provider/model/calibration/readiness provenance runs + 空/真实来源可核验的 RF manifest。
- `ModelAdapter.reset/observe/health`；外部调用统一经过 bounded exception/timeout boundary。模型缺失、异常或超时返回明确 `UNAVAILABLE/ERROR` 与 null prediction，确定性规则继续运行。
- RL environment 返回 observer 的 recent 2 s/5 s、PHY trend、security/model/node/defense/resource 与 availability；明文相关状态只使用本地 sensitive/encrypted protection risk，不使用 eavesdrop capture truth；建议动作与部署模型共用 `DecisionFusion`、认证门控、target resolver 和 `DefenseExecutor`，平台不硬编码 reward weights。

## V2–V7 收敛运行语义

- Replay 使用同 epoch 多活动业务 session，并按 immediate sender/receiver/source namespace/business session/key epoch 隔离 watermark/seen window；显式 stale/key rotation 生命周期保留 OLD_SESSION，immediate、delayed 与合法乱序是不同路径。
- `RunConfig.attack_specs`/`normal_disturbance_specs` 是 RL/batch 的正式 episode plan 入口；完整配置和计划写入 runs，semantic fingerprint 覆盖所有实验语义。
- RL `step` 在 action 后推进 `decision_step_s`，再以真实事件/队列差分生成闭环 outcome；phase 不进入在线 state。
- OnlineEventDispatcher 统一将已存储事件按 adapter subscription 分发，并防止 MODEL_RESULT 自反馈递归。
- C 模型 detection 及其 fusion/defense outcome 使用同一 correlation/dedup reporting hook，沿真实 Leader→GCS 链路上报；断链时缓存，恢复后以真实 received time 计算 delay。
- Compromised-node FDI 在原始 business payload 已生成 application HMAC 后修改 payload，
  不重算 tag；接收端 HMAC mismatch 后 DROP/NO_UPDATE。gradual drift 仍是每 AttackPlan
  独立的累积 mutation truth。
- 六类 normal disturbance 进入真实 PHY/traffic/node/topology 路径但不创建攻击 label。
- link failure/recovery/reroute 只刷新相关 observer 的 local topology view，并产生新的 `TOPOLOGY_UPDATE`。
- terminal authorization 覆盖 program start、network join 和 sensitive command；rekey 只能经 `KeyProvider.request_rekey`。
- RF sample ref 仅属于当前 receiver/current hop；Leader 携带的上游 RFF 结果不会伪装成 GCS PHY 观测。
- Offline evaluator 以 attack episode 和 fixed normal window 为单位；重复正确告警单列，action executed 与 defense effective 分离。
- Flooding message truth 分离 generated/queued/affected/backlogged；只有实际进入 event chain 的 message 才能进入 affected refs，绝不为 backlog 伪造 TX。
- Flooding 与 normal burst 共用普通业务 packet type；normal/attack scenario 名称不进入在线字段，recursive leakage scanner 是 dataset gate。
- FDI attacker 是 compromised origin，target 是 business receiver；两者不再要求相等或包含。
- `AttackEpisodeScope` 按 target node/link/message/observer/evidence 约束 detection、defense、service recovery 和 report attribution。
- OLD_SESSION 由正常 session rotation/rekey 生命周期形成 stale context，AttackEngine 不能修改 detector 内部状态。
- RFF prediction 写入 observer-local security/RL state；模型 recommended action 必须经 B 的 `DecisionFusion` 和 `DefenseExecutor`。
- runs 明示 dataset maturity 和 key/crypto/terminal provider provenance；built-in mock provider 不能产出 FORMAL dataset。
- `DefenseTargetResolver` 只使用本地认证/物理证据，分离 claimed source、authenticated peer、direct link、flow/session；identity-sensitive model action 在 AUTH 前只可 defer/窄范围降级，不能隔离被冒充的合法身份。
- Flooding 与 normal burst 共用 `BusinessPacketTemplate` 和 canonical serialized application-byte size；packet type、payload key 或固定 size 都不能成为标签捷径。
- 攻击 outcome 冻结为 attempted/injected/reached target/malicious content executed/mission impact/effective；injection 不等于 target-side effective。
- V5 attack episode 明确为 single-target；多目标 fail fast。runtime 在 schedule 阶段建立并导出 requested/resolved plans；复合影响的 contributing IDs 只进入离线 truth。
- RFF local state 是 AUTH/PHY/QUEUE/RL snapshot 的单一来源；未测 communication/compute overhead 使用 null + availability，而不是 0。
- `ScenarioOrchestrator` 统一调度 strict business traffic 与合法 session lifecycle；FDI 在 eligible packet queue 前已激活，direct runtime、batch、FastAPI 和 RL reset 共用同一 RunConfig 语义。
- `ScenarioMechanismValidator` 是离线验收组件：每个正式场景必须同时通过数据合同和 subtype-specific 机制证据，label/schema valid 不再足以放行。
- online session/link/probe/flow ID 为 run-scoped opaque token，端点映射只保存在 offline provenance；EXTERNAL observer 默认不进入 C 模型 dispatcher，也不会产生模型驱动防御。
- `BusinessApplyResult` 将 packet delivery 与业务 accepted/executed/state changed 分离；攻击 outcome 和共享 `MissionImpactEvaluator` 只使用真实 target-side apply/service evidence。
- evaluator 保留 NODE/LINK/MESSAGE/FLOW/COMPOSITE typed scope；当前 DoS 攻击只支持
  receiver-node-scope FLOODING，通用 link scope 仍供 PHY/topology/normal evidence 使用。
- Eavesdropping 冻结为 nonsensitive plaintext control、sensitive ciphertext protection 与 sensitive plaintext-exposure 三类；非敏感普通明文被捕获也不算 exposure。
- `BaselineCalibrationFitter` 将有 license/hash/version 的 normalized measurements 拟合为 descriptive targets 与明确 runtime controls；RSSI/SNR bias、background loss、latency base/jitter 进入真实 PHY，`RuntimeCalibrationValidator` 从实际事件比较 source/runtime。throughput target 当前明确为 descriptive-only。
- `RuntimeDependencies`/`PlatformRuntimeFactory` 为 Manager/FastAPI/Batch/RL 创建 fresh A/C providers/models；Manager reset 保留 calibration/factory 而清空 run state，model timeout capacity 只属于当前 runtime。
- run-level `model_assets` 不依赖 MODEL_RESULT；分层 readiness 将 B 软件、dataset、A/C asset 与 final formal experiment 分开，缺任何正式 C model 时 final experiment 不得 READY。
- Schema 2.x 缺少 V7 可恢复语义时，migration CLI 生成 hashed incompatibility report 并拒绝迁移，不伪造 3.2 数据。
- attack/normal subtype 参数为严格合同，未知、类型错误、越界或未支持 multi-target 配置在所有正式入口 fail fast。

## 模块边界

| Module | Responsibility |
|---|---|
| `swarm_sim/simulation.py` | clock, scheduler, run config/context, deterministic IDs/RNG |
| `swarm_sim/domain.py` | roles, packets/messages, node-local state |
| `swarm_sim/packets.py` | shared business payload template and canonical application-byte sizing |
| `swarm_sim/network.py` | directed topology, route, bounded TX/RX/forward queues |
| `swarm_sim/phy.py` | persistent direct-link state and receiver observations |
| `swarm_sim/probe.py` | A-side reciprocal local probe observations |
| `swarm_sim/attacks.py` | AttackPlan/Scheduler and attack effects/truth |
| `swarm_sim/normal.py` | configurable attack-like normal disturbances without labels |
| `swarm_sim/scenario.py` | strict config-driven business traffic and legitimate session rotation shared by all entrypoints |
| `swarm_sim/scenario_validation.py` | offline subtype-specific mechanism acceptance gate |
| `swarm_sim/traffic.py` | observer-local rolling rates/gaps/queues/latency/throughput |
| `swarm_sim/security.py` | local deterministic rules and authorized defense execution |
| `swarm_sim/reporting.py` | local cache, Leader aggregation/emergency bypass, legal multi-hop upload, GCS inbox |
| `swarm_sim/events.py` | schema-3.2 runtime event construction and truth boundary |
| `swarm_sim/leakage.py` | online truth/literal and hard-negative structural leakage audit |
| `swarm_sim/dispatch.py` | unified online event subscription and recursion guard |
| `swarm_sim/model_runtime.py` | runtime-owned bounded external model reset/observe/health exception and inference-timeout boundary |
| `swarm_sim/decision.py` | trusted defense target resolution, auth gate, B-owned model fusion, rule priority and auditable admission |
| `swarm_sim/dataset.py` / `validation.py` | JSONL export and contract validation |
| `swarm_sim/adapters.py` | A/C adapter protocols and explicit null/mock implementations |
| `swarm_sim/rl.py` | deterministic training environment contract |
| `swarm_sim/calibration.py` | normalized measurement contract, baseline fitter, active runtime controls, strict loader/provenance and actual-runtime comparison |
| `swarm_sim/factory.py` | fresh per-run A/C dependency construction shared by formal entrypoints |
| `swarm_sim/redundancy.py` | runtime-integrated logical replica health/adjudication/switch/recovery |
| `swarm_sim/terminal.py` | lifecycle-integrated terminal profile and anti-copy authorization simulation |
| `swarm_sim/evaluation.py` | offline-only metrics |
| `swarm_sim/mission.py` | shared evidence-based mission-impact semantics for labels, RL and evaluation |
| `swarm_sim/runtime.py` | orchestration; never exposes truth to online consumers |

## 兼容策略

旧 `/api/init`、`/api/step`、`/api/attack` 保留为显式 compatibility/debug 层。新前端和批量运行使用 `/api/runs/*`；只读 `/status`、`/events`、`/runtime` 不改变仿真状态。
