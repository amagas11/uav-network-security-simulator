# C 接口：数据、模型、RL 与 RFF

## 数据输入

C 从一个或多个 schema `3.2.0` run 目录读取连续原始事件与独立 labels。每条 run 保存完整 `run_config`、requested/resolved AttackPlan、NormalDisturbancePlan、business traffic/session lifecycle、calibration/security/model/readiness provenance 和 semantic fingerprint。在线 session/link/probe/flow ID 是不可解析的 join key；模型输入 observer role 仅为 GCS/LEADER/FOLLOWER。窗口、归一化、类别映射和训练/验证拆分由 C 在训练流水线中定义；仿真引擎不写死 C 的序列窗口，也不把攻击/normal scenario 真值回填到 observation。字段与迁移规则以 `docs/schema_contract_for_C.md` 和 `docs/c_final_training_contract.md` 为准。

## `ModelAdapter`

BiLSTM、Dueling Q 和 RFF 均使用：

```python
reset(run_info) -> None
observe(event) -> list[ModelResult]
health() -> dict
```

模型 bundle 应携带模型名、版本、schema 版本、特征契约、类别映射、归一化参数、阈值、训练数据版本和 hash。若 schema/特征/模型缺失，返回结构化 `UNAVAILABLE`/`ERROR`，不得回退成正常类别。

当前三个默认适配器均为 `INTERFACE_READY` 且 `MODEL_NOT_CONFIGURED`；Null adapter 只在 health 中说明 unavailable，不为每条事件制造高频空 `MODEL_RESULT`。确定性本地规则仍可独立工作。正式权重、训练、阈值和准确率属于 C 的外部交付。

直接模式仍可通过 `PlatformRuntime(..., model_adapters={"bilstm": ..., "dueling_q": ..., "rff": ...})` 注入；Manager/FastAPI/Batch/RL 的正式程序级入口共用 `RuntimeDependencies`/`PlatformRuntimeFactory`，每个 run/episode 生成 fresh adapters。未覆盖槽位继续返回结构化 unavailable。即使零条 MODEL_RESULT，runs.jsonl 也保存三槽位 name/version/status provenance。

所有事件经 `OnlineEventDispatcher` 单入口路由。adapter 可声明 `accepted_event_types`；默认 BiLSTM 订阅 TX/RX/PHY/QUEUE/NODE/TOPOLOGY/AUTH，Dueling-Q 订阅 PHY/QUEUE/NODE/TOPOLOGY/AUTH/上游 MODEL_RESULT/DEFENSE_RESULT，RFF 订阅 RX/PHY。BiLSTM/RFF result 可送 Dueling-Q；自己的 result 不回送，Dueling-Q result 为终点。

模型 `recommended_action` 只是建议。B 的 `DecisionFusion` 检查 model status、
quality/confidence threshold、高确定性 rule priority、permission/resource state，
通过后才构造 `DefenseRequest` 并调用 `DefenseExecutor`。审计链保留 source、
model result ID、决策原因、allowed/executed/failure；adapter 不能直接修改 simulator。

## RL 环境

`UavDefenseEnv(..., runtime_factory=...).reset(seed, run_config)` 创建独立、可复现 episode，能装载 fresh BiLSTM/RFF adapters，并自动装载 `attack_specs`、`normal_disturbance_specs` 与可选 phase metadata；调用方不得再绕过接口手工 schedule attack。`step(action_request)` 仍经统一 B DecisionFusion/target/auth/permission/DefenseExecutor 路径，再按 `decision_step_s` 推进 SimulationClock，最后返回 `(next_observation, outcome, terminated)`。

在线 observation 含 recent 2 s/5 s traffic、PHY latest/trend、security/model/node/defense/resource/availability，但不含 current phase、攻击类型/攻击者 truth、labels 或未来事件。phase 只在 environment/evaluator metadata 中提供。

outcome 的 attack impact、实际恶意流量阻止数、合法业务损伤及其 drop/throughput/latency 支持分量、mission impact、吞吐、时延和开销来自 action 前后事件/队列的可解释差分，不使用 random placeholder。字段确实不可得时返回 null 与 missing reason。平台不提供 reward 数值或 reward weights，避免替 C 固化训练目标。

## RFF

平台按每个 hop 的实际发送者/接收者语义提供 RF manifest 和 `rff-identity` 插入点。RFF `MODEL_RESULT` 会更新对应 observer 的 local security result/confidence/quality/time，并使 UNKNOWN/anomaly 进入 RL count；该路径只信任模型 prediction，不使用 true device ID。真实 IQ、特征提取器和模型未提供，因此 manifest 默认空、adapter 明确 unavailable；不得用仿真 RSSI 数组冒充 IQ 或给出虚假 RFF 指标准确率。

## 离线评价

`ExperimentEvaluator` 是唯一允许同时读取事件/结果与 labels 的组件，返回逐攻击族 TP/FP/FN/TN、precision、recall/Pd、Pfa/FPR、F1 和响应时间。`AttackEpisodeScope` 还要求 alarm/defense/PHY/service evidence 与 target node/link/message/observer 相关；无关节点不能替目标产生 TP 或恢复。纯被动窃听按敏感明文暴露、密文保护、内容恢复统计，`online_detection_rate=null`，不制造无观测依据的检测率。
