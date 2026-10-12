# Schema 版本决策

决策日期：2026-09-07。

## 结论

数据契约从 `1.0.0` 升级为 `2.0.0`；V4 收敛后平台软件版本独立升级为 `platform-v4`（Python distribution version 为 `4.0.0`）。两种版本不可互换：software version 标识生产程序，schema version 标识 C 侧读取的数据格式和语义。

## 为什么是 major

V2/V3 不只是增加可忽略的 optional extension。为了使一次实验可复现并可由 C 独立验收，`runs.jsonl` 现在新增且要求：

- 完整、无秘密的 `run_config`；
- 完整 `attack_plan`（包括 `parameters`）和 `normal_disturbance_plan`；
- 非空计划对应的稳定 `attack_plan_id` / `normal_disturbance_plan_id`；
- 覆盖 RunConfig、两类计划、profile/calibration reference、软件和 schema 版本的 semantic fingerprint；
- `labels.jsonl` 中 required `parameters`；
- RunConfig 中 required RL decision interval、统计/replay/reporting window、频率和带宽等语义字段。

旧 1.0 consumer 若严格校验 required 字段或依赖旧 plan 摘要，不能无迁移地解释这些记录；新增 required 字段属于 breaking contract change，因此按原版本规则选择 `2.0.0`。没有把软件 V3 错写成 schema 3.0.0。

## 兼容性与迁移

- 2.0 producer 继续保留 1.0 的 event 外层、`message_id` hop 关联、`sim_time_s` 单位、observer-local `online_features`、truth 分离和 RFF manifest 基本结构。
- C loader 必须先按 `schema_version` 分派；不得把 1.0 缺少的新 provenance 当作空计划或默认配置。
- 1.0 数据如需迁移，必须由已知的原始运行配置补齐 `run_config`/plans 后重新计算 fingerprint。无法恢复的字段应明确标记数据不可用于 provenance-sensitive 训练，不能猜测。
- 2.0 的 future backward-compatible optional extension 可升 minor；required/type/unit/既有语义改变仍升 major。

机器可读唯一依据为 `dataset/schema.json`，运行时常量、exporter、validator 和 API 测试均断言同一 `2.0.0`。

## V4 复核（2026-09-08）

V4 保持 `2.0.0`。新增的 provider provenance、dataset maturity、RFF
confidence/quality/update time 和 probe missing reason 均为兼容 optional
字段；现有字段的 type/unit 没有改变。V4 的主要变化是收紧既有语义：
core unknown field、observer/role、attack ID、message/evidence/RF reference
以及在线标签捷径现在会被 validator 拒绝。这属于对已冻结约束的执行，
不是 wire contract 的另一次 breaking change。完整 C 侧说明见
`schema_contract_for_C.md`。
