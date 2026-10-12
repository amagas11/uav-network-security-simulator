# V6 schema version decision

## Decision

V5 的 frozen contract 为 `3.0.0`。V6 producer 为 `platform-v6`，数据合同提升到
`3.1.0`。软件版本与 schema 版本继续独立管理；没有因软件叫 V6 而机械升级到
schema 6.0。

## Compatibility judgment

V6 保留既有 JSONL 文件、核心字段名、字段类型、单位和 `packet_size_bytes` / rolling
`sequence_gap_count` 的 3.0 语义。新增内容为向后兼容字段或枚举扩展：

- `RunConfig.traffic_specs`、`session_lifecycle_specs` 与
  `allow_external_model_observer`；
- run 的 scenario evidence、security/calibration/dataset/readiness maturity 与
  offline opaque-ID provenance；
- attack outcome 的 `attack_active`、`eligible_opportunity_seen`、business apply 与
  mission-impact availability/components；
- Eavesdropping 的 `CIPHERTEXT_ONLY`、`PLAINTEXT_EXPOSURE` subtype；
- Eavesdropping 的 `NONSENSITIVE_PLAINTEXT_CONTROL` subtype；
- `RunConfig.model_inference_timeout_ms`、模型失败的 optional `error_summary`；
- optional 完整 `calibration_profile`、profile hash、fitter evidence 与更细的
  calibration maturity enum；
- machine-readable strict subtype parameter contracts；
- online session/link/probe/flow ID 值改为 opaque run-scoped token，并在 schema 中
  加入格式约束。

以上没有改变字段 JSON 类型或物理单位，因此按原始版本规则选择 minor bump
`3.1.0`。Opaque ID 从“消费者不得解析”这一既有约束收紧为可校验 representation；
依赖 ID 文本中端点、scenario 或 profile 名称的 consumer 本来即违反合同，不视为受
支持兼容行为。

## C migration and schema-2 boundary

从 3.0 loader 迁移到 3.1 时必须：

1. 显式接受 `schema_version=3.1.0` 和 `software_version=platform-v6[+hash]`；
2. 把所有 ID 当作 join key，不拆解或作为分类特征；
3. 接受上述 optional provenance/outcome 字段和 Eavesdropping subtype；
4. 继续以 `null + availability/missing_reason` 解释未测值；
5. 仅使用 GCS/LEADER/FOLLOWER observer 的 online stream；
6. 用 3.1 strict parameter contract 校验 scenario config。

3.0 数据不应被无证据改写成 3.1；loader 可并行支持两版，但训练任务必须记录实际
版本。本次无需修改 packet-size、sequence-gap 或 PHY 单位的特征代码。

Schema 2.x→3.1 是跨 major 的不兼容边界。V6 提供可执行命令
`python -m tools.migrate_dataset --input ... --output ... --target-schema 3.1.0`。
旧记录无法恢复 opaque identifiers、requested/resolved plan、target-side outcome stages
与 provider maturity，因此工具会生成带 source hash、tool version、UTC time、warnings
和 unrecoverable fields 的 `migration_report.json`，并以 `REJECTED` 结束；它不会猜值、
复制 JSONL 或把旧数据冒充 3.1。若原始 scenario/config 可重现，应使用 platform-v6
重新运行。这是正式的 executable incompatibility strategy，而非一句不可迁移声明。
