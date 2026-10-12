# V7 Schema Version Decision

## Decision

V6 contract 为 `3.1.0`。V7 producer 更新为 `platform-v7`，schema 提升为 `3.2.0`。软件版本和 schema 版本继续独立；未机械升级到 7.0。

## Compatibility

V7 不改变 JSONL 文件结构、现有 required field、类型、单位、packet-size、sequence-gap、opaque-ID 或 attack/evaluator semantic。新增均为 additive optional run provenance：

- `model_assets`（三 model slot 的 run-start/export provenance）；
- `readiness_components`、`readiness_blockers`、`dataset_readiness`；
- `calibration_runtime_controls`、`calibration_parameter_semantics`。

因此符合原版本规则的 backward-compatible minor bump。3.1 consumer 可忽略 optional 字段；需要 V7 readiness/calibration/model provenance 的 C loader 必须显式支持 3.2。

## Migration

3.1→3.2 不需重写 events/labels。旧 3.1 run 没有上述 provenance 时必须按 unavailable 处理，不能猜模型资产或 runtime controls。schema-2 政策见 `docs/legacy_dataset_policy.md`：不可恢复时 structured rejection 并重新运行原 scenario。

## Person-A SKG closure addendum

`runs.probe_profile` 是 optional additive provenance，现有 event/label 字段及语义均未改变，
所以 closure patch 保持 schema `3.2.0`。新 export 将 profile 纳入 runtime semantic
fingerprint；旧 3.2 record 缺少该 optional field 时继续使用原 fingerprint 验证路径。
