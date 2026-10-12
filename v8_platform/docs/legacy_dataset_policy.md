# Legacy Dataset Policy

当前冻结 producer 为 `platform-v7`，schema 为 `3.2.0`。schema-2 是开发期数据，缺少 opaque IDs、resolved plans、target-side outcome stages、provider/model/readiness provenance，不能可靠恢复当前训练语义。

- schema-2 数据不得进入 V7 最终训练、评价或正式实验。
- 有原始 scenario/config/seed 时，必须用当前 producer 重新运行。
- `python -m tools.migrate_dataset` 仅生成带 source hash、source/target/tool version、warnings 和 unrecoverable fields 的 structured rejection；绝不改版本号冒充迁移成功，也不猜缺失 truth。
- C 如需保留历史研究结果，应按原 schema 单独归档，不能与 schema 3.2 dataset 混合。

该政策是有意的 incompatibility boundary，不是 B 软件功能缺口。

