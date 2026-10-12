# 实施计划 V1

本计划严格按 Phase 0→10 连续执行；每阶段运行针对性测试并将实际命令/结果写入 `docs/test_report.md`。

| Phase | Scope | Exit evidence |
|---:|---|---|
| 0 | 完整读取三份需求；仓库审计；追踪矩阵；Git/依赖；baseline tests/build | 本矩阵、gap、architecture、baseline 记录 |
| 1 | SimulationClock、RunContext、scheduler、deterministic IDs/RNG、event schema、truth separation | same-seed/reset/leakage tests |
| 2 | roles、权限、GCS/Leader/Follower 业务、逐跳 TX/RX/queue/forward | multihop/断链/message_id/event_id tests |
| 3 | persistent PHY、RX_FAILURE、PHY_SAMPLE、ProbeService | PHY/probe tests |
| 4 | AttackPlan/Scheduler；Spoofing/Eavesdropping/Flooding/Jamming/FDI/Replay | 每子类效果与语义测试 |
| 5 | local deterministic rules、DefenseExecutor、local cache/GCS upload、dataset export | defense/report/dataset tests |
| 6 | RL environment、ModelAdapter、Key/Crypto adapter | smoke/fallback/explicit-outcome tests |
| 7 | calibration framework、RFF interface | profile/manifest/hop semantics tests |
| 8 | logical redundancy、terminal authorization/anti-copy | failure adjudication/copy rejection tests |
| 9 | FastAPI lifecycle/read APIs、legacy compatibility、Runtime/Evaluation UI 分离 | API smoke + frontend type-check/build |
| 10 | evaluator、validator、batch experiments、全量回归、文档/矩阵最终审计 | test report + final status report |

## 实施原则

- 复用 baseline 物理公式和业务分布，但把随机源、状态和接口注入新边界。
- 新逻辑拆分模块；legacy manager 仅保留兼容 facade，不继续膨胀。
- 每条 online event 在创建时按允许字段白名单构造，不从含 truth 的对象做事后删除。
- 外部模块缺失不阻塞 B：明确返回 `INTERFACE_READY`/`BLOCKED_EXTERNAL`，绝不伪造成功或 accuracy。
- 不删除根目录或 `无人机/` 的现有源码；生成数据、日志、模型缓存进入 `.gitignore`。

## 执行结果

Phase 0–10 的平台 B 范围均已执行并通过回归；A 正式 SKG/凭据、C 正式模型/训练、真实 IQ 与真实校准数据按接口边界保持外部阻塞。具体证据见 `docs/test_report.md`，逐项状态见 `docs/requirement_traceability_matrix.md`。
