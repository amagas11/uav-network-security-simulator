# Final Completion Boundary

B 平台在以下条件满足时视为软件功能完成：B 自己负责的网络/攻击/检测/防御/上报/数据/评价/RL/校准软件均进入正式路径；A/C mock/null 可经冻结 adapter/factory 被正式资产替换；主要仿真实验不存在已知 correctness blocker；行为由 acceptance test 和可观察证据证明。

完成不等于零 bug，也不要求外部资产已经交付。此后普通缺陷按 maintenance bugfix 处理，不自动重启平台大版本设计。

## B 已完成边界

- 五类攻击、六类 normal hard negatives、逐跳通信、队列/PHY/拓扑与规则防御闭环；
- model recommendation→B policy→defense→Leader/GCS reporting；
- observer-local dataset、RL、RFF、evaluator、validator、leakage audit；
- calibration measurement loader、baseline fitter、runtime actuation、source-v-runtime comparison、Direct/Batch/API/RL entrypoints；
- `RuntimeDependencies`/`PlatformRuntimeFactory` 提供 A/C 程序级依赖替换和 per-run state isolation。

## 不属于 B 软件冻结阻塞项

- A formal SKG/KeyProvider/CryptoProvider/terminal credential/secure hardware；
- C trained BiLSTM/Dueling-Q/RFF、preprocessor/threshold/reward；
- 最终批准真实无线数据、真实 IQ/RF manifest 和最终实测校准报告；
- 历史 schema-2 数据的无损推断式迁移、任意第三方 native/GPU 永久死锁的强制终止、未来多目标/复杂复合攻击研究、工业级分布式 model serving、实机厂家协议；
- 当前宿主缺少 Node/npm 时的前端 executable build（Python API 与只读 polling regression 仍必须通过）。

外部资产缺失时，`B_PLATFORM_SOFTWARE=READY` 与 `FINAL_FORMAL_EXPERIMENT=BLOCKED_EXTERNAL` 可以同时成立。

