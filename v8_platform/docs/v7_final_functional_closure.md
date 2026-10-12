# V7 Final Functional Closure

日期：2026-09-09。三份原始需求文档保持不变。本表只在正式运行路径和行为级测试均通过后使用 `IMPLEMENTED`；最终 A/C 模型资产和批准真实无线数据不冒充软件完成项。

| Issue ID | Requirement Source | V6/V7 基线行为与风险 | 正确语义 / 实现 | 反例与验收 | 涉及文件 | Final Status |
|---|---|---|---|---|---|---|
| V7F-CAL-ACTUATION-001 | 分工 B 数据校准；A→B PHY 字段 | profile 的 loss/latency/RSSI/SNR 只进 provenance，相同 seed 的极端 profile 输出完全一致 | descriptive targets 与 runtime controls 分离；RSSI/SNR bias、background loss、base latency/jitter 进入真实 PHY 公式，且不覆盖 path loss/fading/Jamming/normal disturbance | 修改前 A/B 输出完全一致；`test_v7_calibration_runtime.py` 比较实际事件方向与显著差异：PASS | `swarm_sim/calibration.py`, `swarm_sim/phy.py` | IMPLEMENTED |
| V7F-CAL-RUNTIME-VALIDATION-001 | 分工 B 校准/对比 | 旧 comparison 可接受人工 simulation records，不能证明 runtime 被 profile 驱动 | `RuntimeCalibrationValidator` 执行 Dataset→Fitter→Profile→PlatformRuntime→events→statistics→comparison | 实际 runtime record count=142；loss/RSSI/SNR/latency 均来自 TX/RX events：PASS | `swarm_sim/calibration.py`, acceptance tests | IMPLEMENTED |
| V7F-READINESS-001 | 分工总集成；C 模型接入 | formal A/calibration/dataset 即使无 C model 也可能 READY | readiness 分层；legacy `experiment_readiness` 冻结为 FINAL_FORMAL_EXPERIMENT，缺 C 三槽位明确 BLOCKED_EXTERNAL | formal A + approved calibration + no C models 的三 blocker 反例：PASS | `swarm_sim/runtime.py`, schema, tests | IMPLEMENTED |
| V7F-RUNTIME-DEPENDENCIES-001 | 分工总集成 | Direct Runtime 可注入，Manager/Batch/API/RL 不能统一替换 A/C 资产 | `RuntimeDependencies` + `PlatformRuntimeFactory` 每 run 创建 fresh provider/model；Direct API 保持兼容 | 同一 fake factory 经 direct/Manager/Batch/controller/RL：metadata 一致且实例不同：PASS | `swarm_sim/factory.py`, Manager, app, batch, RL | IMPLEMENTED |
| V7F-MANAGER-RESET-001 | API lifecycle | calibrated Manager reset 丢 profile 并报 calibration missing | Manager 保存 factory/profile；reset 关闭旧 runtime 并创建 fresh run | profile id/hash/controls 保留；run id、events、queues、model state fresh：PASS | `Manager/simulationmanager.py`, API test | IMPLEMENTED |
| V7F-RL-MODEL-INJECTION-001 | C RL/RFF/ModelAdapter | RL Env 无正式 model factory 注入，无法在 episode 装载 BiLSTM/RFF | Env 接受 runtime factory，每次 reset 获得 fresh adapters，动作仍走同一 B policy | fake BiLSTM scores/confidence/quality 和 RFF UNKNOWN/anomaly 进入 observation：PASS | `swarm_sim/rl.py`, factory tests | IMPLEMENTED |
| V7F-MODEL-PROVENANCE-001 | C 模型版本合同 | 无 MODEL_RESULT 时 runs 看不到已加载模型 | run 开始/导出都记录 bilstm/dueling_q/rff slot、configured/name/version/status/error、可选 bundle/preprocessor/threshold/training-data provenance | zero-result `bilstm-v7-fixture/9.9` 仍写入 runs：PASS；unavailable/timeout 同样有记录 | `swarm_sim/runtime.py`, schema, tests | IMPLEMENTED |
| V7F-MODEL-TIMEOUT-SCOPE-001 | C 模型 fault boundary | process-wide pool 可被旧坏 run 占满并污染新 run | bounded daemon supervisor 改为 runtime-owned generation；timeout 禁用本 run adapter，新 runtime 有 fresh capacity | 10 个 timeout runtime 后 GoodAdapter 仍 `OK`，非 SATURATED：PASS | `swarm_sim/model_runtime.py`, runtime, tests | IMPLEMENTED |
| V7F-CALIBRATION-OWNERSHIP-001 | 分工 B | 文档把整个 calibration 混为外部责任 | B loader/fitter/runtime mapping/comparison/entrypoints=软件责任；仅最终批准数据与最终拟合结果为 external dependency | exhaustive audit 与 completion boundary 已拆分 | calibration/audit/docs | IMPLEMENTED |
| V7F-RELEASE-PROVENANCE-001 | 发布与 C contract | V7 包仍写 platform-v6/schema 3.1 | producer=`platform-v7`；additive run provenance/control fields 使用 schema `3.2.0`，不机械升 major | version/schema/API/tests：PASS | simulation, schema, pyproject, app, frontend, docs | IMPLEMENTED |
| V7F-FINAL-FUNCTIONAL-SMOKE-001 | 三份原始需求 | 校准/DI 修复可能回归历史闭环 | 历史全套 + 22-scenario mechanism + C gate + V7 integration 一起执行 | 22/22 scenario；selected closure matrix 55/55；full 355/355 | tests, mechanism matrix | VERIFIED |
| V7F-FINAL-FREEZE-001 | V7 hard gate | 不能以字段/测试数量代替功能结果 | 以实际 runtime output、正式入口、全历史回归和外部边界作冻结依据 | compileall PASS；pytest 355 PASS；frontend 环境诚实记录 | 本文及最终报告 | VERIFIED |

## Fail-first 证据

- V7 修改前，极端 profile A（loss=0、latency=10 ms）和 B（loss=1、latency=1000 ms）在同 seed/config 下得到完全相同的 RX 与 latency 序列。
- 首批新 tests 因 `RuntimeCalibrationValidator`、`swarm_sim.factory` 尚不存在而 collection ERROR；随后行为反例也证明 Manager reset、readiness、RL injection、zero-result provenance 和跨 run timeout 隔离缺失。
- 未为制造红灯破坏已经正确的 V6 行为。

## 实测校准结果

同一拓扑/流量口径的聚合运行结果：

| Profile | Source target | Runtime result |
|---|---|---|
| low-loss/low-latency | RSSI -65 dBm；SNR 25 dB；loss 0；latency 10 ms | RSSI mean -65.866；SNR mean 28.134；loss 0.000；median latency 10.338 ms |
| high-loss/high-latency | RSSI -85 dBm；SNR 5 dB；loss .9；latency 500 ms | RSSI mean -84.555；SNR mean 9.445；loss .9302；median latency 499.334 ms |

`RuntimeCalibrationValidator` 的独立 synthetic fixture（2 seeds）得到：source/runtime RSSI mean -68/-69.052 dBm、SNR 18/16.948 dB、loss .10/.1127、latency median 25/25.334 ms。comparison 的 simulation side 由真实 Runtime events 生成，不是复制或偏移 source records。throughput target 明确为 `DESCRIPTIVE_VALIDATION_TARGET`，运行 throughput 由 bandwidth/SINR/loss 间接形成。

## Readiness 结论

| Component | 当前默认包状态 |
|---|---|
| B platform/calibration software | READY |
| A/C integration interfaces | READY |
| C dataset generation | READY_FOR_C_DEVELOPMENT |
| Formal A assets | BLOCKED_EXTERNAL |
| Approved real calibration | BLOCKED_EXTERNAL |
| Trained BiLSTM/Dueling-Q/RFF assets | BLOCKED_EXTERNAL |
| Final formal integrated experiment | BLOCKED_EXTERNAL |

这是分工边界下的正确最终状态，不影响 B 软件冻结。
