# V7 原始需求穷尽式最终审计（文件名兼容保留）

审计日期：2026-09-09。审计直接重新阅读 `分工安排(1).md`（当前根目录文件名为
`分工安排.md`）、`A_B_无线观测字段说明.md` 与 `c需求文档.md`，没有把历史矩阵当作
需求来源，也没有修改三份原文。每个独立语义分配唯一 ID；`IMPLEMENTED` 必须同时有
正式代码、正式入口、可观察证据和实际通过的 acceptance test。

状态仅使用：`IMPLEMENTED`、`INTERFACE_READY`、`BLOCKED_EXTERNAL`、`PARTIAL`、
`NOT_IMPLEMENTED`。表中 “PASS” 均包含在 V7 的 355-case 全量检查点；最终收尾复跑见
`docs/test_report.md`。

## B 侧平台责任

| ID | 原始来源 | 原始要求摘要 | 责任 | 实现位置 | 正式运行入口 | 可观察证据 | Acceptance test / actual | Status |
|---|---|---|---|---|---|---|---|---|
| B-REQ-001 | 分工 §B；A→B 字段 | 校准数据/Profile loader 与来源校验 | B | `calibration.py`, run provenance | Runtime/Batch/API/RL | data_source、profile/version/hash | calibration pipeline: PASS | IMPLEMENTED |
| B-REQ-002 | 分工 数据原则 | 无真实数据时不得伪造校准 | B | `CalibrationProfile.uncalibrated_baseline` | all | simulation + UNCALIBRATED | calibration/provenance gates: PASS | IMPLEMENTED |
| B-REQ-003 | 分工 网络建模 | GCS/Leader/Follower 角色真实分离 | B | `domain.py`, `runtime.py` | all | role-local nodes/events | `test_v1_core.py`: PASS | IMPLEMENTED |
| B-REQ-004 | 分工 网络建模 | GCS 命令、Leader 转发、Follower telemetry 业务 | B | `runtime.py`, `scenario.py` | all | TX/RX/message chain | core/e2e: PASS | IMPLEMENTED |
| B-REQ-005 | 分工 网络建模；C 数据 | 真正逐 hop 通信而非端到端瞬移 | B | `network.py`, `runtime.py` | all | per-hop TX/RX，新 event ID，共 message ID | core/multisession: PASS | IMPLEMENTED |
| B-REQ-006 | 分工 网络建模 | 动态拓扑、断链、恢复、重路由 | B | `network.py`, `runtime.py` | Runtime/API | topology version/path | `test_v1_second_round_topology.py`: PASS | IMPLEMENTED |
| B-REQ-007 | 分工 防御/上报 | 断链本地缓存，恢复后上传 | B | `reporting.py`, `runtime.py` | all | cached/reported timestamps | reporting e2e: PASS | IMPLEMENTED |
| B-REQ-008 | 分工 网络建模 | 有界 TX/RX/forward queue 与服务能力 | B | `domain.py`, `runtime.py` | all | QUEUE_SAMPLE/drop/backlog | traffic/runtime tests: PASS | IMPLEMENTED |
| B-REQ-009 | C §3 | 时延、吞吐、packet/byte rate 与 inter-arrival 可计算 | B | `traffic.py` | all | observer-local non-null measures | traffic + C gates: PASS | IMPLEMENTED |
| B-REQ-010 | 分工 攻击仿真 | AttackPlan/Scheduler 用 sim time 执行 | B | `attacks.py`, `runtime.py` | all | scheduled/impact/end truth | attack/runtime tests: PASS | IMPLEMENTED |
| B-REQ-011 | 分工/C 攻击 | Spoofing 未知身份场景 | B | `attacks.py`, `security.py` | all | external frame + auth FAIL | V6 22-scenario matrix: PASS | IMPLEMENTED |
| B-REQ-012 | 分工/C 攻击 | Spoofing 已知身份冲突场景 | B | same | all | claimed known ID、actual external、conflict | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-013 | 分工/C 攻击 | 被动监听敏感密文保护样本 | B | `attacks.py`, crypto adapter | all | capture=3、ciphertext=3、exposure=0、protected=true | three-way eaves matrix/parity: PASS | IMPLEMENTED |
| B-REQ-014 | C 分类目标 | 敏感明文暴露正样本 | B | same | all | unauthorized sensitive exposure=3 | three-way eaves matrix/parity: PASS | IMPLEMENTED |
| B-REQ-015 | 分工/C 攻击 | Flooding 生成真实负载与队列/服务效应 | B | `attacks.py`, `packets.py`, runtime | all | generated/transmitted/rate/backlog | backlog + V6 matrix: PASS | IMPLEMENTED |
| B-REQ-016 | 分工/C 攻击 | Jamming 作用于目标链路 PHY | B | `attacks.py`, `phy.py` | all | target SINR/PER/decode degradation | V6 matrix/wrong-link: PASS | IMPLEMENTED |
| B-REQ-017 | C FDI | command replacement 在 pre-crypto 修改 | B | `attacks.py`, runtime | all | original/modified truth，合法 auth | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-018 | C FDI | telemetry abrupt change | B | same | all | 100→150 modifications | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-019 | C FDI | gradual drift 真累积 | B | same | all | 105,110,115 | regression + matrix + batch parity: PASS | IMPLEMENTED |
| B-REQ-020 | C FDI | out-of-range value | B | same | all | 5000 value，business rejection | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-021 | C FDI | logical inconsistency | B | same | all | LANDED + altitude conflict | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-022 | C Replay | immediate replay 保 message、新 event、duplicate | B | `attacks.py`, `security.py` | all | capture .2/replay .6/DUPLICATE | matrix/replay tests: PASS | IMPLEMENTED |
| B-REQ-023 | C Replay | delayed replay 由 SimulationClock 延迟 | B | same | all | .2→.8，delay=.6 | matrix/replay tests: PASS | IMPLEMENTED |
| B-REQ-024 | C Replay | 合法 rotation 后 old session WRONG_SESSION | B | `scenario.py`, security | all | rotation .6、replay .8、WRONG_SESSION | matrix/parity: PASS | IMPLEMENTED |
| B-REQ-025 | C Replay/control | high-watermark + seen window 接受合法乱序 | B | `security.py`, `traffic.py` | all | 100,102,101 all PASS | replay/normal matrix: PASS | IMPLEMENTED |
| B-REQ-026 | C normal controls | 正常 low-SNR，无 attack label | B | `normal.py`, `phy.py` | all | 55 dB attenuation、low SNR | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-027 | C normal controls | 自然 packet loss，无 attack label | B | same | all | RX_FAILURE from normal profile | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-028 | C normal controls | 合法 traffic burst 与 Flood hard negative | B | normal/packet builder | all | 36 packet、same STATUS schema/size support | hard-negative + matrix: PASS | IMPLEMENTED |
| B-REQ-029 | C normal controls | 合法 out-of-order 不判 Replay | B | normal/security | all | PASS/PASS/PASS，无 label | matrix/combination: PASS | IMPLEMENTED |
| B-REQ-030 | C normal controls | 正常 state change 及一致 telemetry | B | normal/runtime | all | state→TELEMETRY causal chain | hard-negative + matrix: PASS | IMPLEMENTED |
| B-REQ-031 | C normal controls | 正常 congestion，无 attack label | B | normal/phy/runtime | all | queue/busy/rate increase | V6 matrix: PASS | IMPLEMENTED |
| B-REQ-032 | 分工 防御 | 各攻击对应可授权防御动作 | B | `security.py`, `decision.py` | Runtime/API/RL/model | DEFENSE_RESULT/audit | runtime/evaluator tests: PASS | IMPLEMENTED |
| B-REQ-033 | 分工 防御 | 节点本地快速检测与止损 | B | `security.py`, runtime | all | local rule/auth/replay action | integration tests: PASS | IMPLEMENTED |
| B-REQ-034 | 分工 防御 | Leader 去重汇总并保留 evidence refs | B | `reporting.py` | all | SECURITY_SUMMARY/count/source IDs | reporting e2e: PASS | IMPLEMENTED |
| B-REQ-035 | 分工 展示 | GCS 接收、保存并供 runtime/evaluation 展示 | B | reporting/API/frontend | API/UI | inbox/runtime/evaluation views | API/reporting tests: PASS | IMPLEMENTED |
| B-REQ-036 | 分工 上报 | 紧急绕过批处理、普通汇总、断链恢复 | B | reporting/runtime | all | report_received_time/delay | reporting/evaluator tests: PASS | IMPLEMENTED |
| B-REQ-037 | C 检测接入 | 确定性 rule engine 不使用 attack truth | B | `security.py` | all | AUTH/replay/local evidence | security/no-leak tests: PASS | IMPLEMENTED |
| B-REQ-038 | C 模型接入 | 统一在线 ModelAdapter dispatcher | B | `dispatch.py`, adapters/runtime | Runtime/API/RL | subscribed event types、no recursion | C gates/regressions: PASS | IMPLEMENTED |
| B-REQ-039 | C 防御闭环 | model recommendation→B fusion→defense | B | `decision.py`, runtime | model/RL | audit source/reason/allowed/executed | model decision + combination: PASS | IMPLEMENTED |
| B-REQ-040 | 分工/A 接口 | encryption/auth provider adapter 和 mock baseline | B 接口 | `adapters.py`, security | all | auth result/key ref，无 raw key | attacks/security tests: PASS | IMPLEMENTED |
| B-REQ-041 | 分工/A 接口 | rekey 必须经 KeyProvider 并记录失败 | B 接口 | adapters/security/runtime | Runtime/API/RL | state transition/failure reason | rekey integration: PASS | IMPLEMENTED |
| B-REQ-042 | A→B 字段 | LocalPhyObservation 字段、单位、missing | B | `probe.py`, schema | Runtime/probe | paired observations | data/probe tests: PASS | IMPLEMENTED |
| B-REQ-043 | A→B 字段 | reciprocal latent channel + independent receiver noise/SNR | B | `probe.py`, `phy.py` | Runtime | correlated but non-copied series | probe tests: PASS | IMPLEMENTED |
| B-REQ-044 | A→B/C | missing 不补 0，null + reason | B | events/probe/RL/schema | all | explicit availability/missing | data/RL tests: PASS | IMPLEMENTED |
| B-REQ-045 | C RFF | strict RF manifest/ref/current-hop semantics | B | dataset/validation/schema | Batch/export | 18 fields/ref/path or null | RFF validator gates: PASS | IMPLEMENTED |
| B-REQ-046 | C RL | reset(seed, config) 自动装载 attack/normal/traffic/session | B | `rl.py`, runtime | RL | scheduler/initial state | C V1 + V6 parity: PASS | IMPLEMENTED |
| B-REQ-047 | C RL | step 推荐动作后推进 SimulationClock | B | `rl.py` | RL | time advances/next observation | RL tests: PASS | IMPLEMENTED |
| B-REQ-048 | C RL | action/outcome 真实且训练/部署同 policy | B | rl/decision/runtime | RL/model | allowed/executed/reason/service metrics | V6 CASE 6/7: PASS | IMPLEMENTED |
| B-REQ-049 | C RL | 2 s/5 s local state、PHY trend、security/RFF/model/defense | B | `rl.py` | RL | structured observation, no truth | RL acceptance: PASS | IMPLEMENTED |
| B-REQ-050 | 分工 内生安全 | 三逻辑 replica 接入关键运行功能 | B | `redundancy.py`, runtime | Runtime | REDUNDANCY result | runtime redundancy test: PASS | IMPLEMENTED |
| B-REQ-051 | 分工 内生安全 | adjudication majority/weighted baseline | B | redundancy | Runtime | inconsistent result adjudicated | redundancy test: PASS | IMPLEMENTED |
| B-REQ-052 | 分工 内生安全 | health monitor 发现 replica 异常 | B | redundancy | Runtime | health state | redundancy test: PASS | IMPLEMENTED |
| B-REQ-053 | 分工 内生安全 | switch/degrade/recovery 保持服务 | B | redundancy/runtime | Runtime | switch/recovery event | redundancy test: PASS | IMPLEMENTED |
| B-REQ-054 | 分工 防复制 | terminal profile binding 模拟 copy attack | B | `terminal.py` | Runtime | copied config on other profile denied | authz tests: PASS | IMPLEMENTED |
| B-REQ-055 | 分工 防复制 | PROGRAM_START authorization | B | terminal/runtime | Runtime/API | start denied state/event | authz tests: PASS | IMPLEMENTED |
| B-REQ-056 | 分工 防复制 | NETWORK_JOIN authorization | B | same | Runtime | join denied/event | authz tests: PASS | IMPLEMENTED |
| B-REQ-057 | 分工 防复制 | SENSITIVE_COMMAND authorization | B | same | Runtime | command blocked, no execution | authz tests: PASS | IMPLEMENTED |
| B-REQ-058 | C 数据 | online event logging 与唯一 event ID/sim time | B | `events.py`, dataset | all | events.jsonl | data/validator gates: PASS | IMPLEMENTED |
| B-REQ-059 | C 数据 | attack truth 独立 labels logging | B | attacks/dataset | all | labels.jsonl only | no-leak tests: PASS | IMPLEMENTED |
| B-REQ-060 | C 数据 | UTF-8 JSONL export | B | `dataset.py` | Runtime/Batch/API | four files + schema | dataset tests: PASS | IMPLEMENTED |
| B-REQ-061 | C 数据 | machine-readable frozen schema、nested fields/units | B | `dataset/schema.json` | export/validator | schema 3.2.0 | schema tests: PASS | IMPLEMENTED |
| B-REQ-062 | C 数据 | fault-tolerant type/range/ref/cross-file validator | B | `validation.py` | CLI/API/tests | invalid=false，坏值不崩溃 | corrupt validator tests: PASS | IMPLEMENTED |
| B-REQ-063 | C 数据 | 完整 run/attack/normal/calibration/provider provenance | B | runtime/dataset | all | runs.jsonl + fingerprints | provenance tests: PASS | IMPLEMENTED |
| B-REQ-064 | C 数据 | deterministic seed 与 reset isolation | B | simulation/runtime | all | semantic projection identical | deterministic e2e: PASS | IMPLEMENTED |
| B-REQ-065 | C 数据 | unique run/event/message IDs；seed 非 identity | B | IdFactory/batch | all | duplicate seed dirs/IDs distinct | V3 regression: PASS | IMPLEMENTED |
| B-REQ-066 | C 数据 | online truth/normal/identifier/structural shortcut 隔离 | B | events/leakage/runtime | all | bounded leakage report | hard-negative/matrix: PASS | IMPLEMENTED |
| B-REQ-067 | C 评价 | attack episode + normal window TP/FP/FN/TN | B | `evaluation.py` | Evaluation API | confusion units/duplicate alarms | evaluator tests: PASS | IMPLEMENTED |
| B-REQ-068 | C 评价 | family/subtype 与 typed attack scope 归属 | B | evaluation | Evaluation API | node/link/message/flow scope | scope regressions: PASS | IMPLEMENTED |
| B-REQ-069 | C 评价 | attack outcome 分 attempted/injected/reached/executed/effective | B | attacks/runtime | all | staged label outcome | V5/V6 matrix: PASS | IMPLEMENTED |
| B-REQ-070 | C 评价 | action executed 与 defense effective 分开 | B | evaluation | Evaluation API | attempts/first executed/policy | evaluator regressions: PASS | IMPLEMENTED |
| B-REQ-071 | C 评价 | detection/action response delay 分开 | B | evaluation | Evaluation API | detection_delay/action_delay | evaluator tests: PASS | IMPLEMENTED |
| B-REQ-072 | C 评价 | report arrival delay | B | reporting/evaluation | all/eval | received-detect time | reporting e2e: PASS | IMPLEMENTED |
| B-REQ-073 | C 评价 | service recovery time | B | evaluation | Evaluation API | thresholded recovery | evaluator tests: PASS | IMPLEMENTED |
| B-REQ-074 | C 评价 | legitimate service damage | B | evaluation/RL | Eval/RL | throughput/latency/drop components | evaluator/RL tests: PASS | IMPLEMENTED |
| B-REQ-075 | C 评价 | mission impact 真实或 explicit unavailable | B | `mission.py`, attacks/RL/eval | all | score/components/availability | V6 outcome tests: PASS | IMPLEMENTED |
| B-REQ-076 | C 数据 | dataset 可按 run/seed/plan 做 train/val/test split | B 数据支持 | run provenance/schema | Batch/export | stable run/plan IDs | C data acceptance: PASS | IMPLEMENTED |
| B-REQ-077 | 分工 前端 | runtime view 与 evaluation view 分离 | B | FastAPI/frontend | API/UI | separate endpoints/state | API/static tests: PASS | IMPLEMENTED |
| B-REQ-078 | 分工 前端 | polling 只读，不能推进仿真 | B | frontend/API manager | UI/API | GET runtime/status only | source/API regression: PASS | IMPLEMENTED |
| B-REQ-079 | 分工 API | 正式 lifecycle/config/export/evaluation API | B | `app/app.py` | FastAPI | strict create/status/events/eval | API tests: PASS | IMPLEMENTED |
| B-REQ-080 | C 模型 | unavailable/error/timeout 不伪造 NORMAL prediction | B | adapters/`model_runtime.py`/dispatch | all | null prediction + explicit status/error code | final model fault matrix: PASS | IMPLEMENTED |
| B-REQ-081 | C 数据 | opaque online identifiers 与 offline mapping | B | simulation/runtime/leakage | all | `sess/lnk/probe-<scope>-<counter>`；scope 保证非纯数字 | V6 ID regressions（含真实 numeric-SHA 反例）: PASS | IMPLEMENTED |
| B-REQ-082 | C 场景 | schema valid 与机制发生双 gate | B | `scenario_validation.py` | Runtime/Batch/tests | mechanism evidence | 22-scenario matrix: PASS | IMPLEMENTED |
| B-REQ-083 | C 场景 | direct/batch/API/RL 语义一致 | B | scenario/runtime/tool/API/RL | four entrypoints | matching key evidence | V6 parity 4 scenarios: PASS | IMPLEMENTED |
| B-REQ-084 | C 配置 | top-level 和 subtype 参数严格、accepted 参数生效 | B | RunConfig/attacks/normal/scenario | all | fail-fast errors | V6 strict tests: PASS | IMPLEMENTED |
| B-REQ-085 | C 模型部署 | EXTERNAL observer 默认不进入模型/防御流 | B | dispatch/runtime | all | no external MODEL/DEFENSE result | V6 regression: PASS | IMPLEMENTED |
| B-REQ-086 | C 业务因果 | packet delivery 与 business execution 分离 | B | domain/runtime | all | BusinessApplyResult | command/replay/spoof tests: PASS | IMPLEMENTED |
| B-REQ-087 | C 复合标签 | simultaneous attacks 保留离线 attribution | B | runtime/labels | all | contributing attack IDs offline only | V6 combination: PASS | IMPLEMENTED |
| B-REQ-088 | A→B PHY | channel switch 保 reciprocal link/frequency 语义 | B | phy/probe/runtime | Runtime | both links switch or mismatch missing | probe/channel tests: PASS | IMPLEMENTED |
| B-REQ-089 | C 流量 | recent-window sequence gap 与 late fill/expiry | B | traffic/schema | all | gap timestamp/aging | gap tests: PASS | IMPLEMENTED |
| B-REQ-090 | 工程/分工 | mock/formal provider、calibration、dataset maturity 分层 | B | runtime/schema/validator | all | non-secret maturity fields | maturity tests: PASS | IMPLEMENTED |
| B-REQ-091 | C §8–§9 | 外部模型 reset/observe/health 异常与推理超时不得中断平台，规则继续 | B | `model_runtime.py`, `runtime.py` | Runtime/API/RL | runtime-scoped bounded supervisor、ERROR/UNAVAILABLE health、rule result | model fault matrix + V7 cross-run isolation: PASS | IMPLEMENTED |
| B-REQ-092 | 分工上报；C 模型接入 | C 模型检测及 fusion/defense 结果通过 Leader→GCS 并支持断链重传/去重 | B | `runtime.py`, `reporting.py` | Runtime/API/RL/model | correlated SecurityReport、cache、received time/delay | `test_model_reporting_final.py` 3/3: PASS | IMPLEMENTED |
| B-REQ-093 | C Eavesdropping 数据 | 非敏感普通明文监听对照不得标明文泄露 | B | `attacks.py`, `runtime.py`, `scenario_validation.py` | all | capture=3、ordinary=3、cipher=0、exposure=0 | three-way eaves matrix 4/4: PASS | IMPLEMENTED |
| B-REQ-094 | 分工 B 数据校准 | 已整理 measurement dataset 可经可解释 fitter 生成 CalibrationProfile | B | `calibration.py` | calibration API/library | mean/std/quantile/loss/latency + hash/warnings | calibration pipeline: PASS | IMPLEMENTED |
| B-REQ-095 | 分工 B 数据校准 | CalibrationProfile 在 Runtime/Batch/FastAPI/RL 入口一致加载 | B | calibration/runtime/batch/API/RL | four entrypoints | identical profile ID/hash/provenance | calibration pipeline: PASS | IMPLEMENTED |
| B-REQ-096 | 分工 B 数据校准 | 输出源数据与真实校准仿真运行的基础统计对比 | B | `RuntimeCalibrationValidator`, `compare_calibration_observations` | calibration library→Runtime | actual events 的 RSSI/SNR/loss/latency/throughput comparison | V7 runtime calibration validator: PASS | IMPLEMENTED |
| B-REQ-097 | C §6 RL state | 明文相关状态使用本地可观察保护风险，不使用监听者 capture truth | B | node/runtime/`rl.py` | RL reset/step | protected/unprotected count、risk、availability | plaintext-risk acceptance: PASS | IMPLEMENTED |
| B-REQ-098 | schema 版本规则 | major 旧数据有可执行迁移/不兼容策略且禁止猜值 | B | `tools/migrate_dataset.py` | CLI/library | schema2 structured REJECTED report + source hash/warnings | schema migration acceptance: PASS | IMPLEMENTED |
| B-REQ-099 | 分工 B 数据校准 | CalibrationProfile 的主要统计必须实际改变 Runtime signal/loss/latency | B | `calibration.py`, `phy.py` | Direct/Batch/API/RL | runtime controls + actual RX/PHY/traffic output | V7 low/high profile statistical comparison: PASS | IMPLEMENTED |
| B-REQ-100 | 分工总集成 | 平台软件、dataset 与 final formal experiment readiness 分层且缺 C 模型不得 READY | B | `runtime.py`, schema | all run records | components/blockers/dataset readiness | V7 missing-C/readiness matrix: PASS | IMPLEMENTED |
| B-REQ-101 | 分工总集成；A/C 接口 | A/C stateful dependencies 可从 Manager/Batch/API/RL 统一替换并按 run fresh | B | `factory.py`, Manager/app/batch/RL | all formal entrypoints | equal metadata, distinct instances | V7 dependency matrix: PASS | IMPLEMENTED |
| B-REQ-102 | 分工 API lifecycle | calibrated reset 保留 profile/factory 但清空 run state | B | `simulationmanager.py` | Manager/FastAPI | same profile hash/controls, new run/events/queues | V7 calibrated reset: PASS | IMPLEMENTED |
| B-REQ-103 | C RL/model | RL Env 能通过正式 factory 装载 BiLSTM/RFF 并保持 B policy parity | B | `rl.py`, `factory.py` | RL reset/step | model scores/quality + RFF anomaly | V7 RL injection/fresh reset: PASS | IMPLEMENTED |
| B-REQ-104 | C provenance | 已配置模型即使零结果也必须保存 run-level name/version/status | B | `runtime.py`, schema | all exports | three-slot `model_assets` | V7 zero-result/unavailable/timeout matrix: PASS | IMPLEMENTED |
| B-REQ-105 | C model availability | 一个 timed-out run 不得耗尽后续独立 run 的 model execution capacity | B | `model_runtime.py`, runtime | Runtime/Manager/Batch/RL | runtime-owned supervisor generation | V7 timeout cross-run regression: PASS | IMPLEMENTED |

## A→B 外部责任和接口

| ID | 原始来源 | 原始要求摘要 | 责任 | 实现位置 | 正式运行入口 | 可观察证据 | Acceptance test / actual | Status |
|---|---|---|---|---|---|---|---|---|
| A2B-REQ-001 | 分工 A | 正式 SKG 算法/服务 | A | B 的 `KeyProvider` 协议已冻结 | all | provider provenance/state | adapter contract PASS；正式资产未交付 | BLOCKED_EXTERNAL |
| A2B-REQ-002 | 分工 A | 正式 key lifecycle/provider | A | request_rekey/result/state 接口 | all | epoch/state/failure | mock success/failure PASS | INTERFACE_READY |
| A2B-REQ-003 | 分工 A | 正式 encryption/auth provider | A | `CryptoProvider` 协议 | all | auth/cipher metadata，无 secret | test-only provider tests PASS | INTERFACE_READY |
| A2B-REQ-004 | 分工 A | secure element/root of trust | A/硬件 | terminal/provider slots | start/join/command | provider status | simulated binding PASS；硬件缺失 | BLOCKED_EXTERNAL |
| A2B-REQ-005 | 分工 A | 正式 terminal credential | A | terminal credential provider contract | Runtime | authorization result | simulated lifecycle PASS | INTERFACE_READY |
| A2B-REQ-006 | A→B 字段 | 正式 A 输出/消费 LocalPhyObservation | A | frozen schema/probe API | Runtime | paired local observation | B contract PASS；A implementation pending | INTERFACE_READY |
| A2B-REQ-007 | A→B 字段；分工 B 校准 | 最终批准真实无线数据及 provenance | 外部真实数据依赖（非 A 算法责任） | B calibration loader/manifest contract | Direct/Batch/API/RL | version/hash/source | synthetic software fixture PASS；approved real data absent | BLOCKED_EXTERNAL |

## C→B 外部责任和接口

| ID | 原始来源 | 原始要求摘要 | 责任 | 实现位置 | 正式运行入口 | 可观察证据 | Acceptance test / actual | Status |
|---|---|---|---|---|---|---|---|---|
| C2B-REQ-001 | C §5 | 正式 BiLSTM 模型、权重与 preprocessing | C | ModelAdapter/dispatcher ready | Runtime | MODEL_RESULT/status | recording/null adapter PASS | INTERFACE_READY |
| C2B-REQ-002 | C §6 | 训练完成的 Dueling Q policy 与 reward weights | C | RL/model recommendation contract ready | RL/Runtime | policy recommendation/outcome | parity tests PASS | INTERFACE_READY |
| C2B-REQ-003 | C §7 | 训练完成的 RFF model/preprocessor/threshold | C | RFF adapter/state contract ready | Runtime/RL | result→security→RL | RFF state tests PASS | INTERFACE_READY |
| C2B-REQ-004 | C §5–§7 | 模型 bundle 版本/hash/class mapping/threshold | C | provider/model provenance fields | Runtime | model health/metadata | unavailable semantics PASS | INTERFACE_READY |
| C2B-REQ-005 | C §6 | reward definition/训练算法 | C | B 只返回 components，不硬编码权重 | RL | outcome components | no-reward-weight test PASS | BLOCKED_EXTERNAL |
| C2B-REQ-006 | C §2/§8 | C 自己执行 train/val/test 划分和训练 | C | B 提供 run/plan IDs | Dataset | reproducible grouping keys | loader contract PASS | INTERFACE_READY |
| C2B-REQ-007 | C §7 | 真实 device IQ 与 RF manifest | C/真实设备 | strict manifest/ref interface | Dataset | non-null ref only when real sample | empty/null contract PASS；real IQ absent | BLOCKED_EXTERNAL |
| C2B-REQ-008 | C §5–§8 | 正式模型阈值、归一化和部署资产 | C | adapter bundle contract | Runtime | health/version/quality | interface test PASS | BLOCKED_EXTERNAL |

## 配置 effectiveness 与 dead implementation 审计

- 公开 `RunConfig` 字段逐一进入 runtime 或被明确标为 provenance-only；
  `traffic_profile_id` 当前是 metadata-only，已从 semantic fingerprint 排除。
- `attack_specs`、`normal_disturbance_specs`、`traffic_specs`、
  `session_lifecycle_specs` 在 direct、batch、API、RL 中走同一 runtime；四复杂场景
  parity 测试通过。
- `CalibrationProfile` 在 direct、batch、API、RL 中由同一严格 loader 解析；fitter、
  runtime controls、profile hash/provenance 与基于真实 Runtime events 的 comparison 均有正式调用入口。
- `RuntimeDependencies`/`PlatformRuntimeFactory` 是 Manager、FastAPI controller、Batch Python
  API 与 RL reset 的统一程序级注入路径；stateful provider/model 每 run fresh。
- Attack/Normal subtype 的 accepted parameters 均有消费路径；未知或类型/范围错误均
  fail fast。没有“进入 fingerprint 但行为不变”的未声明 semantic 参数。
- 重点模块 `OnlineEventDispatcher`、`DecisionFusion`、`DefenseTargetResolver`、
  `RedundantExecutor`、`TerminalAuthorizer`、`KeyProvider`、`ProbeService`、
  `ScenarioOrchestrator`、`ScenarioMechanismValidator`、`MissionImpactEvaluator`、
  `SafeModelAdapterRunner`、`BaselineCalibrationFitter`、`RuntimeCalibrationValidator`、
  `PlatformRuntimeFactory` 均由
  `PlatformRuntime`、正式入口或 release gate 调用；不存在以“仅 class + unit test”冒充
  runtime integration 的 IMPLEMENTED 项。

## 完整性统计

| Category | Count |
|---|---:|
| Total original/derived atomic requirements | 120 |
| IMPLEMENTED | 105 |
| INTERFACE_READY | 9 |
| BLOCKED_EXTERNAL | 6 |
| PARTIAL | 0 |
| NOT_IMPLEMENTED | 0 |

B 可独立完成项为 105/105 IMPLEMENTED；PARTIAL=0、NOT_IMPLEMENTED=0。外部 15 项中，
接口可在 B 侧冻结的 9 项为 INTERFACE_READY，正式算法/硬件/真实数据或训练资产 6 项为
BLOCKED_EXTERNAL。这些边界不会被 mock 冒充完成。
