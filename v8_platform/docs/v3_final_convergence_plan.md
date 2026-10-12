# V3 最终收敛修复计划与完成记录

依据：`分工安排.md`、`A_B_无线观测字段说明.md`、`c需求文档.md`（当前工程中的三份原始需求文件）以及 V3 最终收敛指令。原始需求未修改。`docs/requirements_conflicts.md` 复核后仍无阻塞实施的实质冲突。

状态口径：`IMPLEMENTED` 仅表示主运行路径接入、语义完整且 acceptance test 通过；`VERIFIED_EXISTING_BEHAVIOR` 表示 V2 行为经新增/既有需求级测试复核，无机械重写。A/C 正式资产和真实数据不使用这两个状态。

| Issue ID | Requirement Source | V2 Current Behavior | Expected Behavior | Root Cause | Files | Acceptance Test | Implementation | Verification | Final Status |
|---|---|---|---|---|---|---|---|---|---|
| V3-RL-001 | C §6；V3 §3 | RunConfig 丢 episode plans；reset 后需手排攻击；step 未形成决策后闭环 | reset 自动装载 attack/normal plan；phase metadata 不泄漏；action 后推进 `decision_step_s`；真实 outcome | 配置字段缺失，step 未保存 action 前基线 | `simulation.py`, `rl.py`, `runtime.py`, C interface | C acceptance RL-1…RL-8；反例 CASE 1 | 完整 plan 进入 RunConfig；按 SimulationClock 推进；由事件/队列差分计算 impact/block/harm/mission/traffic | scheduler>0；同 seed plan 相同；rate-limit 改变后续恶意/合法流；recovery 出现；无 reward/truth | IMPLEMENTED |
| V3-DISPATCH-001 | C §5/§6；V3 §4 | runtime 调用点手工指定 model，AUTH/NODE/TOPO 等被过滤 | event store 后单一 dispatcher；声明订阅；上游 result 单向送 DQ；无递归 | 分发职责散落在 event producer | `dispatch.py`, `adapters.py`, `runtime.py` | RecordingAdapter；CASE 2/3 | `OnlineEventDispatcher` 统一处理所有 event | BiLSTM 实收 AUTH/RX/PHY/QUEUE/NODE/TOPO；DQ 实收 AUTH/PHY/QUEUE/BiLSTM result；RFF 实收 RX/PHY；结果数有限 | IMPLEMENTED |
| V3-PROVENANCE-001 | C §2–§4/§12；V3 §5 | runs 仅摘要/hash；攻击 parameters、normal plan 与 ID 缺失 | 完整 secret-free config/plans、稳定 IDs、全语义 fingerprint | context 不知道 runtime scheduler 最终计划 | `simulation.py`, `attacks.py`, `runtime.py`, schema | metadata C acceptance；CASE 7/8 | run record 由实际 scheduler 导出；canonical plans 排除 run-scoped ID 后 hash | `delta=5/50` 与 normal A/B fingerprint 均不同；calibration refs 保留 | IMPLEMENTED |
| V3-RUNID-001 | C 可复现性；V3 §6 | seed 同时被当 identity，重复 seed 覆盖 | seed 与实例 identity 分离，目录也唯一 | batch 缺 batch ID/run index | `tools/run_experiment.py` | C batch test；CASE 6；实际 `[7,7]` batch | UUID batch ID + run index + readable seed | 两 run ID/目录不同、semantic event hash 相同、均 validator valid | IMPLEMENTED |
| V3-REPLAY-SESSION-001 | C Replay；V3 §7 | 一个 direction 仅一个 active session；同源并发流仍可能互相覆盖 | 同 hop/key epoch 多合法 business session；显式 stale 与 epoch lifecycle；窗口按完整 context 隔离 | 单值 `_active_sessions`；message ID 被误当恶意 transmission identity | `security.py`, `domain.py`, `runtime.py` | RS-1…RS-5；增强 4-node E2E | active set + stale set；epoch rotation 退休旧 context；runtime-private transmission attack ID | F2/F3 两 hop 均 PASS；同源 concurrent session 亦不冲突；OLD_SESSION=`WRONG_SESSION`；duplicate/reorder/epoch/reset PASS | IMPLEMENTED |
| V3-VALIDATOR-001 | C 数据契约；V3 §8 | 坏类型记录后仍 cast；nested/refs 校验不完整；某些数组值可触发 unhashable | 对不可信输入尽量收集 errors、永不因普通字段错误崩溃；schema-driven nested 校验 | 手写字段和无类型守卫的语义后检查 | `validation.py`, `dataset/schema.json` | CASE 4/5；bad type/range/enum/ref/NaN/unhashable tests | 通用 required/type/nullable/enum/range/pattern/object/item refs + guarded cross-reference | good=true；`sim_time="bad"`、bad RSSI/PER/queue/enum/ref/NaN/array 均 false、无异常 | IMPLEMENTED |
| V3-EVAL-EAVES-001 | C §5.2；V3 §9.1 | passive capture 可能进入普通 FN | 从普通 confusion matrix 排除，单独 exposure/protection/service | evaluator 将所有 attack label 当 detection-positive | `evaluation.py` | CASE 10、EV-1/EV-2 | passive policy 与普通 detection universe 分离 | detection episodes=0、family matrix 无 EAVESDROPPING、ciphertext protected/protection effective 正确 | IMPLEMENTED |
| V3-EVAL-JAMMING-001 | C §5.4；V3 §9.3 | 通用公式要求 blocked packet，不适合无恶意包的 Jamming | channel/path action + PHY/合法服务恢复判 effective | 单一 defense 布尔公式 | `evaluation.py`, `attacks.py`, `runtime.py` | CASE 11、EV-3/EV-4 | narrowband jammer 固定原频道；policy 使用 SINR/PER/成功通信/recovery | 成功切频且恢复=true（blocked=0）；执行但未恢复=false | IMPLEMENTED |
| V3-EVAL-FAMILY-001 | C §5；V3 §9 | 所有 family 共用 criterion；action 容易等同效果 | registry 按 Flooding/Replay/Spoofing/FDI/Jamming 分发 | 缺 evaluator policy boundary | `evaluation.py` | family policy parametrized tests + V2 evaluator suite | `EvaluationPolicyRegistry` 返回 policy/evidence；action/effect 分离 | Flooding/Replay block 与 continuity、Jamming PHY/service、失败 action 反例均正确 | IMPLEMENTED |
| V3-BATCH-NORMAL-001 | C NORMAL；V3 §10 | batch 仅 attack plan | CLI/API 同时接 attack/normal plan，normal 进 provenance 不进 labels | runner 缺 normal argument | `tools/run_experiment.py` | C duplicate-seed/normal batch | `--normal-disturbance-plan` 与 `normal_disturbance_specs` | normal plan 非空、plan ID 非空、labels 空、fingerprint 受参数影响 | IMPLEMENTED |
| V3-VERSION-001 | V3 §11 | producer 仍写 `platform-v1` | software=`platform-v3`，与 schema 独立 | 默认/API/UI 硬编码 | `simulation.py`, `app.py`, frontend, `pyproject.toml` | API/run metadata tests | 常量统一；拒绝非 V3 producer config；UI 展示 metadata | run/API/UI=`platform-v3`；distribution=`3.0.0` | IMPLEMENTED |
| V3-SCHEMA-001 | C §2/§3/§12；V3 §12 | 1.0 名义与 V3 required provenance 不兼容 | 正式判断版本，形成 machine-readable frozen contract | required 字段变化未做版本升级 | `dataset/schema.json`, `data_schema_v1.md`, `schema_version_decision.md` | schema/validator/metadata tests | 18 objects 全字段 descriptor；nested constraints；版本升 `2.0.0` | runtime/on-disk/schema/validator 一致，descriptor gaps=0 | IMPLEMENTED |
| V3-E2E-C-ACCEPTANCE-001 | V3 §23–§24 | V2 tests 分散，未同时覆盖一键 plan/dispatcher/multi-session/provenance/corrupt data | 4 节点 normal→disturbance→Replay→detect/defense→Leader/GCS→recovery；两次一致 | 缺 C 视角综合 gate | `tests/acceptance/test_c_data_acceptance_v3.py`, `tests/regression/test_v2_audit_regressions.py` | C acceptance 11/11；V2 counterexamples 22/22 | 新增正式 acceptance/regression suites；增强 E2E 同时覆盖多源会话和报告 | 1,243 events、1 label、1 GCS report；Replay TP=1/FP=0/FN=0/TN=1；两次 semantic projection 相同 | IMPLEMENTED |

## V2 正确能力回归

| Capability | Verification | Final status |
|---|---|---|
| FDI | 五子型；`105,110,115`；动态 baseline；reset/plan state 隔离；pre-crypto auth PASS；truth-only original/modified | VERIFIED_EXISTING_BEHAVIOR |
| Traffic | 非空 inter-arrival/rates；flooding 增速；duplicate/gap；observer isolation；reset | VERIFIED_EXISTING_BEHAVIOR |
| Normal disturbances | 六类均走真实 PHY/traffic/state 路径、进入 provenance、labels 为空 | VERIFIED_EXISTING_BEHAVIOR |
| Topology | failure/recovery local update/version/path；unrelated observer 无全局图 | VERIFIED_EXISTING_BEHAVIOR |
| RFF | 18 required manifest fields、path/ref/hop；null/empty 合法；无 fake IQ | VERIFIED_EXISTING_BEHAVIOR |
| Probe | reciprocal latent、独立 receiver noise/local SNR、direct neighbor、missing 不补 0 | VERIFIED_EXISTING_BEHAVIOR |
| Rekey | KeyProvider success/failure/transitions/reason；无 raw secret | VERIFIED_EXISTING_BEHAVIOR |
| Redundancy | PlatformRuntime 三 logical replicas、adjudication/degrade/recovery | VERIFIED_EXISTING_BEHAVIOR |
| Terminal authorization | Runtime PROGRAM_START/NETWORK_JOIN/SENSITIVE_COMMAND/copy attack | VERIFIED_EXISTING_BEHAVIOR |
| Leader aggregation | aggregate、emergency bypass、断链 cache/recovery/report delay；另修持续转发时本地报告饥饿 | IMPLEMENTED |

## Fail-first 证据

- V3 两个新测试文件第一次完整运行：`16 failed, 2 passed`。失败直接对应 plan 丢失、手工 model 过滤、provenance 缺失、seed ID 覆盖、multi-source session、validator 崩溃/漏检、passive eaves FN 和 Jamming criterion。
- 增强 deterministic E2E 首跑真实得到合法消息 `WRONG_SESSION`；session active-set 修复后，下一次又真实暴露持续 forward queue 使 GCS report 饥饿；公平队列修复后通过。
- 结果抽查又暴露 Replay 复用 message ID 使合法原消息被误计 `malicious_delivered_after_action=1`；改为 runtime-private transmission identity 后为 0，且 `defense_effective=true`。该私有字段不写 events。
- V2 已正确项目均以现有 acceptance test 复核后标 `VERIFIED_EXISTING_BEHAVIOR`，未人为破坏实现制造红测。

## Final gate

最终证据：C-side acceptance `11 passed`；V2 audit regression `22 passed`；全量含 coverage `154 passed, 2 upstream warnings`；compileall、good/corrupt validator、duplicate-seed batch、deterministic E2E、frontend type-check/build、`git diff --check` 全部完成。B 侧 P1/P2 硬门槛通过；外部模型/密钥/真实数据边界不属于假实现。
