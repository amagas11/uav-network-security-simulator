# V11 Final Status（含历史 closure 记录）

## V11 remaining closure（2026-09-29，当前有效）

- Spoofing/FDI 的在线输出仍只有 generic `AUTH_FAILURE`；离线 evaluator 现能把对应
  `DROP_PACKET executed=true` 归属到已知 episode，`defense_effective=true`。
- Flooding 的 decoded arrival 先进入 receiver-total 统计，非法明文帧随后在普通
  `rx_queue` 前被应用 HMAC gate 丢弃；合法帧不因 aggregate DOS alarm 被误丢。
- 80 pps 表示实际 air-TX attempts。专用 emitter 仍经过 Frame、link、PHY、RX 和 HMAC，
  但不占正常业务 TX service budget，也不产生 attack-end 后 backlog。
- 正式 FastAPI/UI 默认使用 file-relative Person-A bundle、`V8_DEFAULT` Probe 和网络 SKG；
  无预加载 key。Direct/unit 默认 test provider 保持兼容。

实际回归：full pytest **410 passed, 2 warnings**；Person-A upstream **37 passed**；
Person-A integration **46 passed**；CSI **4 passed**。完整证据见
`docs/v11_remaining_closure.md`。

```text
V11 REMAINING CLOSURE: READY
OFFICIAL WEB PERSON-A CSI/SKG/AES: READY (INTEGRATED_DEVELOPMENT)
FIVE-ATTACK SEMANTICS: PASS
```

## V10 五类攻击 HMAC closure（历史基线）

本节覆盖后续历史报告中与当前冻结指令冲突的攻击语义。当前攻击集合为
SPOOFING、EAVESDROPPING、DOS/FLOODING、FDI、REPLAY；DOS/JAMMING 已退役，通用
PHY interference/SNR/SINR/PER/CSI 未删除。

| Family | Attack implementation | Online detection | Data-plane defense | Result |
|---|---|---|---|---|
| SPOOFING | HMAC 后仅修改 claimed device ID | generic application HMAC failure | DROP / no business update | PASS |
| EAVESDROPPING | passive capture | no fabricated deterministic alarm | Person-A CSI/SKG→AES-GCM confidentiality | PASS |
| DOS/FLOODING | External 80 pps-style STATUS load | receiver-total arrival rate | per-frame HMAC gate; no peer rate-limit dependency | PASS |
| FDI | business payload mutation after HMAC | generic HMAC mismatch | DROP / NO_UPDATE | PASS |
| REPLAY | byte-for-byte historical frame replay | HMAC PASS then timestamp/session/window | DROP / no repeated execution | PASS |

Application HMAC uses independent per-device keys, canonical JSON, frozen direction/device/type/
sequence/timestamp-ms/payload-length/payload fields, HMAC-SHA-256 truncated to 16 bytes, and
`compare_digest`. Keys never enter events/dataset/API/frontend. Person-A upstream crypto/CSI/SKG
algorithms were not modified. `SKG_CONTROL` remains separately Ed25519-authenticated.

Current verification: focused HMAC/attack tests 10 passed；current scenario matrix 21/21 PASS；
full pytest 398 passed with 2 upstream deprecation warnings；frontend type-check and production
build PASS。See `v10_five_attack_hmac_closure.md` and the current
`final_scenario_mechanism_matrix.md`.

```text
V10 FIVE-ATTACK HMAC CLOSURE: READY
PERSON-A CSI/SKG/AES REGRESSION: PASS
C ONLINE/OFFLINE DATA ISOLATION: PASS
DOS/JAMMING CURRENT ATTACK CAPABILITY: REMOVED
```

## V8 × Person-A crypto integration addendum (2026-09-13)

The independent Person-A delivery is integrated through a B-side adapter without modifying
or copying its crypto algorithms. A node-local coordinator, A-native AES-GCM provider,
network-carried signed SKG controls, asynchronous network rekey and CredentialService
terminal adapter now enter the same RuntimeFactory used by Direct/Manager/FastAPI/Batch/RL.

All 34 A original tests, 355 V8 baseline tests, 36 new integration tests and 391 combined
tests pass. Five-attack semantics, C secret isolation, validator/leakage gates and the 22
scenario mechanism matrix remain green. Provider maturity is deliberately
`PERSON_A_INTEGRATED_DEVELOPMENT`; simulated reciprocal observations and TEST-only generated
identity/credential assets do not qualify as FORMAL.

```text
PERSON-A CRYPTO LIBRARY: PASS
A→B ADAPTER: READY
A AEAD IN V8: READY
A SKG USING V8 PROBE: READY
A SKG OVER V8 NETWORK: READY
A IDENTITY HANDSHAKE: READY
A TERMINAL CREDENTIAL INTEGRATION: READY
A REKEY INTEGRATION: READY
V8 FIVE-ATTACK REGRESSION WITH A: PASS
C DATA SECURITY AFTER A INTEGRATION: PASS
B PLATFORM REGRESSION: PASS
FORMAL A ASSET MATURITY: INTEGRATED_DEVELOPMENT
FINAL FORMAL EXPERIMENT: BLOCKED_EXTERNAL
```

See `person_a_integration_gap_analysis.md`, `person_a_crypto_integration.md`,
`person_a_security_runtime_semantics.md` and `person_a_integration_test_report.md` for the
contract, conflict resolution and test evidence.

日期：2026-09-09。V7 在唯一工程根目录增量关闭 calibration actuation、实际 runtime
comparison、readiness、统一 dependency factory、calibrated reset、RL model injection、
zero-result model provenance 与跨 run timeout isolation；未修改三份原始需求，也未重构已冻结
的 SimulationClock/逐跳事件/攻击/策略架构。

## V7 功能结论

| Issue | Runtime evidence | Status |
|---|---|---|
| V7F-CAL-ACTUATION-001 | RSSI/SNR bias、background loss、latency controls 实际改变 PHY/RX/traffic | IMPLEMENTED |
| V7F-CAL-RUNTIME-VALIDATION-001 | Fitter→Profile→真实 PlatformRuntime events→source/runtime comparison | IMPLEMENTED |
| V7F-READINESS-001 | 缺任一正式 C model 的 final experiment 为 BLOCKED_EXTERNAL，并列出 blockers | IMPLEMENTED |
| V7F-RUNTIME-DEPENDENCIES-001 | fresh per-run factory 贯通 Direct/Manager/FastAPI/Batch/RL | IMPLEMENTED |
| V7F-MANAGER-RESET-001 | reset 保留 profile/factory/hash/controls，创建 fresh run state | IMPLEMENTED |
| V7F-RL-MODEL-INJECTION-001 | RL reset 经 factory 获得 fresh BiLSTM/RFF，observation 可见合法模型状态 | IMPLEMENTED |
| V7F-MODEL-PROVENANCE-001 | zero-result/unavailable/timeout model 均写 runs model_assets | IMPLEMENTED |
| V7F-MODEL-TIMEOUT-SCOPE-001 | runtime-owned supervisor；坏 run 不污染后续 GoodAdapter | IMPLEMENTED |
| V7F-CALIBRATION-OWNERSHIP-001 | B calibration software 与 external approved data 明确拆分 | IMPLEMENTED |
| V7F-RELEASE-PROVENANCE-001 | producer platform-v7、distribution 7.0.0、schema 3.2.0 | IMPLEMENTED |
| V7F-FINAL-FUNCTIONAL-SMOKE-001 | 22/22 scenarios，selected closure 55/55，full 355/355 | VERIFIED |
| V7F-FINAL-FREEZE-001 | 所有 REQUIRED FUNCTIONAL HARD GATE 通过 | VERIFIED |

### Calibration 实测

- low profile：runtime RSSI mean=-65.866 dBm、SNR mean=28.134 dB、loss=0、median latency=10.338 ms；
- high profile：runtime RSSI mean=-84.555 dBm、SNR mean=9.445 dB、loss=.9302、median latency=499.334 ms；
- actual-runtime comparison：source/runtime RSSI=-68/-69.052、SNR=18/16.948、loss=.10/.1127、latency median=25/25.334 ms；
- generic PHY interference 与 normal low-SNR 仍可在 calibration overlay 上降低对应信号指标；throughput target 明确为 descriptive-only。

### Readiness 与外部边界

默认 mock/null run 的 B platform/calibration/C interfaces 和 dataset generation 为 READY；
A formal assets、approved real calibration 与三项 C trained model assets 为
BLOCKED_EXTERNAL，因此 legacy `experiment_readiness` 正确为 BLOCKED_EXTERNAL。
`dataset_readiness=READY_FOR_C_DEVELOPMENT` 不依赖模型是否已经训练。
全 READY case 只使用显式标注的 formal fixture 验证 readiness 逻辑，不代表真实 A/C
资产已经交付。

### 修改文件

- Runtime：`swarm_sim/calibration.py`, `phy.py`, `factory.py`, `runtime.py`,
  `model_runtime.py`, `rl.py`, `simulation.py`, `validation.py`, `__init__.py`；
- 正式入口：`Manager/simulationmanager.py`, `app/app.py`,
  `tools/run_experiment.py`, `tools/migrate_dataset.py`；
- Contract/release：`dataset/schema.json`, `pyproject.toml`, `readme.md` 及 C/schema/
  architecture/audit/status 文档；
- 新 tests：`tests/acceptance/test_v7_calibration_runtime.py`（5）、
  `tests/acceptance/test_v7_runtime_dependencies.py`（11）。

### Final functional smoke

| Function | Result / evidence |
|---|---|
| Normal multi-hop / link failure | PASS：GCS↔Leader↔Follower hop events、message relation、reroute/cache/recovery |
| Spoofing / three-way Eavesdropping | PASS：UNKNOWN/CONFLICT 与 ordinary/ciphertext/exposure 三路机制 |
| Flooding / FDI / Replay | PASS：receiver-total load + HMAC gate、五 FDI、三 replay lifecycle |
| Six normal hard negatives | PASS：无 attack truth，22-scenario matrix 内逐机制验证 |
| Rule-only and C model closed loop | PASS：rules independent；fake model→fusion→defense→report→GCS |
| RL / RFF | PASS：reset/step、B policy parity、factory-injected BiLSTM/RFF local state |
| Probe / terminal authorization / redundancy | PASS：reciprocal local observations、三 authorization gates、runtime adjudication/recovery |
| Calibration | PASS：fitter→controls→actual Runtime→comparison；generic interference/normal disturbance 可组合 |
| Dataset / evaluator | PASS：schema/validator/leakage/typed metrics and deterministic E2E |
| API lifecycle | PASS：create/start/pause/resume/stop/reset；calibrated reset 保留 profile |

### Final verification

- `python -m compileall -q swarm_sim Manager app tools`: PASS；
- full pytest：355 passed，2 个第三方 deprecation warnings；
- coverage pytest：355 passed，87% overall；
- selected scenario/combination/C/V7 closure：55 passed；
- schema JSON parse、good/corrupt validator、leakage、API、deterministic E2E targeted：PASS；
- `git diff --check`: PASS（仅 Windows LF→CRLF 提示）；
- frontend：Node/npm 在当前 host 不可用，`npm ci`/type-check/build 为
  **NOT VERIFIED DUE TO ENVIRONMENT**；静态检查确认 polling 只调用 read-only
  `getRuntime`，不调用 `/api/step`。

### Remaining non-blocking limitations

- arbitrary permanently blocked third-party native/GPU call cannot be force-killed safely in
  Python；runtime-scoped daemon generation 已保证坏 run 不污染新 run，正式 adapter 应遵守 deadline；
- throughput calibration target 当前是 descriptive validation target，并非强制 actuator；
- schema-2 开发数据无法可靠恢复当前 truth，按 policy structured reject/re-run；
- leakage audit 是验收范围内的规则/统计审计，不是对一切可能相关性的理论证明；
- FastAPI/Starlette TestClient 有两个上游 deprecation warnings，前端 executable build 受宿主环境限制。

### 当前冻结状态

```text
B-SIDE PLATFORM FUNCTIONALITY: COMPLETE
B-SIDE PLATFORM ARCHITECTURE: FROZEN
B-SIDE DATA SEMANTICS: FROZEN
B-SIDE CALIBRATION SOFTWARE: READY
A-SIDE INTEGRATION INTERFACE: READY
C-SIDE DATA INTERFACE: READY
C-SIDE RL ENVIRONMENT: READY
C-SIDE MODEL INTEGRATION INTERFACE: READY
FINAL A ASSETS: BLOCKED_EXTERNAL
FINAL C MODEL ASSETS: BLOCKED_EXTERNAL
FINAL REAL-DATA CALIBRATION: BLOCKED_EXTERNAL
FINAL FORMAL INTEGRATED EXPERIMENT: BLOCKED_EXTERNAL
```

## Preserved V6 closure evidence

## Final Closure Patch 结果

| Patch issue | Closure evidence | Status |
|---|---|---|
| V6P-MODEL-FAULT-001 | external reset/observe/health exception 隔离，null prediction，rules continue | IMPLEMENTED |
| V6P-MODEL-TIMEOUT-001 | bounded worker + configured wall deadline + `MODEL_INFERENCE_TIMEOUT` | IMPLEMENTED |
| V6P-MODEL-REPORTING-001 | correlated MODEL/FUSION/DEFENSE report，Leader→GCS，cache/retry/dedup | IMPLEMENTED |
| V6P-EAVES-CONTROL-001 | non-sensitive plaintext / sensitive ciphertext / sensitive plaintext 三类机制 | IMPLEMENTED |
| V6P-CAL-FITTER-001 | deterministic descriptive fitter、missing warning、hash/provenance | IMPLEMENTED |
| V6P-CAL-ENTRYPOINT-001 | CalibrationProfile 在 Runtime/Batch/FastAPI/RL 同一 loader | IMPLEMENTED |
| V6P-RL-PLAINTEXT-RISK-001 | local protection risk 可观察；actual capture truth 不进入 state | IMPLEMENTED |
| V6P-SCHEMA-MIGRATION-001 | executable schema2 incompatibility report；不猜值/不伪造 JSONL | IMPLEMENTED |
| V6P-EXHAUSTIVE-AUDIT-CORRECTION-001 | 原子审计扩为 113 项并拆开 B 软件/外部真实资产 | IMPLEMENTED |
| V6P-OPAQUE-ID-STABILITY-001 | 纯数字 SHA scope 不再被误判为端点编码；真实失败 run 固化回归 | IMPLEMENTED |
| V6P-FINAL-FREEZE-001 | 339 full suite + 22 scenario + parity/leakage/validator gates | VERIFIED |

## V6 Issue 结果

| Issue | V5 problem | V6 closure | Status |
|---|---|---|---|
| V6-SCENARIO-MECHANISM-001 | valid dataset 可掩盖空机制 | 独立 data-contract + subtype mechanism gates；22/22 | VERIFIED |
| V6-FDI-SCHEDULING-001 | FDI 常在业务入队后才 schedule | config scheduler 先激活 attack、后 queue eligible traffic；batch 同路径 | VERIFIED |
| V6-FDI-ATTEMPT-001 | 无关 packet 也可置 attempted | active/opportunity/attempt/injected 分层，sender/target/type/field 后标记 | VERIFIED |
| V6-ID-PRIVACY-001 | session/link ID 编码端点/scenario | run-scoped opaque public IDs + offline map +出口清洗 | VERIFIED |
| V6-NORMAL-ID-LEAK-001 | normal/replay 名进入 session | 所有 online session/link/probe/flow ID 统一 opaque | VERIFIED |
| V6-EXTERNAL-DISPATCH-001 | 模型可运行在攻击者 observer | dispatcher 默认仅 GCS/Leader/Follower；external 无 model/defense result | VERIFIED |
| V6-RL-DEPLOYMENT-PARITY-001 | RL 直接调用 executor | RL/model 都走 recommendation→fusion→auth→resolver→permission→executor | VERIFIED |
| V6-EVAL-TYPED-SCOPE-001 | same-node wrong-link 可冒充 recovery | NODE/LINK/MESSAGE/FLOW/COMPOSITE scope 与 link precedence | VERIFIED |
| V6-BUSINESS-EXECUTION-001 | delivery 自动等于恶意执行 | `BusinessApplyResult` 分 accepted/executed/state change/reason | VERIFIED |
| V6-SESSION-LIFECYCLE-001 | old session 只能 test helper rotation | strict config lifecycle，batch/API/RL 可产生真实 WRONG_SESSION | VERIFIED |
| V6-PLAINTEXT-EXPOSURE-001 | 缺正式 exposure 正样本 | ciphertext-only 与 unauthorized sensitive plaintext 两条正式路径 | VERIFIED |
| V6-SUBTYPE-CONTRACT-001 | parameter typo/ignored field 静默 | attack/normal typed/range contracts，四入口 fail-fast | VERIFIED |
| V6-LEAKAGE-AUDIT-001 | 未扫 identifier shortcut | literal + ID + payload/type/size/extension bounded audit | VERIFIED |
| V6-HARDNEG-STATE-001 | normal state change 无 telemetry 对照 | 合法 state→consistent telemetry；FDI 为 state 不变/telemetry 修改 | VERIFIED |
| V6-MISSION-IMPACT-001 | label/RL/evaluator 来源不统一 | 共享 evidence-based `MissionImpactEvaluator`，不足时 explicit unavailable | VERIFIED |
| V6-MATURITY-SEMANTICS-001 | FORMAL 概念混合 | provider/calibration/dataset/readiness 四维 provenance | VERIFIED |
| V6-FINAL-ENTRYPOINT-PARITY-001 | helper 与正式入口不一致 | 一份 strict RunConfig/ScenarioOrchestrator 驱动 direct/batch/API/RL | VERIFIED |
| V6-FINAL-FREEZE-GATE-001 | test 数量替代需求闭环 | 113 原子需求审计 + history + mechanism/parity/leakage/validator gates | VERIFIED |

## 主要修改文件

- Runtime/scenario/outcome：`swarm_sim/runtime.py`, `scenario.py`,
  `scenario_validation.py`, `attacks.py`, `normal.py`, `domain.py`, `mission.py`；
- Security/model/RL/evaluation：`decision.py`, `dispatch.py`, `security.py`, `rl.py`,
  `evaluation.py`, `adapters.py`, `model_runtime.py`, `reporting.py`；
- Identity/data/PHY：`simulation.py`, `events.py`, `leakage.py`, `packets.py`,
  `traffic.py`, `phy.py`, `probe.py`, `validation.py`, `dataset.py`；
- Formal entrypoints/contracts：`tools/run_experiment.py`, `app/app.py`,
  `Manager/simulationmanager.py`,
  `tools/migrate_dataset.py`, `swarm_sim/calibration.py`, `dataset/schema.json`,
  `pyproject.toml`, frontend version display, README and V6 docs；
- Tests：V6 regression, final mechanism matrix, entrypoint parity and final combination
  suites plus tightened historical assertions.

## Final scenario evidence

The 22-scenario table is `docs/final_scenario_mechanism_matrix.md`; every row is validator
valid, leakage-audit pass and mechanism-gate pass. Key evidence:

- FDI: command replacement=1 modification; abrupt=150/150/150; gradual=105/110/115;
  out-of-range=5000×3; logical inconsistency=(altitude 120, LANDED)×3. All five have
  attempted/injected=true and real modification truth.
- Formal `run_batch` gradual FDI independently reproduces injected=true and 105/110/115;
  no manual test queue/schedule hook is used.
- Spoofing UNKNOWN and KNOWN_ID_CONFLICT each generate receiver auth evidence; claimed GCS0
  is never chosen as isolation target merely because it was claimed.
- Flooding generated/transmitted 84 observable malicious-load messages with max local rate
  72 pps. Normal burst uses the same STATUS template and overlapping packet size support.
- The former target-link attack row is retired in V10; generic PHY link scope remains covered
  by topology/calibration/normal-disturbance tests without exposing it as a DoS subtype.
- Immediate Replay: capture .2/replay .6/DUPLICATE. Delayed: .2/.8 with configured .6 s
  delay. Old session: A at .2, legitimate rotation .6, old replay .8, WRONG_SESSION.
- Ciphertext-only eavesdrop: 3 captures, 0 exposure. Explicit unprotected sensitive case:
  3 captures, 3 plaintext-exposure positives. The new ordinary non-sensitive control has
  3 captures, ordinary=3, ciphertext=0, exposure=0 and is not a positive.
- A synthetic TEST calibration fixture fits RSSI=-70 dBm mean, SNR=15 dB mean, observed
  loss=.1 and latency median=19 ms; its profile ID/hash and full manifest are identical
  through Runtime, Batch, FastAPI and RL. This proves B software, not real-data approval.
- Model reset/observe/health errors and a 5 ms inference timeout leave the run completed;
  failed results have null prediction. Model detection/defense reporting reaches GCS once,
  or remains cached until link recovery with positive report delay.

## Correctness examples

- Actual opaque-ID sample: `sess-8df506d759f0-00000001` and
  `lnk-8df506d759f0-00000005`; neither endpoint `-1`, scenario nor profile text is embedded.
- A release-stress batch exposed SHA scope `563586642103`, whose all-decimal appearance was
  falsely read as endpoint encoding. The factory now deterministically disambiguates that
  rare form without changing the frozen 12-hex schema; the exact run exports validator-valid data.
- EXTERNAL spoof TX can remain simulator/offline evidence, but Recording BiLSTM receives no
  observer_role=EXTERNAL and no external MODEL_RESULT/DEFENSE_RESULT is generated.
- In a normal episode, RL recommendation to isolate GCS0 without trusted evidence is
  denied/deferred. The same evidence/recommendation through deployed adapter produces the
  same B decision semantics.
- FDI FLY_TO→unsupported LAND can be injected and reach the target while
  `malicious_content_executed=false`, `attack_effective=false`.
- `sim_time_s="bad"`, wrong nested PHY values, unknown observer/role, fake attack ID,
  unknown frozen keys and bad refs return validator invalid without ordinary-data crashes.
- `delta_per_stpe`, unknown normal params and top-level `attak_specs` fail fast at formal
  batch/API/RL configuration boundaries.
- RFF UNKNOWN remains in later AUTH/PHY/QUEUE snapshots and increments RL anomaly count;
  model output, not device truth, is the state source.
- Unmeasured compute/communication overhead is null with availability=false and
  `NOT_MEASURED`, not fake zero.
- Measured gradual-FDI mission sample is `mission_impact=0.5`, availability=true, with
  `unauthorized_state_change=0.5`; label and evaluator match. Where evidence is insufficient,
  value is null with availability=false in labels, RL and evaluation.
- The same sample records security maturity=TEST, calibration=UNCALIBRATED,
  dataset=DEVELOPMENT and experiment readiness=BLOCKED_EXTERNAL.

## Tests and quality

- New V6 tests: 76 total, including **25 Final Closure Patch cases**.
- Full Python suite: **339 passed, 2 dependency deprecation warnings**.
- Coverage: **86% overall** across `swarm_sim`, `Manager`, `app`, and all `tools`;
  runtime 93%, evaluation 97%, PHY/probe 98%, traffic 94%.
- 22 final scenarios + one exact gradual proof: 23 passed.
- Four-entrypoint parity/strict contract: 5 passed.
- Final combination semantics: 7 passed.
- Targeted validator/C data gates: 34 passed.
- Targeted deterministic e2e: 5 passed.
- Python compileall (runtime/API/tools/Manager): PASS. JSON schema parse: PASS.
  `git diff --check`: PASS (line-ending
  warnings only).
- Frontend: Node/npm unavailable on this host, so dependency install/type-check/build is
  **NOT VERIFIED DUE TO ENVIRONMENT**. Static source verification confirms timers call
  read-only `getRuntime`; no polling-to-step path exists.

## Original requirements closure

`docs/v6_exhaustive_requirement_audit.md` contains 113 atomic rows:

- IMPLEMENTED: 98;
- INTERFACE_READY: 9;
- BLOCKED_EXTERNAL: 6;
- PARTIAL: 0;
- NOT_IMPLEMENTED: 0.

All 98 B-owned, non-external requirements have a formal path and a passing acceptance test.
The audit separately records configuration-effectiveness and dead-implementation checks;
important requirement modules are runtime or release-gate integrated rather than merely
instantiated in unit tests.

## Remaining known issues and external dependencies

No known P1 B-side correctness issue in the V6 closure scope remains. Non-blocking engineering
items are:

- frontend build could not be re-executed without Node/npm;
- FastAPI/Starlette tests emit two upstream deprecation warnings;
- historical tracked node_modules/cache/old project artifacts predate V6; `.gitignore` now
  protects new output, but bulk `git rm --cached` was deliberately not performed;
- the current leakage audit is a bounded rules/statistics gate, not proof against every
  possible learned correlation.

External deliverables remain: A formal SKG/KeyProvider/crypto/terminal credential and secure
root of trust; C trained/versioned BiLSTM, Dueling-Q and RFF assets, preprocessing, thresholds
and reward; real device IQ/RF manifest and approved calibration dataset/version/hash/license.
The bundled mock/simulated providers are explicitly TEST-only, so formal experiment maturity
cannot be claimed.

## Freeze status

```text
B-SIDE ARCHITECTURE: FROZEN
B-SIDE DATA SEMANTICS: FROZEN
B-SIDE CALIBRATION PIPELINE: READY
C-SIDE DATA PIPELINE: READY
C-SIDE RL ENVIRONMENT: READY
C-SIDE MODEL DEPLOYMENT ADAPTER: READY
A-SIDE SKG/CRYPTO INTERFACE: READY
FINAL REAL-DATA CALIBRATION: BLOCKED_EXTERNAL
FINAL FORMAL EXPERIMENT: BLOCKED_EXTERNAL
```

This freezes B's schema/communication/attack/event/policy semantics as the A/C integration
baseline. Future work should be adapter/model/calibration assets, parameter tuning,
backward-compatible maintenance or confirmed correctness bugs—not another architecture
redesign.

## Person-A SKG closure patch

融合版现已恢复原始 V8 Probe 为唯一默认 `V8_DEFAULT`；先前为 A v0.1 exact-match
quantizer 使用的双状态统计被隔离为显式 `PERSON_A_V01_COMPAT_TEST`，标记 TEST_ONLY，
写入 provenance/fingerprint，并阻止 formal readiness。

SKG confirm 已改为 pairwise two-phase commit。一个 endpoint 收到 confirm 只形成
`CONFIRM_PENDING`，双方 authenticated confirm 齐全且 cross-verify 通过才进入
`COMMIT_READY` 并调用两个 A engine。A28 的单侧丢失和 A30 的 cross conflict 均证明
双方无新 epoch；旧 epoch 仍可用。`RekeyCoordinator` 对 pair/session/target epoch 去重，
重复请求返回 `existing_rekey_in_progress`。

实际结果：A upstream 34 passed；原始 V8 355 passed；Person-A integration 41 passed；
融合版 complete suite 396 passed。A 五个核心密码文件未修改。

```text
AEAD INTEGRATION: READY
SKG ADAPTER/NETWORK/TWO-PHASE BASELINE: READY
SKG V8_DEFAULT/REAL-RF COMPATIBILITY: NOT FORMALLY VALIDATED
IDENTITY INTEGRATION: READY (TEST IDENTITY; FORMAL ASSET EXTERNAL)
CREDENTIAL INTEGRATION: READY (SIMULATED FINGERPRINT; FORMAL ASSET EXTERNAL)
REKEY INTEGRATION: READY
FIVE-ATTACK REGRESSION: PASS
A CRYPTO INTEGRATION BASELINE: READY
FORMAL A ASSET MATURITY: INTEGRATED_DEVELOPMENT
FINAL FORMAL EXPERIMENT: BLOCKED_EXTERNAL
```

正式信道的剩余边界记录在 `person_a_change_requests.md` 的 A-CHANGE-001；不能以
compatibility profile 的成功率替代 A 算法对原始 V8/批准实测数据的验收。
