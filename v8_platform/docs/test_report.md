# V11 Test Report（含历史回归记录）

## V11 remaining closure（2026-09-29，当前有效）

| Gate | Actual result |
|---|---:|
| `python -m compileall -q swarm_sim Manager app tools` | PASS |
| V11 focused T1–T12 | **12 passed, 2 dependency warnings** |
| Full Python suite | **410 passed, 2 dependency warnings** |
| Person-A upstream | **37 passed** |
| Person-A platform integration | **46 passed** |
| CSI focused | **4 passed** |
| API/dependency entrypoint focused | **28 passed, 2 dependency warnings** |
| Current scenario mechanism matrix | **22 passed** |
| DatasetValidator / LeakageAudit / C data gates | **44 passed** |
| Frontend `npm ci` | PASS; 306 packages installed; npm reported 13 dependency vulnerabilities |
| Frontend `npm run type-check` / `npm run build-only` | PASS / PASS |

The only Python warnings are the existing FastAPI/Starlette TestClient deprecations. Detailed
before/after runtime evidence is frozen in `docs/v11_remaining_closure.md`.

## V10 five-attack HMAC closure（历史基线）

| Gate | Actual result |
|---|---:|
| `python -m compileall -q` | PASS |
| Application HMAC / five-attack focused suite | 10 passed |
| Current final scenario mechanisms | 21/21 scenarios; test file 22 passed including gradual proof |
| Full Python suite | **398 passed, 2 warnings** |
| Person-A upstream | **37 passed** |
| Person-A platform integration | **46 passed** |
| DatasetValidator / LeakageAudit | PASS |
| Frontend `npm ci` | PASS; 306 packages installed, npm reported 13 dependency vulnerabilities |
| Frontend `npm run type-check` | PASS |
| Frontend `npm run build-only` | PASS; Vite production bundle built |

The two Python warnings are upstream FastAPI/Starlette deprecations. The npm audit findings are
dependency advisories and were not auto-fixed because a forced fix could introduce unrelated
breaking changes. Current semantic evidence is in `v10_five_attack_hmac_closure.md` and
`final_scenario_mechanism_matrix.md`.

## V8 × Person-A crypto integration checkpoint (2026-09-13)

- Person-A original seven-file suite: **34 passed**.
- V8 original suite excluding new integration directory: **355 passed**, 2 dependency
  deprecation warnings.
- Person-A integration suite after SKG closure: **41 passed** (original 36 + 5).
- Combined platform suite: **396 passed**, 2 dependency deprecation warnings.
- Final 22-scenario mechanism matrix: **23 passed**.
- C data/formal acceptance selection: **26 passed**.
- V2–V7 regressions and entrypoint parity selection: **92 passed**.
- Determinism/reproducibility selection: **3 passed**.
- Frontend executable checks: **NOT VERIFIED DUE TO ENVIRONMENT** (`node` and `npm` are not
  installed/visible on this host); no frontend business code was changed.

Detailed A01–A31 evidence and unchanged upstream hashes are in
`docs/person_a_integration_test_report.md`.

## V7 final checkpoint

日期：2026-09-09，Windows / Python 3.13.1。V6 基线 `339 passed`；V7 新增 16 个行为级
acceptance/regression cases，当前收集并全量执行 355 cases。

| Gate | Actual result |
|---|---:|
| compileall (`swarm_sim`, `Manager`, `app`, `tools`) | PASS |
| V7 calibration runtime statistics/composition/entrypoint profile parity | 5/5 PASS |
| V7 dependency/readiness/reset/RL injection/provenance/timeout isolation | 11/11 PASS |
| 22 final scenario mechanisms + combination + C formal gate + V7 suites | 55/55 PASS |
| Full Python suite | **355 passed, 2 warnings in 14.29 s** |
| Coverage run | **355 passed; 87% overall (6,485 statements / 873 missed)** |
| Schema parse / targeted validator+leakage+API+deterministic E2E | PASS / 24 passed |
| `git diff --check` | PASS (line-ending warnings only) |
| Frontend npm/type-check/build | NOT VERIFIED DUE TO ENVIRONMENT (Node/npm unavailable) |

V7 fail-first：新增 tests 最初因 `RuntimeCalibrationValidator` 与 `swarm_sim.factory`
不存在而 collection error；独立反例同时复现 calibration profile 不改变 runtime、Manager
reset 丢 profile、缺 C 模型 readiness 错误、zero-result model 无 provenance、RL 无 model
factory 和 process-wide timeout saturation。完成后全部转绿。

| V7 file | Cases | Gate |
|---|---:|---|
| `tests/acceptance/test_v7_calibration_runtime.py` | 5 | actual signal/loss/latency actuation、runtime comparison、normal-low-SNR composition、units、four-entry profile parity |
| `tests/acceptance/test_v7_runtime_dependencies.py` | 11 | factory/Manager/API/Batch/RL、fresh reset/adapters、readiness、model provenance、timeout cross-run isolation |

校准行为实测：low/high profile 的 runtime loss 为 0/.9302，median latency 为
10.338/499.334 ms，RSSI mean 为 -65.866/-84.555 dBm，SNR mean 为
28.134/9.445 dB。`RuntimeCalibrationValidator` 使用 142 条真实 runtime records，得到
source/runtime loss .10/.1127、latency median 25/25.334 ms。normal low-SNR 组合测试证明
calibration overlay 没有覆盖正常信道扰动。

V7 coverage：runtime 93%、evaluation 97%、PHY/probe 98%、RL 96%、factory 96%、
traffic 94%、decision 91%、model runtime 88%、calibration 83%；较低文件为 Manager 54%、
batch CLI 64%、scenario 75%、validator/scenario validator 79%。coverage 是诊断信息，
不是需求完成证据。

两个 FastAPI/Starlette TestClient deprecation warnings 是依赖告警，不是测试失败。
下列 V6 明细作为历史回归证据保留。

## V6 historical checkpoint

日期：2026-09-09。环境：Windows、Python 3.13.1。V5 基线为 263 cases；V6 主体新增
51 cases，Final Closure Patch 再新增 25 cases，当前收集 339 cases。修改前 patch
基线全量结果为 314 passed；V6 主体反例最初暴露
14 个 V5 correctness/semantics 问题，其余已有正确行为以新增 acceptance test 验证，
没有为了制造红测而破坏实现。

## 分层结果

| Layer | Scope | Actual result |
|---|---|---:|
| L1 | `python -m compileall -q swarm_sim app tools Manager` | PASS |
| L2/L3 | unit + complete Python suite | 339 passed |
| L4 | C V1 regression：RL reset、dispatcher、traffic、coverage、provenance、RFF、validator | PASS |
| L5 | V2–V5 historical regressions | PASS |
| L6 | `test_v5_freeze_audit_regressions.py` | 18 passed |
| L7 | 22 final scenarios + explicit FDI gradual evidence | 23 passed |
| L8 | direct/batch/API/RL four-scenario parity + strict config | 5 passed |
| L9 | leakage/identifier audit in every final scenario | 22 passed |
| L10 | hard-negative pairs | 4 passed |
| L11 | typed target/link evaluator and wrong-link regression | PASS |
| L12 | RL/deployed recommendation-policy parity | PASS |
| L13 | V6 final combination semantics | 7 passed |
| L14 | deterministic reporting/C E2E targeted run | 5 passed |
| L15 | good/corrupted dataset validator targeted gates | 34 passed |
| L16 | frontend type-check/build | NOT VERIFIED DUE TO ENVIRONMENT |
| L17 | final model fault/reporting/eaves/calibration/RL-risk/migration matrices | 23 passed |

Full-suite command:

```text
python -m pytest -q
339 passed, 2 warnings in 20.33 s
```

Warnings are dependency deprecations from FastAPI/Starlette TestClient (`httpx2` and AnyIO
alias); they are not test failures or runtime semantic failures.

## V6 new tests

| File | New cases | Main gate |
|---|---:|---|
| `tests/regression/test_v5_freeze_audit_regressions.py` | 18 | V5 counterexamples, including eligible FDI attempt, negative identifier audit, numeric-SHA opaque-ID stability and shared mission impact |
| `tests/acceptance/test_final_scenario_mechanism_matrix_v6.py` | 23 | 22 data+mechanism scenarios and exact gradual sequence |
| `tests/acceptance/test_v6_entrypoint_parity.py` | 5 | FDI, old replay, Flooding, exposure across four entrypoints; strict subtype config |
| `tests/acceptance/test_v6_final_combination_audit.py` | 7 | compound attribution, no leakage, target scope, business execution, policy parity |
| `tests/acceptance/test_model_fault_tolerance_final.py` | 9 | reset/observe/health exception, timeout, ERROR/UNAVAILABLE/no-result, fixed pool, default subscription |
| `tests/acceptance/test_model_reporting_final.py` | 3 | model/fusion report, dedup, disconnected cache/recovery |
| `tests/acceptance/test_eavesdropping_three_way_final.py` | 4 | ordinary plaintext control, ciphertext protection, exposure, PASSIVE dispatch |
| `tests/acceptance/test_calibration_pipeline_final.py` | 5 | fitter, save/load, Runtime/Batch/API/RL, invalid profile, comparison |
| `tests/acceptance/test_rl_plaintext_protection_risk_final.py` | 1 | locally observable risk without capture truth |
| `tests/acceptance/test_schema_migration_final.py` | 1 | executable schema2 incompatibility strategy |
| existing final matrix parameter extension | 1 | new non-sensitive plaintext scenario |
| **Total** | **76** | 51 V6主体 + 25 patch |

## Mechanism evidence

- FDI command replacement: one eligible modification, FLY_TO → LAND, reached target but
  rejected by unsupported-command business handler.
- FDI abrupt: three modifications, altitude 100 → 150.
- FDI gradual: three modifications, 105 → 110 → 115; the same evidence is produced by
  `run_batch` without manual queue/schedule hooks.
- FDI out-of-range: three modifications to 5000, then range rejection.
- FDI logical inconsistency: three payloads with altitude 120 and state LANDED, then
  consistency rejection.
- Old-session Replay: capture at .2 s, legitimate rotation at .6 s, replay at .8 s,
  receiver result WRONG_SESSION.
- Non-sensitive plaintext Eavesdropping control: captures=3, ordinary plaintext=3,
  ciphertext=0, plaintext exposure=0. Encrypted sensitive case: ciphertext=3,
  exposure=0, protection=true. Unprotected-sensitive case: exposure positives=3.
- Normal out-of-order: 100/102/101 all PASS. Normal state change emits both NODE_STATE and
  consistent legitimate TELEMETRY.

Full row-by-row evidence is in `docs/final_scenario_mechanism_matrix.md`.

## Entrypoint parity

| Scenario | Direct runtime | Batch | FastAPI | RL reset |
|---|---:|---:|---:|---:|
| FDI gradual 105/110/115 | PASS | PASS | PASS | PASS |
| Replay old-session WRONG_SESSION | PASS | PASS | PASS | PASS |
| Flooding receiver-total rate + HMAC gate | PASS | PASS | PASS | PASS |
| Sensitive plaintext exposure | PASS | PASS | PASS | PASS |

## Final Closure Patch evidence

- Model fault matrix: reset exception=`MODEL_RESET_EXCEPTION`; observe exception=
  `MODEL_OBSERVE_EXCEPTION`; health exception=`MODEL_HEALTH_EXCEPTION`; blocked observe=
  `MODEL_INFERENCE_TIMEOUT`. All retain null prediction, the run completes, and the spoofing
  fixture still produces the deterministic-rule result. ERROR, UNAVAILABLE and no-result
  adapter semantics also pass.
- Model reporting: one observable Leader model FDI result produces one correlated defense
  and one GCS report. Low-confidence denial remains one audited report. With Leader→GCS down,
  inbox remains empty while the report is cached; recovery yields one delivery with
  `report_delay_s > 0`.
- Calibration TEST fixture: fitted RSSI mean=-70 dBm, SNR mean=15 dB, loss=.1, latency
  median=19 ms/p95=27.1 ms. Profile round-trip/hash, deterministic direct runtime, Batch,
  FastAPI, RL, invalid-profile rejection and source-vs-simulation comparison all pass.
- RL plaintext protection: unencrypted sensitive traffic produces nonzero local protection
  risk both with and without an attacker; encryption produces risk=0. Actual capture/attacker
  fields are absent.
- Schema migration: schema 2 input produces a structured `REJECTED` report with source/
  target/tool versions, UTC time, source SHA-256, warnings and unrecoverable fields; no
  migrated events are fabricated.
- Opaque-ID release stress: the exact formerly failing batch run whose SHA prefix was
  `563586642103` now yields a non-decimal 12-hex scope; its events pass both leakage audit
  and `DatasetValidator`. This closes a low-probability duplicate-seed false rejection.

## Coverage

Command:

```text
python -m pytest --cov=swarm_sim --cov=Manager --cov=app --cov=tools --cov-report=term-missing -q
```

Final coverage run exited successfully with all 339 tests: 6,269 statements, 861 missed,
**86% overall**. Core runtime was 93%, evaluation 97%, PHY/probe 98%, traffic 94%,
decision 91%, dispatcher 94%, safe model runtime 88%, reporting 92%, and calibration 80%.
Lowest scoped production files were legacy packet/validator command wrappers (0% because
their behavior is exercised through imported implementations), Manager integration (52%),
batch CLI (63%), migration CLI (66%), scenario config validation (75%), and validator/
scenario-mechanism validation (79%). Coverage is diagnostic, not requirement-completion
evidence.

## Frontend and repository checks

- `node` and `npm` are not installed/visible on this host, so `npm ci`, type-check and
  production build could not be executed: **NOT VERIFIED DUE TO ENVIRONMENT**.
- Static inspection confirms both timers call read-only `getRuntime`; no frontend source
  contains polling to `/api/step` or `/api/debug/step`.
- `git diff --check` exits 0 with no whitespace errors; only expected Windows LF→CRLF warnings.
- `.gitignore` covers Python caches, coverage, node_modules and build outputs. Historical
  tracked node_modules/cache artifacts remain in the pre-existing worktree and were recorded,
  not destructively removed during this closure.

## Person-A SKG closure checkpoint (2026-09-13)

本 checkpoint 在 A/B 首次融合的 36 cases 上新增 A28–A31 共 5 个行为级 cases。

| Gate | Command | Actual result |
|---|---|---:|
| A upstream baseline | `python -m pytest -q`（A 独立目录） | 34 passed |
| Original V8 baseline | `python -m compileall -q ...; python -m pytest -q` | 355 passed, 2 warnings |
| Person-A integration | `python -m pytest -q tests/integration/person_a` | 41 passed |
| Combined complete | `python -m compileall -q ...; python -m pytest -q` | 396 passed, 2 warnings |

Fail-first 结果为 5 failed：旧实现无 Probe profile、默认样本不是原 V8、单端 confirm
路径无 pending 状态、重复 rekey 第二次仍 success、cross-confirm conflict 可产生 half key。
修复后 5/5 PASS。

- A28：一个 confirm 经真实 queue/TX/RX 到达时，两端 target epoch 均非 AVAILABLE；另一
  confirm 丢失后 timeout/FAILED，旧 epoch ciphertext 仍 decrypt PASS。
- A29：正反方向重复 rekey 只有一个 active handshake 和一个 probe ID；第二次返回
  `existing_rekey_in_progress`。
- A30：重新 Ed25519 签名但内容冲突的 confirm 在 commit 前触发
  `SKG_CROSS_CONFIRM_CONFLICT`；两端无新 key。
- A31：固定 seed/run 的 `V8_DEFAULT` 16 个 endpoint samples 与原始 V8 逐值一致；compat
  只有显式选择才启用，run metadata 正确且 formal readiness 被阻塞。

同一 64-sample evidence 中，默认 profile 两端 std=1.244/1.296 dB，compat profile
std=7.896/8.010 dB。默认 A v0.1 handshake 保守失败为 reconcile mismatch；compat 的完整
状态链为 `NEGOTIATING → CONFIRM_PENDING → COMMIT_READY → AVAILABLE`。因此报告只把
compat 结果作为 adapter integration evidence，不把它表述为真实 V8 channel success。
