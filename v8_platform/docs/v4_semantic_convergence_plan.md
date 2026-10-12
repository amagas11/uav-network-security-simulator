# V4 Semantic Convergence Plan

This file is the live requirement-level ledger for the V4 convergence pass. The
three original requirement documents remain unchanged and are the source of
truth. `FAIL_FIRST` means the V3 counterexample was reproduced; `VERIFIED` means
the required behavior is covered by a passing acceptance/regression test.

| Issue ID | Requirement source | V3 current behavior / risk | Expected semantics | Affected files | Failing counterexample | Implementation / verification | Final status |
|---|---|---|---|---|---|---|---|
| V4-FLOOD-REF-001 | C dataset references; V4 §3 | Queued Flooding messages were immediately written to `affected_message_ids`; an end-of-run backlog could reference no event. | Generated/queued/observable message lifecycle is explicit; affected IDs reference real events only; no fake TX. | `swarm_sim/runtime.py`, validator/schema, V4 tests | Short high-rate run with backlog | Added generated/queued/affected/backlogged lifecycle; only real TX promotes a message to affected; schema and ref validator enforce it. Backlog sample: generated=20, queued=20, affected/TX=2, backlogged=18; export valid. | VERIFIED |
| V4-LABEL-PROXY-001 | C online features; V4 §4 | `FLOOD` and `LEGITIMATE_BURST` packet types reveal the answer. | Attack and hard-negative traffic share ordinary business packet types; leakage scanner rejects answer literals. | runtime, events/validator, schema, tests | Flooding vs normal burst categorical scan | Both paths use configured ordinary business types (`STATUS` by default); recursive scanner rejects attack/normal answer literals outside audited outputs. Hard-negative test observes the same `STATUS` type. | VERIFIED |
| V4-NORMAL-LEAK-001 | Events/labels isolation; V4 §5 | Normal plan/type appears in event extensions/missing reasons. | Scenario truth remains in run provenance only; events contain effects only. | runtime, events/validator, tests | Six normal controls scanned recursively | Removed normal-plan names/markers from events and payload metadata; all six plans remain complete in `runs.jsonl`; 7 normal datasets are recursively leak-free. | VERIFIED |
| V4-FDI-SEMANTICS-001 | `c需求文档.md`; V4 §6 | FDI incorrectly required attacker to be a target and selected mutation by target membership. | Compromised origin is attacker; target is business receiver; legitimate auth remains possible. | attacks, runtime, tests | attacker=2, target=[1] | Scheduler accepts actor 2/receiver 1; mutation requires origin=2 and final destination=1. Origin 3 or destination 0 remains unchanged; legitimate pre-crypto auth passes. | VERIFIED |
| V4-EVAL-SCOPE-001 | C evaluation; V4 §§7–9 | Family/time-only matching lets unrelated nodes create TP/recovery. | Detection and defense use an explicit attack episode scope (targets/links/messages/observers/evidence). | evaluation, tests, docs | node-3 alarm/recovery for node-2 attack | Added `AttackEpisodeScope` and scope-aware alarm, defense, PHY, service and reporting filters. E-SCOPE-1..5 pass: node-3 alarm/recovery cannot satisfy node-2 episode. | VERIFIED |
| V4-REPLAY-LIFECYCLE-001 | C Replay; V4 §10 | OLD_SESSION attack path directly expires receiver detector state. | Legitimate session rotation makes an old context stale; attacker only captures/retransmits. | runtime, security, tests | A active → B active → replay A | Added legitimate `rotate_security_session`; receiver lifecycle makes A stale before replay. Replay path only captures/retransmits, contains no detector expiry call; replay A returns `WRONG_SESSION`. | VERIFIED |
| V4-RFF-STATE-001 | C RFF/RL; V4 §11 | RFF `MODEL_RESULT` is logged but not reflected in node-local security/RL state. | Model prediction updates observer-local RFF state and anomaly count without device-truth use. | domain, events, runtime, schema, tests | Fake RFF UNKNOWN | RFF prediction updates observer-local result/confidence/quality/time; UNKNOWN increments a resettable anomaly counter. Later events and RL observation expose this local state only. | VERIFIED |
| V4-MODEL-DEFENSE-001 | B/C boundary; V4 §12 | Model recommendations stop at logging. | Configurable B-side fusion authorizes recommendations and invokes `DefenseExecutor`, with audit and rule priority. | new decision module, runtime/config/schema, tests | Observable-triggered fake BiLSTM recommendation | Added `DecisionFusion`: status/quality/confidence/rule priority are B-controlled; accepted recommendations invoke the existing executor and emit audited `DEFENSE_RESULT`; low confidence and rule conflict are rejected. | VERIFIED |
| V4-VALIDATOR-SEMANTIC-001 | Frozen dataset contract; V4 §13 | Validator misses observer/role/attack references, unknown nested keys, and some event semantics. | Fault-tolerant schema plus cross-file validation. | validation, schema, tests | corrupted observer/role/attack/core field | Validator now checks run observer membership/role, label plan IDs, normal-run labels, all refs, frozen nested keys, decode semantics, maturity/providers and answer proxies while continuing after ordinary bad data. | VERIFIED |
| V4-CONFIG-STRICT-001 | Formal reset/batch API; V4 §14 | Unknown RunConfig keys are silently discarded. | Strict-by-default config with explicit legacy opt-out. | simulation, callers, tests | `attak_specs` typo | `RunConfig.from_dict(..., strict=True)` is default; formal API, RL and batch use it. Typo raises `ConfigValidationError`; explicit `strict=False` remains a legacy escape hatch. | VERIFIED |
| V4-EPISODE-PHASE-001 | Reproducibility; V4 §15 | Metadata-only phase config changed the semantic hash. | Phases remain evaluator metadata and are excluded from behavioral fingerprint. | simulation, docs, tests | Two metadata phase maps | Declared metadata-only, absent from online observation and excluded from semantic fingerprint; different metadata maps produce identical behavioral fingerprints. | VERIFIED |
| V4-TRAFFIC-PROFILE-001 | Reproducibility; V4 §16 | Unimplemented traffic profile ID changed semantic hash. | Until a registry exists the reference is provenance-only and excluded from behavior hash. | simulation, docs, tests | Two unknown profile IDs | Declared provenance-only until a loader exists and excluded from semantic fingerprint; direct rate/mix plan parameters remain semantic and hashed. | VERIFIED |
| V4-GAP-WINDOW-001 | C traffic statistics; V4 §17 | Implementation tracks unresolved gaps while surrounding metrics are rolling. | Schema/docs explicitly define current unresolved sequence gaps (resolved late arrivals clear them). | traffic, schema/docs, tests | gap then late arrival | Contract now explicitly defines current unresolved observer-local gaps; sequence 100→102 reports one, later 101 clears it. | VERIFIED |
| V4-PROBE-CHANNEL-001 | A reciprocal probing; V4 §18 | Channel switch can leave reverse frequency stale; probe does not reject mismatch. | Coordinated reciprocal switch; defensive mismatch result is explicit missing. | phy, probe, schema, tests | switch/probe reverse link | Channel switch coordinates both directions; a manually inconsistent reverse link yields `missing=true`, `FREQUENCY_MISMATCH`, never fabricated reciprocal data. | VERIFIED |
| V4-PROVIDER-PROVENANCE-001 | A boundary; V4 §§19, 28–29 | Run does not identify mock key/crypto/terminal providers or maturity. | Non-secret provider records and DEVELOPMENT/PRELIMINARY/FORMAL maturity; formal-security gate. | simulation/runtime/schema/batch/docs/tests | Default mock and require-formal run | Runs record key/crypto/terminal name/version/status and maturity with no secrets. Built-ins are DEVELOPMENT/TEST_ONLY; formal-security/FORMAL generation is refused. | VERIFIED |
| V4-SCHEMA-GOVERNANCE-001 | C schema contract; V4 §20 | C has migration note but no consolidated 2.0 contract/example. | Document 2.0 breaking migration and produce a validated example dataset. | schema/docs/example/tests | Schema contract acceptance | Added consolidated C contract and checked `schema_2_0_example_dataset`; exact schema copy validates with 75 events/1 label/0 RF samples (intentional warning only). | VERIFIED |
| V4-NULL-MODEL-001 | Adapter availability; V4 §21 | Null adapters emit an UNAVAILABLE result for every subscribed event. | Null adapter emits no per-event predictions; health remains UNAVAILABLE. | adapters/tests | Default run model-noise count | `observe()` returns no results; `health()` remains UNAVAILABLE. Default runs no longer create high-frequency unavailable predictions. | VERIFIED |
| V4-FINAL-DATASET-MATRIX-001 | V4 §§22–30 | A single good dataset cannot prove scenario coverage. | Every required normal/attack scenario exports a valid, leak-free, reproducible dataset; C formal gate passes. | acceptance/regression tests, reports | 19-scenario matrix and corrupted datasets | All 19 required deterministic scenario exports validate and pass ID/ref/provenance/leakage gates; hard-negative, formal gate, V3 counterexample, full-suite and deterministic E2E tests pass. | VERIFIED |

## Explicit risk and acceptance-test ledger

This companion table separates the `Risk` and `Tests` fields required by the
V4 instruction; the table above records current/expected behavior, files,
counterexample, implementation and final status.

| Issue ID | Risk | Acceptance / regression tests | Verification |
|---|---|---|---|
| V4-FLOOD-REF-001 | Invalid dataset or fabricated lifecycle evidence | V3-audit CASE 1; FREF lifecycle assertions; all-scenario Flooding export | PASS |
| V4-LABEL-PROXY-001 | Model learns a one-token answer instead of behavior | V3-audit CASE 2; packet-type hard-negative overlap; recursive proxy scanner | PASS |
| V4-NORMAL-LEAK-001 | Normal class is revealed in causal input | V3-audit CASE 3; seven normal datasets recursively scanned | PASS |
| V4-FDI-SEMANTICS-001 | Wrong node is mutated/labeled and C learns invalid actor/target semantics | V3-audit CASE 4; FDI-S1..S5; five-subtype matrix | PASS |
| V4-EVAL-SCOPE-001 | Unrelated alarm/recovery inflates TP or defense success | E-SCOPE-1..5; V3-audit CASE 5/6 | PASS |
| V4-REPLAY-LIFECYCLE-001 | Attack truth changes detector state and creates an oracle shortcut | V3-audit CASE 7; formal gate old-session flow; Replay regressions | PASS |
| V4-RFF-STATE-001 | RFF is unusable by security policy/RL despite model output | V3-audit CASE 8; C formal RFF closure gate | PASS |
| V4-MODEL-DEFENSE-001 | C recommendation has no effect or bypasses B authorization | V3-audit CASE 9; high/low-confidence and rule-priority integration tests | PASS |
| V4-VALIDATOR-SEMANTIC-001 | Cross-file corruption silently enters training | V3-audit CASE 10–13; corrupt formal gate; V2 bad-type/range/ref suite | PASS |
| V4-CONFIG-STRICT-001 | A typo silently changes the intended experiment | V3-audit CASE 14; formal reset/batch/API strict tests | PASS |
| V4-EPISODE-PHASE-001 | Hash claims a behavior difference that does not exist | V3-audit CASE 15; fingerprint metadata test | PASS |
| V4-TRAFFIC-PROFILE-001 | Unimplemented profile ID creates false reproducibility claims | V3-audit CASE 15; fingerprint metadata test | PASS |
| V4-GAP-WINDOW-001 | C misreads lifetime gaps as recent-window features | gap-open/late-arrival-clear regression | PASS |
| V4-PROBE-CHANNEL-001 | Reciprocal sample is physically impossible after asymmetric switch | V3-audit CASE 16; A probe/channel formal gate | PASS |
| V4-PROVIDER-PROVENANCE-001 | Mock-A data is mislabeled as a formal experiment | provider provenance, maturity validator, batch formal-refusal gates | PASS |
| V4-SCHEMA-GOVERNANCE-001 | C loader interprets incompatible schema or guesses missing provenance | checked schema-2 example loader gate | PASS |
| V4-NULL-MODEL-001 | UNAVAILABLE noise dominates event/data volume | null-adapter no-result regression and model health tests | PASS |
| V4-FINAL-DATASET-MATRIX-001 | One happy-path dataset hides per-attack contract failures | 19 scenario exports; 21 matrix/hard-negative cases; 9 formal gates | PASS |

## Fixed semantic choices

- `episode_phases` is evaluator/provenance metadata, not an online feature and
  not a behavioral input; it is excluded from the semantic fingerprint.
- `traffic_profile_id` remains a provenance reference until a real profile
  registry exists; it is excluded from the semantic fingerprint.
- `traffic.sequence_gap_count` means **currently unresolved gaps in an
  observer-local sequence stream**, not cumulative history and not a rolling
  count. A late in-window sequence removes its gap.
- Schema remains `2.0.0`: V4 additions are optional compatible metadata/state
  fields and stricter enforcement of already-frozen semantics, not a wire-type
  or unit change.

## Final verification

- V4 cases: 55/55 passed (16 V3-audit counterexamples, 21 scenario/hard-negative
  cases, 9 formal-gate cases, 5 scoped-evaluator cases, 3 model-fusion cases,
  and 1 gap-semantics case).
- Full suite: 209 passed, 2 upstream deprecation warnings; coverage 88%.
- Python compileall, deterministic E2E, duplicate-seed batch, checked example
  validator and `git diff --check` passed.
- Frontend commands are environment-blocked in this run because neither Node
  nor npm exists on PATH. This is not reported as a pass.
- Formal A providers, trained C model assets, real IQ and real calibration remain
  external and are not represented by mock success.
