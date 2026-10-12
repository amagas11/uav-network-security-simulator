# V6 Final Closure Patch

This ledger is the fail-first tracking record for the final V6 closure patch. The
three original requirement documents remain unchanged and authoritative. A row
may become `IMPLEMENTED` only after its runtime path and acceptance evidence pass.

| Issue ID | Requirement Source | V5/V6 Actual Behavior | Risk | Correct Semantics | Counterexample / Test | Files | Implementation | Final Status |
|---|---|---|---|---|---|---|---|---|
| V6P-MODEL-FAULT-001 | `c需求文档.md` §8–9 | External adapter exceptions crossed the runtime boundary. | One C failure could stop simulation and deterministic protection. | All external `reset/observe/health` calls are isolated; failure is explicit and never mapped to NORMAL. | `test_model_fault_tolerance_final.py` exception/error/unavailable/no-result/resource/default-subscription matrix: 9/9 PASS | `swarm_sim/model_runtime.py`, runtime/dispatcher | One bounded process-wide worker pool; safe summary/health/result; deterministic rule path and legacy default subscription continue. | IMPLEMENTED |
| V6P-MODEL-TIMEOUT-001 | `c需求文档.md` §9 | A blocking `observe()` had no deadline. | A run/API/RL episode could hang. | Configured wall-clock timeout, bounded daemon worker, explicit `MODEL_INFERENCE_TIMEOUT`, no simulated-time mutation. | timeout fixture returns runtime before blocked call, submits once: PASS | model runtime, config/API/schema | `model_inference_timeout_ms`; timeout permanently disables that adapter for the run, preventing task growth. | IMPLEMENTED |
| V6P-MODEL-REPORTING-001 | `c需求文档.md` data acceptance | External model/fusion results stopped at local event logging. | GCS datasets and response-delay metrics omitted deployed C decisions. | One correlated security-outcome hook carries MODEL/RULE/FUSION reports over Source→Leader→GCS with retry/dedup. | `test_model_reporting_final.py`: 3/3 PASS | runtime/reporting | Model-only and defense outcomes share correlation/dedup; disconnected report is cached and later timestamped at GCS. | IMPLEMENTED |
| V6P-EAVES-CONTROL-001 | `c需求文档.md` eavesdropping controls | Matrix had ciphertext and sensitive-plaintext cases only. | Ordinary plaintext could be mislabeled as exposure. | Distinguish nonsensitive plaintext capture, ciphertext protection, and sensitive plaintext exposure. | `test_eavesdropping_three_way_final.py`: 4/4 PASS; final matrix 22/22 | attacks/runtime/scenario validator/matrix | Added explicit control subtype and evidence counters; PASSIVE_CAPTURE derives outcome from sensitivity/encryption. | IMPLEMENTED |
| V6P-CAL-FITTER-001 | `分工安排(1).md` calibration task | Only a fitter Protocol existed. | Approved measurements would still require code changes. | Conservative deterministic baseline fitter with descriptive statistics, warnings and hash provenance. | synthetic known-statistics fixture: PASS | calibration module | RSSI/SNR moments/quantiles, loss, latency, optional throughput/PHY; missing is warning, never zero. | IMPLEMENTED |
| V6P-CAL-ENTRYPOINT-001 | B calibration responsibility | Only direct runtime object injection worked. | Batch/API/RL could not reproduce calibrated runs. | Profile save/load and equivalent Direct/Batch/API/RL resolution. | `test_calibration_pipeline_final.py`: 5/5 PASS | calibration/runtime/batch/API/RL/manager/schema | Strict profile/hash loader passed through all four entrypoints; complete profile preserved in runs.jsonl. | IMPLEMENTED |
| V6P-RL-PLAINTEXT-RISK-001 | `c需求文档.md` RL state | RL exposed only unavailable exposure truth. | C lacked observable protection risk or was tempted to consume attacker truth. | Local unprotected-sensitive count/risk, independent of actual eavesdrop truth. | observable encrypted/unencrypted risk acceptance: PASS | node/runtime/RL contract | Node-local protection counters and availability are exposed; capture truth remains absent. | IMPLEMENTED |
| V6P-SCHEMA-MIGRATION-001 | schema compatibility rule | Schema-2→3 had prose notes but no executable strategy. | Old data could be silently mixed or guessed. | Executable migration utility; safely migrate recoverable data or reject with structured provenance. | `test_schema_migration_final.py`: PASS | `tools/migrate_dataset.py`, CLI/docs | Schema 2 is rejected with source hash, versions, time, warnings and unrecoverable list; no JSONL is fabricated. | IMPLEMENTED |
| V6P-EXHAUSTIVE-AUDIT-CORRECTION-001 | exhaustive gate | Calibration/model fault/model reporting/eaves rows were overclaimed or missing. | Freeze status was unsupported. | Split B-owned software from external assets and attach exact runtime/test evidence. | 113-row evidence review + 339-case checkpoint | audit/matrix/status docs | Added eight atomic B requirements; calibration data remains external while loader/fitter/entrypoints are B IMPLEMENTED. | IMPLEMENTED |
| V6P-OPAQUE-ID-STABILITY-001 | C no-truth-leakage contract | A rare all-decimal 12-nibble SHA scope (real sample `563586642103`) was mistaken for legacy numeric endpoint encoding. | A valid duplicate-seed batch could nondeterministically fail its own leakage/validator gate. | Generated opaque scopes remain schema-compatible 12-hex tokens but are guaranteed visibly non-decimal. | exact formerly failing batch run ID + export/validator regression: PASS | `simulation.py`, V5 freeze regression | The deterministic factory replaces one nibble only for an all-decimal digest; no endpoint/scenario data is introduced and the existing schema format is unchanged. | IMPLEMENTED |
| V6P-FINAL-FREEZE-001 | V6 patch hard gate | Baseline was 314 passing tests but closure gates were absent. | False freeze. | Full history, 22-scenario mechanism matrix, validator/leakage/E2E and frontend checks determine status. | full suite 339 PASS; 39 scenario/parity/combination/hard-negative PASS | reports | All P1 software gates pass, including the release-stress opaque-ID edge; frontend is honestly environment-unverified and real/A/C assets remain external. | VERIFIED |

## Fail-first baseline

- Existing full suite before patch: `314 passed, 2 warnings`.
- Confirmed missing behavior: adapter exceptions propagate; no model inference
  timeout; external MODEL/FUSION path creates no `SecurityReport`; scenario
  matrix contains only two eavesdropping variants; `CalibrationFitter` is only a
  Protocol; Batch/API/RL cannot load a calibration profile; RL plaintext exposure
  remains unavailable even when local protection configuration is observable.
- First execution before implementation: model fault matrix 4 failed/3 passed;
  model reporting 3 failed; eaves matrix 3 failed/1 passed; RL risk 1 failed;
  calibration and migration suites failed collection because the concrete fitter
  and migration module did not exist. These are the recorded red counterexamples,
  not failures manufactured by changing previously correct code.
- Final stress verification exposed one additional real counterexample: the batch run
  `batch-c7e3ae46ace247e9ab55253f45364c53-run-0002-seed-7` produced numeric SHA scope
  `563586642103`, making valid opaque IDs look endpoint-encoded. The exact ID is now a
  permanent regression fixture.

## Final verification checkpoint

- New patch cases: 25; full suite: `339 passed, 2 dependency warnings`.
- New acceptance matrices: model fault 9/9, reporting 3/3, eaves/calibration/risk/
  migration 11/11; final matrix gained the 22nd scenario.
- Final scenario + entrypoint + combination + hard-negative selection: 39/39.
- `python -m compileall -q swarm_sim app tools Manager`: PASS (final rerun recorded in
  `docs/test_report.md`).
- Frontend executable verification: NOT VERIFIED DUE TO ENVIRONMENT (`node` and `npm`
  are not installed); read-only polling remains covered by static/API regression.
