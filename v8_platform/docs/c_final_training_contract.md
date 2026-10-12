# C final training contract

## Person-A crypto integration (V8 integration profile)

Person-A 模式不改变 C 的 truth-isolation contract。C 可使用的非秘密安全结果限定为：
`status`、`auth_result`、`key_id`、`key_epoch`、`algorithm`、`key_state`、
`error_code` 及合法 observer-local evidence。AES nonce/公开协议 metadata 不是模型默认
特征；SKG 完整 RECONCILE/CONFIRM blob 不导出为 C raw feature。

禁止输入 C 的内容包括 raw/session key、Ed25519 private PEM、credential master/serial、
SKG quantized bits/candidate key/privacy-amplification intermediate、simulator attacker truth。
GCM PASS 只表示密码认证通过。当前业务层另有独立 per-device application HMAC：
FDI 在 HMAC 生成后篡改 payload 并由 HMAC mismatch 拒绝；Replay 原样保留合法 HMAC，
再由 timestamp/session/ReplayWindow 拒绝。C 不得把 GCM、application HMAC 与 SKG
Ed25519 control authentication 合并成一个含义。

Person-A provider status `PERSON_A_INTEGRATED_DEVELOPMENT` 可用于 C loader/feature/RL
联调数据，但不是正式 A 资产 maturity。C 端必须读取 runs 的 provider provenance，不能
把 TEST/INTEGRATED_DEVELOPMENT 数据误标为最终正式实验数据。

## Frozen versions and entrypoints

- Producer: `platform-v7` (distribution `7.0.0`).
- Dataset contract: schema `3.2.0`.
- Dataset files: `runs.jsonl`, `events.jsonl`, `labels.jsonl`,
  `rf_manifest.jsonl`, plus the exact `schema.json` used for the export.
- RL contract:
  `reset(seed, run_config) -> initial_observation` and
  `step(action_recommendation) -> next_observation, outcome, terminated`.
- Formal scenario semantics are shared by direct `PlatformRuntime`, `run_batch`,
  FastAPI and RL reset; all accept the same strict `RunConfig` content.

## Application authentication and encryption profiles

`online_features.security_state` 可使用非秘密字段
`application_hmac_result`、`application_hmac_failure_reason` 与
`application_hmac_key_id`。原始 HMAC key、Person-A session key 和 SKG secret 永不导出。
HMAC failure 只表示身份/完整性认证失败，在线 detector 不读取 attack truth 将其硬分类为
Spoofing 或 FDI。

当前单场景 profile：SPOOFING、DOS/FLOODING、FDI、REPLAY 为 application HMAC on +
AES off；EAVESDROPPING 为 CSI/SKG + AES-GCM on（显式 plaintext exposure control 除外）。
`SKG_CONTROL` 使用 Person-A Ed25519 handshake authentication，application HMAC 结果为
`NOT_APPLICABLE`。

## Online observer and identity boundary

C online models may consume only events whose `observer_role` is `GCS`, `LEADER` or
`FOLLOWER`. `EXTERNAL` is simulator/offline truth and is excluded by the dispatcher by
default. External activity is learned from legitimate receivers' observable evidence, not
from running a model on the attacker.

`run_id`, `event_id`, `message_id`, `session_id`, `link_id`, `flow_id`, `probe_id` and
related refs are identifiers/join keys. V7 session/link/probe/flow IDs are opaque and stable
only within their documented scope. C must never parse endpoint, role, scenario, subtype or
class meaning from an ID, and must not use raw identifiers as learned categorical features.

Online features must not contain attack family/subtype, actual attacker/transmitter truth,
normal-disturbance type, mutation original/modified values, contributing attack IDs, future
state, labels or offline defense/effectiveness truth. Normal and attack scenarios differ only
through observable PHY/traffic/queue/state/security behaviour. Current rule/statistical
leakage audit covers literal, identifier, packet-type, payload-key, extension and obvious
packet-size shortcuts.

## Run provenance

Each run stores the complete secret-free `run_config`, requested and resolved AttackPlan,
normal-disturbance plan, business traffic plan, legitimate session lifecycle plan, plan IDs,
semantic fingerprint, seed, unique run ID, producer/schema versions, data/calibration source,
security-provider provenance, participant contract and maturity fields. Runtime defaults are
resolved before execution and the executed resolved plan is what labels and run provenance
record. Secrets and raw key material are forbidden.

`probe_profile` records the actual reciprocal-observation statistics mode. `V8_DEFAULT` is
the platform default. `PERSON_A_V01_COMPAT_TEST` is an explicit TEST_ONLY Person-A v0.1
integration fixture and adds a formal-readiness blocker; C must treat it only as run-level
provenance and never as an online feature.

`node_count` counts legitimate nodes. `legitimate_node_roles` covers GCS/Leader/Follower;
`external_participants` is separate. A repeated seed reproduces semantic event content but
never reuses run identity or output directory.

## Supported scenario set

The frozen required matrix comprises:

- normal baseline, low SNR, packet loss, traffic burst, legal out-of-order, state change and
  congestion;
- Spoofing UNKNOWN_ID and KNOWN_ID_CONFLICT;
- Eavesdropping NONSENSITIVE_PLAINTEXT_CONTROL, CIPHERTEXT_ONLY and
  PLAINTEXT_EXPOSURE;
- DoS FLOODING（DOS/JAMMING 已从当前攻击合同移除）；
- FDI command replacement, abrupt change, gradual drift, out-of-range and logical
  inconsistency;
- Replay immediate, delayed and old-session.

Scenario acceptance requires both dataset validity and actual mechanism evidence. In
particular, FDI is scheduled before eligible business traffic, old-session replay uses a
legitimate configured session rotation, and plaintext exposure requires sensitive plaintext
visible to an unauthorized listener. A label alone never passes a scenario gate.

Current final mechanism matrix contains 21 scenarios. Flooding is detected from receiver-total
arrival rate before HMAC filtering; FDI truth records
`POST_HMAC_PRE_TRANSMISSION`; Replay requires application HMAC PASS before timestamp/session/
sequence rejection.

## Strict scenario configuration

`RunConfig.from_dict` is strict by default. Formal runtime, batch, API and RL paths reject
unknown top-level fields, unknown attack/normal subtype parameters, wrong parameter types,
invalid ranges, unsupported subtype names and silent multi-target truncation. V7 supports a
single node and at most one link target per attack episode; larger plans fail with
`MULTI_TARGET_NOT_SUPPORTED_V6` (compatibility error code). The machine-readable accepted parameter map is
`schema.json.scenario_parameter_contracts`. Every accepted semantic parameter is consumed by
the runtime; `traffic_profile_id` remains explicitly provenance-only and is excluded from the
semantic fingerprint until a formal loader exists.

## Model and RFF adapters

`ModelAdapter.reset(run_info)`, `observe(event)` and `health()` remain frozen. The unified
dispatcher delivers subscribed local events, prevents MODEL_RESULT self-recursion, forwards
BiLSTM/RFF results to Dueling Q, and filters EXTERNAL observers. Unavailable models report
health as `UNAVAILABLE` and do not emit per-event fake NORMAL predictions. Every externally
supplied adapter is invoked through the runtime-owned bounded `SafeModelAdapterRunner`: reset, observe and
health exceptions are isolated; observe has `RunConfig.model_inference_timeout_ms`; failure
produces an explicit null-prediction ERROR/UNAVAILABLE result and deterministic rules keep
running. A timed-out instance is disabled, so later events cannot accumulate worker tasks;
the next independent runtime receives fresh execution capacity.

Programmatic Direct/Manager/FastAPI-server/Batch/RL integration uses
`RuntimeDependencies` and `PlatformRuntimeFactory`. Stateful model/provider instances are
fresh per run or episode. `runs.jsonl.model_assets` records all bilstm/dueling_q/rff slots at
run start/export even if no MODEL_RESULT is emitted, including configured/name/version/status,
errors and available bundle/preprocessor/threshold/training-data provenance.

An OK external detection and its allowed/denied/executed fusion result use one correlated
SecurityReport. Reports traverse the simulated Source/Follower→Leader→GCS path, deduplicate
by result/decision correlation, remain cached while disconnected and retain real received
time/report delay after recovery. Model result fields contain no attack truth.

RFF outputs update the observer-local security snapshot (`rff_identity_result`, confidence,
quality and timestamp). Subsequent AUTH/PHY/QUEUE/NODE events and the RL state use that same
snapshot. `UNKNOWN` increments the local RL anomaly count; C predictions, never true
`device_id`, drive the state. `rf_sample_ref=null` is valid when no real IQ exists; a non-null
ref must resolve to the strict 18-field manifest contract and represent the current receiver/
hop only.

## RL and deployment-policy parity

An RL action is a recommendation, not privileged simulator control. Training-agent,
deployed-Dueling-Q and BiLSTM recommendations enter the same B-owned pipeline:

```text
Recommendation
  -> DecisionFusion
  -> authentication/identity policy
  -> DefenseTargetResolver
  -> permission/resource policy
  -> DefenseExecutor
  -> audited DEFENSE_RESULT
```

Identity-sensitive action is deferred/denied without trusted evidence. An untrusted
`claimed_src_id` cannot select a legitimate isolation/rekey target; channel actions require a
direct physical link. RL outcomes expose actual `allowed`, `executed`, `failure_reason` and
`decision_reason`, then advance `SimulationClock` by `decision_step_s` before measuring local
service outcome. B defines no C reward weights. Unmeasured compute/communication overhead is
`null` with availability=false, never fake zero.

## State, outcome and missing values

RL observations contain observer-local recent 2 s/5 s traffic, queue, latency, throughput,
PHY values/trends, security/RFF state, model status/output, node/topology state, active defense
and available resource measures. They contain no attack phase/truth or future data. The
plaintext field is an observable protection risk derived only from this node's sensitive
encrypted/unencrypted traffic (`protected_sensitive_count`,
`unprotected_sensitive_count`, availability); actual eavesdrop capture or attacker presence
never enters the state.

Attack outcome stages are distinct: active/opportunity, attempted, injected, reached target,
business accepted/executed/state changed, mission impact and attack effective. Delivery alone
does not mean malicious content executed. Mission impact is calculated by the shared B helper
when evidence exists; otherwise value is null and availability=false. The evaluator and RL
consume the same base semantics.

All unavailable or unmeasured values use JSON `null` and an availability/missing reason where
the object exposes one. Numeric zero means an actual measured zero. C must never impute
UNKNOWN/UNAVAILABLE as NORMAL without recording an explicit preprocessing decision.

## Maturity and external dependencies

Maturity dimensions are separate:

- `security_provider_maturity`: TEST or FORMAL;
- `calibration_maturity`: UNCALIBRATED, TEST, DEVELOPMENT, PRELIMINARY or APPROVED;
- `dataset_maturity`: DEVELOPMENT, PRELIMINARY or FORMAL;
- `dataset_readiness`: READY_FOR_C or READY_FOR_C_DEVELOPMENT;
- `readiness_components`: independent B software, provider/calibration data, three model
  asset slots, dataset generation and final experiment states;
- `experiment_readiness`: READY or BLOCKED_EXTERNAL and means only the final formal
  integrated experiment; `readiness_blockers` explains every missing asset.

The bundled MockKeyProvider, test-only crypto and simulated terminal authorization cannot
produce FORMAL maturity. Current data is suitable for loader, feature-pipeline and algorithm
development/smoke training. Final formal experiments remain blocked on A's formal providers,
C's trained/versioned model assets, real device IQ/RF manifest and approved calibration/data
provenance. B does not fabricate any of them.

## Calibration and schema migration

The B calibration software path is frozen as:

```text
licensed/provenanced normalized measurements
  -> BaselineCalibrationFitter
  -> CalibrationProfile (targets, runtime controls, warnings, hashes, maturity)
  -> identical Runtime / Batch / FastAPI / RL loading and actuation
  -> RuntimeCalibrationValidator(actual runtime events)
```

The baseline fitter is deliberately explainable: it preserves RSSI/SNR moments/quantiles,
observed loss ratio, latency median/p95 and optional throughput as descriptive targets, then
emits explicit RSSI/SNR bias, background-loss and latency controls. Those controls affect
actual PHY/traffic output while path loss, fading, generic interference and normal low-SNR effects remain.
Throughput target is explicitly descriptive-only and runtime throughput remains derived from
bandwidth/SINR/loss. `RuntimeCalibrationValidator` runs the fitted profile through real
PlatformRuntime events before comparing source and runtime statistics. Missing input remains
unavailable and creates warnings, never a synthetic zero. A TEST fixture proves the software
path only; it is not approved real-calibration evidence.

Schema 2.x data is not silently relabeled as 3.2.0. `python -m tools.migrate_dataset` writes
a versioned, hashed incompatibility report and rejects migration when opaque IDs, resolved
plans or staged outcomes cannot be reconstructed. Re-running the original reproducible
scenario is the supported route; consumers must not guess unrecoverable fields.
