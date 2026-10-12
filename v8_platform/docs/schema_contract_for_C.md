# Schema 3.2.0 contract for C (V10 semantics)

## Version boundary

The producer compatibility identifier remains `platform-v7`; the V10 package keeps the frozen data contract at `3.2.0`.
Software and schema versions remain independent. Schema 3 was a deliberate V5 major
migration; V7 adds compatible calibration-control, model-provenance and layered-readiness
run fields, so it uses a minor increment. The decision is recorded in
`schema_version_decision_v7.md`.

C loaders must explicitly accept `3.2.0`; they must not reinterpret schema-2
packet sizes or sequence gaps. Unknown keys in frozen objects are invalid.
Compatible application-specific data belongs under a documented `extensions`
surface. Missing measurements are JSON `null` with availability, never an
invented zero or NORMAL prediction.

Schema 2.x is a non-compatible source. The executable `tools.migrate_dataset`
strategy rejects it with a hashed/versioned incompatibility report when V7
identifiers, resolved plans and staged outcomes cannot be recovered; it never
copies or relabels the old JSONL as 3.2.0.

## Dataset files

| File | Frozen meaning |
|---|---|
| `runs.jsonl` | Full secret-free resolved run configuration and provenance. |
| `events.jsonl` | Observer-local causal online observations only. |
| `labels.jsonl` | Offline attack plan, scope, mechanism truth and staged outcome. |
| `rf_manifest.jsonl` | Strict 18-field RF sample metadata; may be empty. |
| `rf_samples/` | Referenced samples; V7 never fabricates IQ. |
| `schema.json` | Exact copy of `dataset/schema.json`. |

## Run and participant contract

`node_count` and `legitimate_node_count` both count non-EXTERNAL platform nodes.
`legitimate_node_roles` contains only GCS/Leader/Follower nodes. `node_roles`
contains every observer, including declared external participants, while
`external_participants` lists those external IDs separately. The validator
checks all four views agree.

`run_config`, `attack_plan`, `requested_attack_plan`,
`normal_disturbance_plan`, business `traffic_specs`, legitimate
`session_lifecycle_specs`, data/calibration provenance, provider provenance,
plan IDs and the semantic fingerprint are present. `attack_plan` is always the
resolved plan actually executed. The original request is retained separately;
labels repeat both `truth.requested_plan` and `truth.resolved_plan`.

Run records may include additive `probe_profile`: `V8_DEFAULT` or the explicitly TEST_ONLY
`PERSON_A_V01_COMPAT_TEST`. The latter is provenance, not an observer feature, and its use
must appear in `readiness_blockers` as `PERSON_A_COMPAT_PROBE_TEST_ONLY`.

When calibration is loaded, `calibration_profile` stores the exact validated
profile: source manifest/version/hash/license, fitted target statistics and explicit
runtime controls, sample count, method, warnings, hash and maturity. Runs also store
`calibration_runtime_controls` and `calibration_parameter_semantics`. RSSI/SNR bias,
background loss and latency controls act on real runtime output; throughput target is
currently descriptive-only. The same profile is used by Runtime, Batch, FastAPI and RL.
Synthetic fixtures are `TEST`, not approved real-data evidence.

V7 supports exactly one target node and at most one target link per attack
episode. Multiple targets are rejected with
`MULTI_TARGET_NOT_SUPPORTED_V6` (compatibility error code); they are never silently truncated.

The formal config is strict at direct runtime, batch, FastAPI and RL reset. Attack and
normal subtype parameters use the machine-readable
`schema.json.scenario_parameter_contracts`; unknown, mistyped, out-of-range or ignored
semantic parameters are rejected rather than silently dropped.

## Online/truth boundary

Events contain only information available to `observer_node_id`. Attack family,
subtype, attack IDs, actual attacker, mutation before/after values, contributing
attack IDs, normal-disturbance type and future/defense truth are forbidden from
`online_features` and raw observation extensions. Model results and audited
defense results may name their own predictions because those are outputs.

Normal bursts and Flooding use the same ordinary business packet template and
packet-type space. Scenario-only payload keys such as `flood_index`,
`padding_bytes`, `burst_index` and normal/attack markers are not emitted. V7's
leakage audit checks literals, opaque identifier format/scenario encoding,
packet-type support, observable payload-key support and packet-size range overlap for
hard-negative pairs. Passing this bounded rule/statistical audit is not a theoretical
proof that no statistical shortcut can exist.

Online `session_id`, `link_id`, `flow_id` and `probe_id` are opaque run-scoped join
keys. They never encode simulator-private endpoints, attack/normal names or profile IDs.
Endpoint mapping is offline run provenance. C must not parse or learn from identifiers.
Only GCS/LEADER/FOLLOWER events are model-deployment inputs; EXTERNAL observers are
filtered by default.

Application authentication is observer-local and secret-free. Optional
`security_state.application_hmac_result` is one of `PASS`, `FAIL`, `MISSING`,
`UNKNOWN_DEVICE`, `NOT_APPLICABLE`, or `UNAVAILABLE`, with an optional public failure
reason. It is generated from a per-device HMAC-SHA-256 key over canonical business
fields and is distinct from AES-GCM authentication, Person-A SKG material, and
handshake signatures. Raw HMAC keys are never exported. `SKG_CONTROL` is
`NOT_APPLICABLE` because Person-A's signed handshake owns that control-plane trust.

## Packet and traffic semantics

`packet.packet_size_bytes` is the UTF-8 byte length of the canonical JSON
serialized application payload (sorted keys and compact separators). It
excludes encryption expansion and link/PHY overhead. The shared packet builder
creates the configured target size exactly for Flooding and normal bursts.
`traffic.byte_rate_Bps` uses that same application-byte definition.

`traffic.sequence_gap_count` is the number of still-unfilled gaps detected
inside `run_config.traffic_statistics_window_s` for observer-local sequence
streams. A legal late arrival removes its gap; a gap detection older than the
window is no longer counted. Other rates, latency, duplicates and throughput
remain observer-local rolling receive statistics.

## Attack lifecycle and attribution

Every label outcome contains:

- `attack_active` and `eligible_opportunity_seen` — schedule activity and a valid
  source/target/business opportunity are separate;
- `attempted` — the mechanism tried to act;
- `injected` — content/load/capture was injected;
- `reached_target` — it reached the configured target receiver/link/service;
- `malicious_content_executed` — target logic accepted or acted on malicious
  content where applicable;
- `mission_impact` — measured normalized value or null;
- `attack_effective` — family policy found a target-side security/mission
  effect.

Injection alone never makes FDI effective. In particular, an FDI mutation lost
at the PHY has `injected=true`, `reached_target=false` and
`attack_effective=false`. Passive Eavesdropping retains its protection/exposure
semantics. The current DoS contract contains Flooding only; JAMMING is not a supported
attack subtype. Generic PHY noise/interference/SNR/SINR/PER remain channel observables,
not attack truth.

The four non-eavesdropping demonstrations use application HMAC with AES disabled:
Spoofing changes only the claimed device ID after signing; FDI mutates payload after
signing; Flooding is detected from receiver-total arrivals before HMAC rejection; and
Replay preserves a valid HMAC before freshness/session/ReplayWindow rejection.
Eavesdropping continues to exercise Person-A CSI/SKG and AES-GCM confidentiality.

## Models, defense and missing costs

Model and RL recommendations are advisory. Both use the same B-owned recommendation
entrypoint. `DecisionFusion`, the authentication gate
and `DefenseTargetResolver` run before `DefenseExecutor`. An unauthenticated
`claimed_src_id` never becomes an isolation/rekey/peer-rate-limit target.
Identity-sensitive recommendations are deferred until AUTH; high-certainty
rules retain priority. PHY recommendations resolve their direct link from local
packet or sample evidence.

Every externally supplied model adapter runs behind a runtime-owned bounded safety boundary.
Reset/observe/health exceptions and inference timeout are explicit ERROR/
UNAVAILABLE states with null prediction; they never mean NORMAL and do not stop
deterministic rules. A timed-out run cannot exhaust a later run's execution capacity.
OK detections and their fusion/defense outcomes use a
correlated, deduplicated SecurityReport that follows the simulated Leader→GCS
route and its disconnect/cache/recovery timing.

RFF MODEL_RESULT updates the observer's security state, and later AUTH/PHY/QUEUE
snapshots preserve it. KNOWN, UNKNOWN, ERROR and UNAVAILABLE remain explicit;
only actual model prediction/status is used, never true device identity.

Unmeasured communication and compute overhead are null with availability false.
Zero is reserved for a measured zero cost.

The RL plaintext field is `plaintext_protection_risk`, derived from locally
known sensitive encrypted/unencrypted traffic and paired counts/availability.
Actual passive capture, attacker presence and plaintext recovery truth are not
online state.

## Validation and maturity

The validator is fault tolerant and schema driven. It checks types/ranges/enums,
frozen unknown keys, observer identity/role, legitimate/external populations,
resolved label-to-plan equality, attack IDs, outcome causal ordering, message,
event and RF references, event-type semantics, maturity/provider consistency
and leakage rules.

Built-in providers are explicitly test-only/simulated, so the default maturity is
DEVELOPMENT and FORMAL export is rejected. Maturity is split into security-provider,
calibration (`UNCALIBRATED/TEST/DEVELOPMENT/PRELIMINARY/APPROVED`), dataset and
experiment-readiness dimensions. `dataset_readiness` is independent of trained model assets;
`experiment_readiness` means final formal integrated experiment and lists explicit blockers.
Each run records every bilstm/dueling_q/rff slot in `model_assets` even when no result exists.
Current datasets prove the 3.2 interface and can support development/preliminary training;
they do not prove formal SKG, trained C models, real IQ or approved wireless calibration.
