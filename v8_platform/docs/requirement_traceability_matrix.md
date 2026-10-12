# 需求追踪矩阵

## V11 remaining closure（当前有效）

| Requirement | Runtime implementation | Acceptance evidence | Status |
|---|---|---|---|
| Generic AUTH_FAILURE defense is attributed offline | evaluator uses the same family-attribution set for detection and defense; online label remains generic | V11 T1/T2 | IMPLEMENTED |
| Flood arrival is visible before authentication | receiver-total `record_arrival()` and DOS alarm precede application HMAC | V11 T3 | IMPLEMENTED |
| Invalid plaintext never enters normal RX queue | one pre-ingress HMAC verification; failure emits AUTH/DEFENSE and drops; PASS result is cached for RX service | V11 T4/T5/T12 | IMPLEMENTED |
| Flood pps means actual air-TX attempts | dedicated synchronous attack emitter keeps Message→Frame→PHY→RX but bypasses only the legitimate TX service queue | V11 T6/T7/T8 | IMPLEMENTED |
| Official Web uses Person-A | file-relative application factory, V8_DEFAULT Probe, no preloaded key; network SKG then AES-GCM | V11 T9/T10 | IMPLEMENTED |
| Four non-eaves attacks remain plaintext | application HMAC remains primary; Person-A injection does not force AES | V11 T11 | IMPLEMENTED |

## V10 五类攻击 HMAC closure（当前有效）

| Requirement | Runtime implementation | Acceptance evidence | Status |
|---|---|---|---|
| Per-device application integrity | independent `ApplicationHmacService`; canonical frozen fields; 16-byte HMAC-SHA-256 tag | V10 TEST-A | IMPLEMENTED |
| Spoof changes identity only | sign normal business message, then replace only claimed source | V10 TEST-B + scenario matrix | IMPLEMENTED |
| Flooding is receiver-total rate | pre-HMAC arrival accounting by receiver; configured threshold/window | V10 TEST-C + matrix | IMPLEMENTED |
| FDI is post-HMAC tamper | sign original payload, mutate payload, preserve tag, drop/no-update | V10 TEST-D + five FDI rows | IMPLEMENTED |
| Replay ordering | HMAC → timestamp → session/epoch → sliding window | V10 TEST-E/F/G | IMPLEMENTED |
| Encryption profile separation | four active attacks AES off; eaves Person-A CSI/SKG/AES on | V10 H/I + Person-A suite | IMPLEMENTED |
| DOS/JAMMING retirement | subtype rejected; no runtime/API/Manager/UI/evaluator capability | rejection + source scan | IMPLEMENTED |

## V8 × Person-A crypto integration addendum

| Requirement | Implementation | Acceptance evidence | Status |
|---|---|---|---|
| A raw key stays inside A | production/test key protocols split; PersonA adapter calls only A encrypt/decrypt | A03 + source scan | IMPLEMENTED |
| AES-GCM in V8 packet path | `PersonACryptoProvider`, canonical AAD, recoverable send failure | A04–A07, A16 | IMPLEMENTED |
| V8 local observations drive SKG | session-bound Probe mapping, endpoint-local engine input | A08, A11–A12 | IMPLEMENTED |
| SKG controls traverse network | signed SKG_CONTROL queue/TX/PHY/RX/security handler | A09–A10, A13, A22 | IMPLEMENTED |
| Network SKG key drives business AEAD | authenticated confirms pending on both sides→cross-verify→pair commit→business AEAD | A10, A28, A30 | IMPLEMENTED |
| Rekey uses actual SKG lifecycle | defense request→UPDATING→network handshake→new epoch | A14 | IMPLEMENTED |
| Rekey requests are concurrency-safe | `RekeyCoordinator` unique pair/session/target epoch; duplicate gets existing-in-progress | A29 | IMPLEMENTED |
| V8 Probe and A compatibility statistics are separated | `V8_DEFAULT` exact legacy behavior; explicit compat TEST_ONLY profile + provenance/readiness blocker | A31 | IMPLEMENTED |
| Terminal credential adapter | simulated public fingerprint→A CredentialService; secret boundary | A23–A24 | IMPLEMENTED |
| Five attacks preserve semantics with A | Spoof/Eaves/Flood/FDI/Replay integration tests | A15–A22 + V10 HMAC suite | IMPLEMENTED |
| Secret-free C/dataset/API surfaces | integration secret audit + DatasetValidator + LeakageAudit | A24 | IMPLEMENTED |
| All formal entrypoints share fresh A bundle | RuntimeDependencies/Factory/Manager/API/Batch/RL | A25–A27 | IMPLEMENTED |
| Formal A identities/credentials and real-data/V8-default SKG validation | external assets/data plus A v0.1 reconciliation tolerance not present | provenance + A-CHANGE-001 | BLOCKED_EXTERNAL |

V7 Final Functional Closure 审计日期：2026-09-09。本文件是模块级总览；逐原始需求拆分的 120
条原子矩阵、运行入口、证据和实际测试结果见
`docs/v6_exhaustive_requirement_audit.md`。状态口径：

- `IMPLEMENTED`：正式代码 + 正式主路径 + 正确语义 + 无 truth 泄漏 + acceptance PASS；
- `INTERFACE_READY`：B 公共合同与 failure/unavailable 语义已冻结，外部实现尚未交付；
- `BLOCKED_EXTERNAL`：必须由 A、C、硬件或批准真实数据提供；
- `PARTIAL` / `NOT_IMPLEMENTED`：V7 B 可完成项最终均为 0。

| Requirement group | Source | Runtime/API evidence | Acceptance evidence | Status | Boundary |
|---|---|---|---|---|---|
| Simulation clock/RNG/identity | 分工；C 数据 | SimulationClock、scheduler、named RNG、unique run/event/message ID | deterministic e2e、duplicate seed | IMPLEMENTED | seed 与 run identity 分离 |
| Role-aware multi-hop network | 分工 | GCS/Leader/Follower、per-hop queues/TX/RX/forward | core、multi-session、topology | IMPLEMENTED | External 单列 |
| Persistent PHY/topology | 分工；A→B | direct-link state、RX_FAILURE、PHY_SAMPLE、reroute/recovery | PHY/generic-interference/probe/topology | IMPLEMENTED | observer-local view |
| Observer-local traffic | C §3 | rate/bytes/inter-arrival/latency/throughput/queue/drop/recent gaps | traffic/gap/C acceptance | IMPLEMENTED | 1 s configurable rolling window |
| Attack scheduling/outcome | C §4 | resolved AttackPlan、scheduler、staged outcome policy | current mechanism matrix 21/21 | IMPLEMENTED | label alone cannot pass |
| Spoofing | C §4/§5 | UNKNOWN_ID + KNOWN_ID_CONFLICT, auth/identity evidence | final matrix + claimed-GCS defense regression | IMPLEMENTED | claimed source untrusted |
| Eavesdropping | C §4/§5 | nonsensitive plaintext control + ciphertext protection + sensitive plaintext exposure | three-way/final matrix + four-entry parity | IMPLEMENTED | ordinary plaintext is not an exposure positive |
| Flooding | current frozen requirement | receiver-total arrival rate before HMAC gate; external invalid load | V10 TEST-C + matrix | IMPLEMENTED | no sender attribution/rate-limit dependency |
| FDI five subtypes | current frozen requirement | post-HMAC eligible mutation, HMAC mismatch, no update | five matrix rows; gradual 105/110/115; batch | IMPLEMENTED | opportunity/attempt/injection distinct |
| Replay | C §4 | immediate/delayed/stale lifecycle + legal reorder | replay matrix/parity/multisession | IMPLEMENTED | AttackEngine cannot expire detector state |
| Normal hard negatives | C §5 | six configured physical/traffic/state mechanisms | six matrix rows + four pair audits | IMPLEMENTED | no attack label/online plan truth |
| Scenario mechanism gate | current closure | ScenarioMechanismValidator + actual evidence | 21 scenarios + gradual proof | IMPLEMENTED | contract validity and mechanism separate |
| Strict scenario config | V6/C | typed/ranged subtype params and traffic/session specs | batch/API/RL typo tests | IMPLEMENTED | unknown/ignored semantic config fails |
| Opaque online IDs | C truth boundary | run-scoped link/session/probe/flow aliases; offline map; all-decimal digest disambiguation | identifier leakage + exact numeric-SHA batch regression | IMPLEMENTED | IDs are join keys, not features |
| Online model dispatcher | C §5–§8 | unified subscriptions, recursion guard, EXTERNAL filter | RecordingAdapter/C/V6 tests | IMPLEMENTED | only GCS/Leader/Follower by default |
| Model fault boundary | C §8–§9 | runtime-scoped bounded SafeModelAdapterRunner wraps external reset/observe/health | fault matrix + timeout cross-run isolation | IMPLEMENTED | failure never becomes NORMAL; bad run cannot exhaust next run |
| Decision/defense policy | 分工；C model | fusion→auth gate→trusted target→permission→executor | model/RL parity, spoof/link regressions | IMPLEMENTED | C only recommends |
| Model/fusion reporting | 分工上报；C model | correlated MODEL/FUSION/DEFENSE SecurityReport, Leader→GCS, cache/retry/dedup | final reporting matrix 3/3 | IMPLEMENTED | local event alone is insufficient |
| RL environment | C §6 | reset loads full scenario; step uses same B policy then advances; local plaintext-protection risk | RL/risk acceptance + entrypoint parity | IMPLEMENTED | no capture truth/reward weights/extra privilege |
| RFF data/state | C §7 | strict manifest/ref; prediction→local state→RL | RF validator + KNOWN/UNKNOWN/error matrix | IMPLEMENTED | no fake IQ/device-truth prediction |
| A probe contract | A→B | reciprocal latent state, independent noise/local SNR, direct neighbor | probe/frequency tests | IMPLEMENTED | missing is null, not zero |
| Key/crypto/rekey | 分工 A/B | Person-A AES/SKG/rekey plus independent per-device application HMAC | security/rekey/V10 HMAC tests | IMPLEMENTED | secrets never exported |
| Terminal anti-copy/authz | 分工 | start/join/sensitive-command runtime gate | runtime authorization tests | IMPLEMENTED | simulated binding, not secure hardware |
| Logical redundancy | 分工 | 3 logical replicas, adjudication/health/switch | PlatformRuntime integration | IMPLEMENTED | not software diversity |
| Leader/GCS reporting | 分工 | emergency bypass, aggregation, cache/recovery | reporting deterministic e2e | IMPLEMENTED | raw evidence retained |
| Offline evaluator | C §6 | episode/window confusion, typed scope, family policy, all attempts | evaluator/scope/wrong-link regressions | IMPLEMENTED | action executed ≠ defense effective |
| Mission/service metrics | C §6 | shared MissionImpactEvaluator, damage/recovery/report delay | RL/evaluator/outcome tests | IMPLEMENTED | unavailable stays null |
| JSONL/schema/validator | C §2–§4/§7 | schema 3.2, strict cross-file validation, fault tolerance | good/corrupt + all scenarios | IMPLEMENTED | unknown frozen keys invalid |
| Schema migration strategy | version contract | executable schema2→3.2 assessment and structured rejection when semantics are unrecoverable | migration acceptance | IMPLEMENTED | no guessed opaque IDs/outcomes |
| Provenance/maturity/readiness | C data | plans/provider/calibration/model assets/fingerprints + layered blockers | V7 zero-result/readiness matrix | IMPLEMENTED | dataset readiness ≠ final experiment readiness |
| Calibration software pipeline | 分工 B | normalized measurements→fitter→explicit controls→actual Runtime→comparison；four entrypoints | V7 statistical/runtime parity 5/5 | IMPLEMENTED | approved real input remains external |
| Runtime dependency integration | 分工总集成；A/C | fresh per-run provider/model factories across Manager/Batch/API/RL | V7 dependency matrix | IMPLEMENTED | HTTP never uploads Python objects |
| Frontend/API separation | 分工 | lifecycle/eval endpoints and read-only polling | API + type-check + production build | IMPLEMENTED | current UI exposes Flooding only |
| Direct/batch/API/RL parity | C interface | one RunConfig/ScenarioOrchestrator | FDI/replay/flood/eaves × four paths | IMPLEMENTED | helper-only semantics prohibited |
| Dataset leakage audit | C training | truth/literal/identifier/payload/type/size/extension checks | final matrix + hard-negative pairs | IMPLEMENTED | bounded audit, not theoretical proof |
| A formal SKG/key/crypto/credential | 分工 A | provider contracts and provenance | interface/mock failure tests | INTERFACE_READY | formal implementations external |
| A secure element/root of trust | 分工 A | terminal provider slot | simulated lifecycle test | BLOCKED_EXTERNAL | hardware external |
| C trained BiLSTM/Dueling Q/RFF | C | adapters, bundle health, RL policy interface | unavailable/recording/fake integration tests | INTERFACE_READY | trained assets external |
| C reward/preprocessing/threshold assets | C | outcome components/model metadata contract | no-hardcoded-reward/unavailable tests | BLOCKED_EXTERNAL | C deliverable |
| Real IQ/RF/calibration datasets | A/C/real data | manifest/ref/calibration loaders | synthetic contract tests | BLOCKED_EXTERNAL | no fake data |

## Final counts

Exhaustive atomic matrix：120 total = 105 IMPLEMENTED + 9 INTERFACE_READY +
6 BLOCKED_EXTERNAL + 0 PARTIAL + 0 NOT_IMPLEMENTED。所有 B 自身可完成项均为
IMPLEMENTED；外部项未被 mock 或接口存在冒充完成。
