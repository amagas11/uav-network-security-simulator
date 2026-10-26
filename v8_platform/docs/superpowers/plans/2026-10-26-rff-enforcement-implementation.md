# RFF Enforcement Implementation Plan

> **For agentic workers:** Use subagent-driven-development for isolated policy/evaluator tasks and test-first runtime integration. Track execution here and in the plan-scoped ledger.

**Goal:** Implement the approved design's second phase: receiver-local physical identity admission, pressure-driven strict whitelist, real report delivery, and truth-separated evaluation.

**Architecture:** Keep the existing feature sampler and template identifier. A new receiver-local policy consumes only identification output and local queue/rate observations, and decides before application HMAC and RX queue admission. Existing platform report transport carries bounded notifications. A separate offline evaluator joins receive emissions with simulator-only attack truth.

**Tech Stack:** Python dataclasses, existing simulation clock, queues, reporting service, dataset contracts, pytest. No new production dependencies.

**Spec:** `docs/superpowers/specs/2026-10-14-rff-physical-detection-design.md`, sections 2, 8-13. User authorized phase two on 2026-10-26.

## Global Constraints

- Preserve default `rff_policy_mode="OBSERVE_ONLY"`; observations alone create no new reports, drops or defense actions.
- ENFORCE must drop before application parsing and normal RX queue insertion, at most once per reception.
- Compare against the claimed hop identity, not end-to-end source. No attack labels, actual sender, payload, HMAC or replay state enter the RFF policy.
- `RFF_IDENTITY_MISMATCH` is generic physical identity evidence, not an online claim of a particular attack family.
- Low quality, ambiguous and missing observations are unverified, not confirmed attacker identities.
- Under pressure only a quality-qualified MATCH with both claimed and predicted identity in the local whitelist may pass.
- No token bucket, traffic-class priority, real IQ claim, training work or frontend changes.
- Explicit external asynchronous RFF adapters remain supported in observe mode; ENFORCE rejects them until a synchronous identity contract exists, rather than reusing a stale result.
- Preserve the four unrelated untracked documents. Work on the existing feature branch; no push or main merge.

## Task 1: Receiver-Local Admission Policy

**Files:** create `swarm_sim/rff_policy.py`, `tests/test_rff_policy.py`.

One `RffIngressPolicy` belongs to one receiver. Constructor keyword parameters: `policy_mode`, `quality_threshold`, `queue_pressure_ratio`, `strict_hold_s`, `strict_on_rate_alarm`, `rate_threshold_pps`. Defaults match RunConfig: OBSERVE_ONLY, .45, .60, 2.0, true, 8.0.

```python
decision = policy.evaluate(
    sim_time_s=0.2, identification=identification,
    claimed_is_whitelisted=True, predicted_is_whitelisted=False,
    queue_ratio=0.0, packet_rate_pps=1.0,
)
transition = policy.refresh(sim_time_s=1.0, queue_ratio=0.0, packet_rate_pps=0.0)
```

`RffIngressDecision` is frozen: `identity_result: str`, `policy_state: str`, `would_drop: bool`, `drop: bool`, `confirmed_identity_anomaly: bool`, `reason: str`, `transition: str | None`. Policy properties: `state`, `strict_since_s`, `clear_since_s`.

- [x] Write failing tests for single-frame MISMATCH; quality-qualified UNKNOWN with `NO_TEMPLATE_WITHIN_THRESHOLD` and an available claim; good MATCH pass; missing claim/template/quality not confirmed.
- [x] Implement confirmed identity anomaly only for valid high-quality MISMATCH with unequal claim/prediction or UNKNOWN due to no acceptable template and an available claim. Outside strict mode, these would drop; low-quality/ambiguous/unavailable observations pass without confirmed accusation.
- [x] Write failing tests for queue/rate activation and quiet recovery. Queue >= threshold or enabled rate >= threshold activates `RFF_STRICT_WHITELIST`. Pressure resets `clear_since_s`; the first pressure-free refresh starts it; exit only after continuous clear duration >= hold. No new frame is required to exit.
- [x] Implement refresh and strict admission. Strict rejection of unverified samples uses `RFF_STRICT_UNVERIFIED`; confirmed anomalies keep `RFF_IDENTITY_MISMATCH`. OBSERVE_ONLY exposes would_drop but never drop. Reject nonfinite/backward time and invalid ratios/settings.
- [x] Verify policy tests with the project Python environment.

## Task 2: Runtime Admission, Visibility and Data Contracts

**Files:** modify `swarm_sim/runtime.py`, `security.py`, `domain.py`, `simulation.py`, `events.py`, `dataset/schema.json`, `validation.py`; extend `tests/integration/test_rff_receive_pipeline.py`; create `tests/acceptance/test_rff_enforcement.py`.

- [x] Replace the phase-one ENFORCE rejection with explicit synchronous-template enforcement guards. Reject ENFORCE when RFF is disabled or a provided external RFF adapter would replace the synchronous identifier.
- [x] Add validated `application_layer_available: bool=True`. Default true is omitted from semantic hashing so historical records retain their hash; false changes the hash. Add optional schema field and historical schema compatibility.
- [x] Add `DeterministicRuleEngine.arrival_statistics(sim_time_s)` to trim and read the existing total-arrival window without counting a new frame or triggering an alarm. Reuse it in record_arrival. Read it on quiet ticks so strict mode exits correctly.
- [x] Initialize policies only for legitimate receiver nodes. At each decoded ingress, record total arrival first, evaluate policy before building RX event, and put exact decision in `extensions.rff_decision`. Include opaque `air_emission_ref` pointing to the TX event. A failed decode may carry a policy observation but never creates an executed packet drop.
- [x] Persist optional node/event fields `rff_policy_state`, `rff_strict_since_s`, `rff_clear_since_s`. Keep per-frame decision attached to RX event/ReceivedFrame; don't replace older evidence with current receiver state.
- [x] In ENFORCE perform a local DROP_PACKET request on decision.drop, increment receiver drop count once, record an executed DEFENSE_RESULT referring to this RX evidence, and skip HMAC, enqueue and execution for the rejected frame. Don't invoke application classification or attribute attack family online.
- [x] Test copied spoof, copied/on-path FDI, replay and Flooding using the first-phase fixture configurations. Verify causal attack emissions are rejected before authentication, while legitimate direct and multi-hop frames pass. Test low-quality strict drops separately from confirmed detection, clear hold, reset, disabled behavior and async-adapter rejection.
- [x] When application_layer_available is false, suppress unavailable business headers/payload projections in online events, skip business crypto/HMAC/replay inspection, and accept/relay business frames opaquely without applying commands or telemetry. Opaque relay preserves bytes, updates current-hop headers, and produces fresh relay RFF observations. Count opaque deliveries separately from business execution. Platform-owned SECURITY_REPORT/SECURITY_SUMMARY/SKG_CONTROL remain authenticated known management protocols, not vendor business parsing.
- [x] Test physical-only operation with a business crypto.open spy that raises; business frames must never reach it. Require empty upper-header projections and no fabricated business execution. Test normal opaque relay and report delivery.
- [x] Extend schema/validator additively; preserve exact older schema variants and fingerprints; validate new policy decision shape and ranges. Run focused RFF, existing HMAC/replay/API/data regressions.

## Task 3: Real Reports and Offline Evaluation

**Files:** modify `swarm_sim/reporting.py`, `runtime.py`; create `swarm_sim/rff_evaluation.py`, `tests/test_rff_evaluation.py`; extend enforcement acceptance tests.

- [x] Create at most one report per receiver/reason within `security_summary_window_s`; retain every per-frame decision for audit. Report mode transitions once. Report categories: RFF_IDENTITY_MISMATCH, RFF_IDENTITY_UNVERIFIED, RFF_STRICT_WHITELIST. Evidence contains only current receiver measurements, claims, predictions, pressure and event IDs. Never claim passive-listener identity.
- [x] Reuse Source -> Leader -> GCS queues. Preserve RFF evidence/action_result in aggregated summaries. Disconnect/reconnect must delay/upload the existing cached reports, never inject them directly into the GCS inbox.
- [x] Add `evaluate_rff(events, labels, *, transmissions, legitimate_node_ids, enabled, policy_mode)` returning an additive physical-layer evaluation. Join RX `extensions.air_emission_ref` to offline `transmissions.emission_id`, including attack_id, actual_sender_id and target identity only in this evaluator.
- [x] Eligible attack samples are target receptions causally bound to external retransmission, with a usable fingerprint and claimed hop ID. Count only these for attack detection; count decoded eligible samples for packet-blocking opportunities. Passive eavesdropping, compromised legal-radio sends, missing/low-quality observations, and no reception are unavailable with reasons, not fake successes or failures.
- [x] Return per-family episode and sample counts, nullable detection/block rates, confirmed detection time, normal qualified sample false-positive rate, protective unverified-drop count and declared policy mode. Deduplicate receive event IDs; unrelated same-message emissions, wrong receivers and other attack episodes must not cross-match. OBSERVE_ONLY must not be assigned an executed defense success.
- [x] Expose this result under evaluation_view.physical_layer without changing original evaluation meanings. Runtime view's actual GCS security_reports show only reports that traversed the simulated links.
- [x] Test all scope/denominator boundaries plus report routing and lost/recovered link cases.

## Task 4: Verification, Documentation and Commit

**Files:** update `docs/rff_observe_only_guide.md`; create `docs/rff_enforcement_guide.md`; update this task status.

- [x] Review normal and attack sample distributions using unchanged simulation thresholds; document that these are not measured real-world performance.
- [x] Run focused suites and independent code review, fix reproduced issues and rerun affected tests.
- [x] Copy tracked files plus new source/tests/docs into a clean validation snapshot under workspace tmp. Verify changed source hashes match the canonical directory. Exclude personal untracked documents and temporary dependencies from the packaging test input.
- [x] Run full pytest and report completed exit status. Record any unrelated canonical-directory packaging constraint separately.
- [x] Document defaults, ENFORCE/physical-only examples, whitelist and recovery rules, quality limits, outputs and independent evaluation.
- [x] Commit the verified integrated change locally on feature/rff-physical-detection; preserve unrelated documents.
