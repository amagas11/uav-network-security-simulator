# RFF Observe-Only Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, receiver-side simulated radio-frequency-fingerprint pipeline that identifies each hop's transmitter and records the result without dropping or modifying traffic.

**Architecture:** A new `swarm_sim.rff` module owns simulator-private device baselines, receiver-specific enrollment templates, noisy feature observations, and deterministic nearest-template identification. `PlatformRuntime` invokes it synchronously after PHY sampling and before RX event construction; only the noisy observation and identification result enter online events, while actual transmitter identity remains simulator-private. This plan deliberately stops at `OBSERVE_ONLY`; enforcement and DoS strict-whitelist behavior receive a separate plan after observation quality is validated.

**Tech Stack:** Python 3.10+, dataclasses, existing `RNGRegistry`, FastAPI-facing `RunConfig`, schema 3.2 event contracts, pytest.

**Spec:** `docs/superpowers/specs/2026-10-14-rff-physical-detection-design.md`

## Global Constraints

- Do not place `actual_transmitter_id`, attack labels, attack plans, or noiseless device baselines in online events.
- Do not put the RFF feature vector inside application payload or cryptographic AAD.
- RFF identity is hop-local: compare against `claimed_link_sender_id`, never blindly against end-to-end `claimed_src_id`.
- RSSI, CSI, and SINR adjust observation quality/noise; they are not identity-vector dimensions.
- Phase one is observation-only. No RFF result may change queue admission, drop counters, business execution, routing, or existing HMAC/replay behavior.
- Keep existing external `rff` model-adapter interfaces available; the deterministic simulated identifier is a local baseline, not a claim of trained-model accuracy.
- All new thresholds are uncalibrated simulation defaults and must be persisted through `RunConfig`.
- Existing untracked documents at repository root are outside this plan and must not be staged.

---

## File Structure

- Create `swarm_sim/rff.py`: feature schema, device registry, observation generator, receiver templates, and deterministic identifier.
- Create `tests/test_rff_profiles.py`: deterministic profile, drift/noise, quality, enrollment, and distance tests.
- Create `tests/integration/test_rff_receive_pipeline.py`: normal direct and multi-hop runtime integration tests.
- Create `tests/acceptance/test_rff_observe_only.py`: attack mismatch, no-enforcement, and truth-leakage acceptance tests.
- Modify `swarm_sim/simulation.py`: RFF observe-only configuration and validation.
- Modify `swarm_sim/domain.py`: hop-claimed identity and receiver-local last-result fields.
- Modify `swarm_sim/adapters.py`: initialize `claimed_link_sender_id` on newly protected frames.
- Modify `swarm_sim/runtime.py`: initialize RFF service, register external devices, sample/identify per reception, and preserve copied-frame hop claims.
- Modify `swarm_sim/events.py`: frozen online packet, PHY, and security fields.
- Modify `dataset/schema.json`: field types, enums, ranges, and nullable rules.
- Modify existing frame-construction tests only where a required assertion is needed; keep `claimed_link_sender_id` optional on manually constructed legacy fixtures.

---

### Task 1: Deterministic Device Profiles and Receiver Observations

**Files:**
- Create: `swarm_sim/rff.py`
- Create: `tests/test_rff_profiles.py`

**Interfaces:**
- Consumes: `swarm_sim.simulation.RNGRegistry`.
- Produces: `RFF_FEATURE_SCHEMA`, `RFF_FEATURE_NAMES`, `DeviceRffProfile`, `RffObservation`, `DeviceRffProfileRegistry`, and `RffObservationGenerator.observe(...)`.

- [ ] **Step 1: Write failing tests for profile reproducibility and separation**

```python
from swarm_sim.rff import DeviceRffProfileRegistry, RFF_FEATURE_NAMES
from swarm_sim.simulation import RNGRegistry


def test_device_profiles_are_reproducible_and_device_specific():
    first = DeviceRffProfileRegistry(RNGRegistry(42))
    second = DeviceRffProfileRegistry(RNGRegistry(42))
    assert first.ensure(2).baseline == second.ensure(2).baseline
    assert first.ensure(2).baseline != first.ensure(3).baseline
    assert len(first.ensure(2).baseline) == len(RFF_FEATURE_NAMES) == 8
```

- [ ] **Step 2: Run the profile test and verify the missing module failure**

Run: `python -m pytest tests/test_rff_profiles.py::test_device_profiles_are_reproducible_and_device_specific -v`

Expected: FAIL because `swarm_sim.rff` does not exist.

- [ ] **Step 3: Implement immutable feature/profile/observation types and registry**

```python
RFF_FEATURE_SCHEMA = "RFF_FEATURE_V1"
RFF_FEATURE_NAMES = (
    "cfo_ppm", "iq_gain_imbalance_db", "iq_phase_imbalance_deg",
    "dc_offset_i", "dc_offset_q", "pa_am_am", "pa_am_pm",
    "clock_skew_ppm",
)

@dataclass(frozen=True, slots=True)
class DeviceRffProfile:
    device_id: int
    feature_schema: str
    baseline: tuple[float, ...]

@dataclass(frozen=True, slots=True)
class RffObservation:
    sample_id: str
    feature_schema: str
    feature_vector: tuple[float, ...]
    quality: float
    extraction_status: str
    missing_reason: str | None

    def to_online_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "feature_schema": self.feature_schema,
            "feature_vector": list(self.feature_vector),
            "quality": self.quality,
            "extraction_status": self.extraction_status,
            "missing_reason": self.missing_reason,
        }

class DeviceRffProfileRegistry:
    _FEATURE_RANGES = (
        (-12.0, 12.0), (-1.2, 1.2), (-4.0, 4.0),
        (-0.08, 0.08), (-0.08, 0.08), (0.92, 1.08),
        (-3.0, 3.0), (-8.0, 8.0),
    )

    def __init__(self, rng_registry: RNGRegistry) -> None:
        self._rng_registry = rng_registry
        self._profiles: dict[int, DeviceRffProfile] = {}

    def ensure(self, device_id: int) -> DeviceRffProfile:
        existing = self._profiles.get(device_id)
        if existing is not None:
            return existing
        rng = self._rng_registry.python(f"rff-profile:{device_id}")
        baseline = tuple(
            round(rng.uniform(lower, upper), 6)
            for lower, upper in self._FEATURE_RANGES
        )
        profile = DeviceRffProfile(device_id, RFF_FEATURE_SCHEMA, baseline)
        self._profiles[device_id] = profile
        return profile
```

Generate each dimension from a dedicated `rff-profile:{device_id}` random stream and fixed dimension-specific ranges. Do not expose a method that serializes all profiles into online data.

- [ ] **Step 4: Write failing tests for noisy observation behavior**

```python
def test_observation_is_reproducible_and_quality_controls_noise():
    def sample(seed: int, quality: float):
        rng = RNGRegistry(seed)
        registry = DeviceRffProfileRegistry(rng)
        generator = RffObservationGenerator(registry, rng)
        return generator.observe(
            actual_device_id=2, receiver_id=1, sim_time_s=1.0,
            sinr_db=18.0, measurement_quality=quality,
            sample_id="rff-sample-1",
        )
    assert sample(42, 0.9) == sample(42, 0.9)
    assert sample(42, 0.9).feature_vector != sample(42, 0.3).feature_vector
    assert sample(42, 0.9).quality > sample(42, 0.3).quality
```

- [ ] **Step 5: Implement online drift, receiver bias, and quality-dependent noise**

```python
class RffObservationGenerator:
    _DRIFT_SIGMA = (0.03, 0.005, 0.015, 0.0004, 0.0004, 0.0005, 0.01, 0.02)
    _NOISE_SIGMA = (0.20, 0.03, 0.08, 0.002, 0.002, 0.003, 0.05, 0.10)

    def __init__(
        self,
        registry: DeviceRffProfileRegistry,
        rng_registry: RNGRegistry,
        quality_threshold: float = 0.45,
    ) -> None:
        self._registry = registry
        self._rng_registry = rng_registry
        self._quality_threshold = quality_threshold
        self._drift: dict[tuple[int, int], float] = {}
        self._receiver_biases: dict[int, tuple[float, ...]] = {}

    def receiver_bias(self, receiver_id: int) -> tuple[float, ...]:
        cached = self._receiver_biases.get(receiver_id)
        if cached is not None:
            return cached
        rng = self._rng_registry.python(f"rff-receiver-bias:{receiver_id}")
        bias = tuple(rng.gauss(0.0, sigma * 0.5) for sigma in self._NOISE_SIGMA)
        self._receiver_biases[receiver_id] = bias
        return bias

    def observe(
        self, *, actual_device_id: int, receiver_id: int,
        sim_time_s: float, sinr_db: float | None,
        measurement_quality: float | None, sample_id: str,
    ) -> RffObservation:
        if sinr_db is None or measurement_quality is None:
            return RffObservation(
                sample_id, RFF_FEATURE_SCHEMA, (), 0.0,
                "UNAVAILABLE", "PHY_QUALITY_UNAVAILABLE",
            )
        sinr_factor = max(0.0, min(1.0, (sinr_db + 5.0) / 25.0))
        quality = max(0.0, min(1.0, measurement_quality * sinr_factor))
        profile = self._registry.ensure(actual_device_id)
        bias = self.receiver_bias(receiver_id)
        rng = self._rng_registry.python(
            f"rff-online:{actual_device_id}:{receiver_id}"
        )
        values = []
        for index, baseline in enumerate(profile.baseline):
            key = (actual_device_id, index)
            previous = self._drift.get(key, 0.0)
            drift = 0.98 * previous + rng.gauss(0.0, self._DRIFT_SIGMA[index])
            self._drift[key] = drift
            noise_scale = self._NOISE_SIGMA[index] / max(quality, 0.05)
            values.append(baseline + bias[index] + drift + rng.gauss(0.0, noise_scale))
        status = "AVAILABLE" if quality >= self._quality_threshold else "LOW_QUALITY"
        reason = "OK" if status == "AVAILABLE" else "QUALITY_BELOW_THRESHOLD"
        return RffObservation(
            sample_id, RFF_FEATURE_SCHEMA, tuple(values), quality, status, reason,
        )
```

Maintain AR(1) drift by `(actual_device_id, feature_index)`, receiver bias by `(receiver_id, feature_index)`, and sample noise by `(actual_device_id, receiver_id)`. Clamp output quality to `[0, 1]`. Return `UNAVAILABLE` with an empty vector and `PHY_QUALITY_UNAVAILABLE` when SINR or measurement quality is absent; return `LOW_QUALITY` when computed quality is below the configured quality floor.

- [ ] **Step 6: Run the RFF profile tests**

Run: `python -m pytest tests/test_rff_profiles.py -v`

Expected: PASS.

- [ ] **Step 7: Commit Task 1**

```bash
git add v8_platform/swarm_sim/rff.py v8_platform/tests/test_rff_profiles.py
git commit -m "feat: add deterministic RFF profile simulation"
```

---

### Task 2: Receiver Enrollment Templates and Deterministic Identification

**Files:**
- Modify: `swarm_sim/rff.py`
- Modify: `tests/test_rff_profiles.py`

**Interfaces:**
- Consumes: `RffObservation`, `DeviceRffProfileRegistry`, `RNGRegistry`.
- Produces: `RffTemplate`, `RffIdentificationResult`, `ReceiverRffTemplateStore.enroll(...)`, `ReceiverRffTemplateStore.identify(...)`, and `RffService` facade.

- [ ] **Step 1: Write failing tests for receiver-specific enrollment**

```python
def test_templates_are_receiver_specific_and_exclude_external_devices():
    service = RffService(RNGRegistry(42), enrollment_samples=20)
    service.register_device(2)
    service.register_device(-1)
    service.enroll(receiver_id=1, device_id=2)
    assert service.template_store.is_whitelisted(1, 2)
    assert not service.template_store.is_whitelisted(1, -1)
    assert not service.template_store.is_whitelisted(0, 2)
```

- [ ] **Step 2: Run the enrollment test and verify failure**

Run: `python -m pytest tests/test_rff_profiles.py::test_templates_are_receiver_specific_and_exclude_external_devices -v`

Expected: FAIL because `RffService` and template storage are not implemented.

- [ ] **Step 3: Implement enrollment using an independent RNG stream**

```python
@dataclass(frozen=True, slots=True)
class RffTemplate:
    receiver_id: int
    device_id: int
    feature_schema: str
    feature_mean: tuple[float, ...]
    feature_std: tuple[float, ...]
    sample_count: int

class ReceiverRffTemplateStore:
    _STD_FLOOR = (0.10, 0.015, 0.04, 0.001, 0.001, 0.0015, 0.025, 0.05)

    def __init__(self, rng_registry: RNGRegistry,
                 observation_generator: RffObservationGenerator) -> None:
        self._rng_registry = rng_registry
        self._observation_generator = observation_generator
        self._templates: dict[tuple[int, int], RffTemplate] = {}

    def enroll(self, receiver_id: int, device_id: int,
               profile: DeviceRffProfile, sample_count: int) -> RffTemplate:
        rng = self._rng_registry.python(f"rff-enroll:{receiver_id}:{device_id}")
        bias = self._observation_generator.receiver_bias(receiver_id)
        columns = [[] for _ in RFF_FEATURE_NAMES]
        for _sample_index in range(sample_count):
            for index, baseline in enumerate(profile.baseline):
                value = baseline + bias[index] + rng.gauss(0.0, self._STD_FLOOR[index])
                columns[index].append(value)
        means = tuple(statistics.fmean(column) for column in columns)
        stds = tuple(
            max(statistics.pstdev(column), self._STD_FLOOR[index])
            for index, column in enumerate(columns)
        )
        template = RffTemplate(
            receiver_id, device_id, RFF_FEATURE_SCHEMA, means, stds, sample_count,
        )
        self._templates[(receiver_id, device_id)] = template
        return template

    def templates_for_receiver(self, receiver_id: int) -> tuple[RffTemplate, ...]:
        return tuple(
            template for (stored_receiver_id, _), template in self._templates.items()
            if stored_receiver_id == receiver_id
        )

    def is_whitelisted(self, receiver_id: int, device_id: int) -> bool:
        return (receiver_id, device_id) in self._templates
```

Use `rff-enroll:{receiver_id}:{device_id}` streams. Enrollment must include receiver bias and registration noise but must not advance online drift/noise streams.

- [ ] **Step 4: Write failing identification tests for MATCH, MISMATCH, UNKNOWN, AMBIGUOUS, and LOW_QUALITY**

```python
def enrolled_service(seed: int, receiver_id: int,
                     legal_ids: tuple[int, ...]) -> RffService:
    service = RffService(
        RNGRegistry(seed), enrollment_samples=20,
        quality_threshold=0.45, distance_threshold=3.0,
        min_identity_margin=0.5,
    )
    for device_id in legal_ids:
        service.register_device(device_id)
        service.enroll(receiver_id=receiver_id, device_id=device_id)
    return service

def test_identification_compares_prediction_with_claimed_hop_sender():
    service = enrolled_service(seed=42, receiver_id=1, legal_ids=(2, 3))
    observation = service.observe(
        actual_device_id=2, receiver_id=1, sim_time_s=1.0,
        sinr_db=20.0, measurement_quality=0.95, sample_id="rff-1",
    )
    matched = service.identify(1, 2, observation)
    mismatched = service.identify(1, 3, observation)
    assert matched.identity_result == "MATCH"
    assert matched.predicted_device_id == 2
    assert mismatched.identity_result == "MISMATCH"
    assert mismatched.predicted_device_id == 2
```

- [ ] **Step 5: Implement normalized distance and result serialization**

```python
@dataclass(frozen=True, slots=True)
class RffIdentificationResult:
    identity_result: str
    predicted_device_id: int | None
    claimed_link_sender_id: int | None
    distance: float | None
    threshold: float
    confidence: float | None
    quality: float | None
    reason: str

    def to_security_state(self) -> dict[str, Any]:
        return {
            "rff_identity_result": self.identity_result,
            "rff_predicted_device_id": self.predicted_device_id,
            "rff_claimed_link_sender_id": self.claimed_link_sender_id,
            "rff_distance": self.distance,
            "rff_threshold": self.threshold,
            "rff_identity_confidence": self.confidence,
            "rff_quality": self.quality,
            "rff_reason": self.reason,
        }
```

Implement `RffService.register_device`, `enroll`, `observe`, and `identify` as a facade over the registry, generator, and template store. In `identify`, compute each template's root-mean-square standardized distance using `sqrt(mean(((value - mean) / std) ** 2))`; use the enrolled standard deviations, which already apply a per-dimension floor. Sort `(distance, device_id)` pairs to make ties deterministic. Require both `nearest_distance <= distance_threshold` and `second_distance - nearest_distance >= min_identity_margin`. Return `MATCH` when the predicted ID equals the claimed hop ID, `MISMATCH` when it differs, `UNKNOWN` when every template exceeds the threshold, and `AMBIGUOUS` when the nearest candidates lack margin. `LOW_QUALITY` and `UNAVAILABLE` bypass template distance and retain their status as the identity result. Compute confidence as `max(0.0, min(1.0, 1.0 - nearest_distance / distance_threshold))`.

- [ ] **Step 6: Run all unit tests and confirm no state-order flakiness**

Run: `python -m pytest tests/test_rff_profiles.py -v`

Expected: PASS on two consecutive invocations with identical results.

- [ ] **Step 7: Commit Task 2**

```bash
git add v8_platform/swarm_sim/rff.py v8_platform/tests/test_rff_profiles.py
git commit -m "feat: add receiver-local RFF template identification"
```

---

### Task 3: Freeze Configuration, Frame Identity, and Event Contracts

**Files:**
- Modify: `swarm_sim/simulation.py`
- Modify: `swarm_sim/domain.py`
- Modify: `swarm_sim/adapters.py`
- Modify: `swarm_sim/events.py`
- Modify: `dataset/schema.json`
- Create: `tests/integration/test_rff_receive_pipeline.py`

**Interfaces:**
- Consumes: Task 2 result field names.
- Produces: validated `RunConfig` RFF fields, `Frame.claimed_link_sender_id`, frozen online event fields, and schema validation support.

- [ ] **Step 1: Write failing configuration validation tests**

```python
def test_rff_observe_only_configuration_is_validated_and_fingerprinted():
    config = RunConfig(rff_enabled=True, rff_policy_mode="OBSERVE_ONLY")
    changed = RunConfig(rff_enabled=False, rff_policy_mode="OBSERVE_ONLY")
    assert config.semantic_fingerprint() != changed.semantic_fingerprint()
    with pytest.raises(ValueError, match="rff_policy_mode"):
        RunConfig(rff_policy_mode="DROP_EVERYTHING")
```

- [ ] **Step 2: Add exact `RunConfig` defaults and validation**

```python
rff_enabled: bool = True
rff_policy_mode: str = "OBSERVE_ONLY"
rff_enrollment_samples: int = 20
rff_quality_threshold: float = 0.45
rff_distance_threshold: float = 3.0
rff_min_identity_margin: float = 0.5
rff_queue_pressure_ratio: float = 0.60
rff_strict_hold_s: float = 2.0
rff_strict_on_rate_alarm: bool = True
```

Require booleans for boolean fields, `rff_policy_mode in {"OBSERVE_ONLY", "ENFORCE"}`, positive sample count/distance/hold time, and `[0, 1]` quality/queue ratios. Phase-one runtime must reject `ENFORCE` with `RFF_ENFORCEMENT_NOT_IMPLEMENTED` rather than silently observing.

- [ ] **Step 3: Write a failing frame/event contract test**

```python
def test_protected_frame_and_rx_event_expose_claimed_hop_identity_not_truth():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="rff-contract")
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    event = next(e for e in runtime.events
                 if e["event_type"] == "RX_SUCCESS" and e["message_id"] == message_id)
    assert event["online_features"]["packet"]["claimed_link_sender_id"] == 2
    assert "actual_transmitter_id" not in json.dumps(event)
```

- [ ] **Step 4: Add optional `Frame.claimed_link_sender_id` and initialize it in crypto protection**

Append `claimed_link_sender_id: int | None = None` to `Frame` optional fields so legacy fixture constructors remain valid. In `TestOnlyAeadCryptoProvider.protect`, set `claimed_link_sender_id=sender_id`. Do not include this new observable claim in application HMAC or change existing link AAD in phase one.

- [ ] **Step 5: Extend event defaults and schema**

Add `claimed_link_sender_id` to `online_features.packet`; add nested `rff_observation` to `online_features.phy`; add the following to `online_features.security_state`:

```text
rff_identity_result
rff_predicted_device_id
rff_claimed_link_sender_id
rff_distance
rff_threshold
rff_identity_confidence
rff_quality
rff_reason
rff_last_update_s
```

Freeze enums and ranges in `dataset/schema.json`. Keep all RFF fields nullable when `rff_enabled=false` or extraction is unavailable. Update `build_event` only through its existing allow-list dictionaries so arbitrary nested truth cannot pass through.

- [ ] **Step 6: Run configuration and contract tests**

Run: `python -m pytest tests/integration/test_rff_receive_pipeline.py tests/test_v1_data_interfaces.py tests/test_v1_second_round_contracts.py -v`

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add v8_platform/swarm_sim/simulation.py v8_platform/swarm_sim/domain.py v8_platform/swarm_sim/adapters.py v8_platform/swarm_sim/events.py v8_platform/dataset/schema.json v8_platform/tests/integration/test_rff_receive_pipeline.py
git commit -m "feat: define RFF observe-only event contracts"
```

---

### Task 4: Integrate RFF Sampling and Identification into the RX Path

**Files:**
- Modify: `swarm_sim/runtime.py`
- Modify: `swarm_sim/domain.py`
- Modify: `tests/integration/test_rff_receive_pipeline.py`

**Interfaces:**
- Consumes: `RffService.observe(...)`, `RffService.identify(...)`, and Task 3 event fields.
- Produces: `PlatformRuntime.rff_service`, receiver-local enrollment, per-hop RFF observations, and last-result state.

- [ ] **Step 1: Write a failing normal direct-link integration test**

```python
def test_normal_direct_link_produces_matching_observe_only_result():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rff_policy_mode="OBSERVE_ONLY"),
        run_id="rff-direct",
    )
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    event = next(e for e in runtime.events
                 if e["event_type"] == "RX_SUCCESS" and e["message_id"] == message_id)
    assert event["online_features"]["security_state"]["rff_identity_result"] == "MATCH"
    assert event["online_features"]["phy"]["rff_observation"]["feature_schema"] == "RFF_FEATURE_V1"
```

- [ ] **Step 2: Initialize and enroll the service after topology creation**

In `PlatformRuntime.__init__`, create `RffService` after `FormationTopology` and before initial state emission. Register every configured legitimate node. For every active directed link whose source and destination are non-EXTERNAL, enroll the source device in the destination's template store. Store no external profile in a whitelist.

- [ ] **Step 3: Register late-created external transmitters without enrollment**

In `_external_node`, call `self.rff_service.register_device(node_id)` after node creation when the service exists. Do not enroll this node when `ensure_external_ingress` adds an attack link.

- [ ] **Step 4: Sample and identify immediately after `self.phy.sample(...)`**

```python
rff_observation = self.rff_service.observe(
    actual_device_id=sender.node_id,
    receiver_id=receiver.node_id,
    sim_time_s=self.context.clock.now_s,
    sinr_db=outcome.observation.get("sinr_db"),
    measurement_quality=outcome.observation.get("measurement_quality"),
    sample_id=self.context.ids.next("rff"),
)
rff_result = self.rff_service.identify(
    receiver.node_id,
    frame.claimed_link_sender_id,
    rff_observation,
)
observation["rff_observation"] = rff_observation.to_online_dict()
```

Pass `rff_result.to_security_state()` to both RX_SUCCESS and RX_FAILURE `build_event` calls. Update receiver-local last-result fields for later snapshots. Do not branch on `identity_result` and do not call `_handle_detection` in this task.

- [ ] **Step 5: Write a failing multi-hop correctness test**

```python
def test_multihop_rff_compares_each_physical_relay_not_original_source():
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False), run_id="rff-hop")
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    received = [e for e in runtime.events if e["event_type"] == "RX_SUCCESS"
                and e["message_id"] == message_id]
    leader = next(e for e in received if e["observer_node_id"] == 1)
    gcs = next(e for e in received if e["observer_node_id"] == 0)
    assert leader["online_features"]["packet"]["claimed_link_sender_id"] == 2
    assert gcs["online_features"]["packet"]["claimed_link_sender_id"] == 1
    assert {leader["online_features"]["security_state"]["rff_identity_result"],
            gcs["online_features"]["security_state"]["rff_identity_result"]} == {"MATCH"}
```

- [ ] **Step 6: Run direct, multi-hop, and legacy PHY tests**

Run: `python -m pytest tests/integration/test_rff_receive_pipeline.py tests/test_csi_channel.py tests/test_nr_channel_model.py tests/test_v1_attacks_security.py -v`

Expected: PASS, with no queue/drop changes caused by RFF.

- [ ] **Step 7: Commit Task 4**

```bash
git add v8_platform/swarm_sim/runtime.py v8_platform/swarm_sim/domain.py v8_platform/tests/integration/test_rff_receive_pipeline.py
git commit -m "feat: observe RFF identity on every receive hop"
```

---

### Task 5: Preserve Legal Hop Claims in External Re-Transmission Attacks

**Files:**
- Modify: `swarm_sim/runtime.py`
- Create: `tests/acceptance/test_rff_observe_only.py`

**Interfaces:**
- Consumes: `Frame.claimed_link_sender_id` and runtime RFF events.
- Produces: faithful external re-transmission semantics for copied spoofing, capture-modify-inject FDI, replay, and flooding observations.

- [ ] **Step 1: Write failing copied-spoof, FDI, replay, and flooding identity tests**

```python
from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from tests.acceptance.test_v20_fdi_copies import copied_configuration


def _copied_spoof_runtime(*, rff_enabled: bool = True) -> PlatformRuntime:
    return PlatformRuntime(RunConfig(
        duration_s=3.2, step_s=0.2, auto_traffic=False,
        queue_capacity=128, tx_service_per_step=64, rx_service_per_step=64,
        rff_enabled=rff_enabled, rff_policy_mode="OBSERVE_ONLY",
        traffic_specs=[{
            "source_node_id": 2, "target_node_id": 1, "packet_type": "STATUS",
            "payload": {"status_code": 1, "value": 42}, "start_s": 0.2,
            "interval_s": 0.4, "count": 6, "session_id": "source",
            "sequence_start": 100,
        }],
        attack_specs=[{
            "attack_family": "SPOOFING", "attack_subtype": "KNOWN_ID_CONFLICT",
            "scheduled_start_s": 0.0, "impact_start_s": 0.4, "end_s": 2.4,
            "attacker_node_id": -1, "target_node_ids": [1],
            "parameters": {
                "claimed_src_id": 0, "source_copy_mode": "LEGITIMATE_FRAME_COPY",
                "legitimate_source_id": 2,
            },
        }],
    ))

def _copied_fdi_runtime(*, rff_enabled: bool = True) -> PlatformRuntime:
    config = copied_configuration(duration=3.2, count=10, end=2.4)
    config.rff_enabled = rff_enabled
    config.rff_policy_mode = "OBSERVE_ONLY"
    return PlatformRuntime(config)

def _replay_runtime(*, rff_enabled: bool = True) -> PlatformRuntime:
    runtime = PlatformRuntime(RunConfig(
        duration_s=1.6, auto_traffic=False,
        rff_enabled=rff_enabled, rff_policy_mode="OBSERVE_ONLY",
    ))
    runtime.schedule_attack(AttackPlan(
        attack_family="REPLAY", attack_subtype="CAPTURE_AND_REPLAY",
        scheduled_start_s=0.0, impact_start_s=0.6, end_s=1.2,
        attacker_node_id=-1, target_node_ids=[1],
    ))
    runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95})
    return runtime

def _flooding_runtime(*, rff_enabled: bool = True) -> PlatformRuntime:
    return PlatformRuntime(RunConfig(
        duration_s=1.6, auto_traffic=False, queue_capacity=32,
        tx_service_per_step=20, rx_service_per_step=20,
        rff_enabled=rff_enabled, rff_policy_mode="OBSERVE_ONLY",
        attack_specs=[{
            "attack_family": "DOS", "attack_subtype": "FLOODING",
            "scheduled_start_s": 0.0, "impact_start_s": 0.2, "end_s": 1.2,
            "attacker_node_id": -1, "target_node_ids": [1],
            "intensity": {"value": 100.0, "unit": "pps"},
        }],
    ))

@pytest.mark.parametrize(
    "runtime_factory",
    [_copied_spoof_runtime, _copied_fdi_runtime, _replay_runtime, _flooding_runtime],
)
def test_external_retransmission_is_observed_as_hop_identity_mismatch(runtime_factory):
    runtime = runtime_factory()
    runtime.run_to_completion()
    receive_events = [
        event for event in runtime.events
        if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
    ]
    assert any(
        event["online_features"]["security_state"]["rff_identity_result"]
        in {"MISMATCH", "UNKNOWN"}
        for event in receive_events
    )
```

- [ ] **Step 2: Preserve the captured legal hop claim while using the attacker for PHY**

- `_inject_derived_spoofing`: cloned frame keeps the original `claimed_link_sender_id`; `sender` passed to `_perform_air_transmission` remains the external attacker.
- `_inject_derived_fdi`: after `crypto.protect`, replace only `frame.claimed_link_sender_id` with the captured original frame's claimed hop identity; do not alter `frame.link_sender_id`, keys, or AAD.
- `_transmit_replay_frame`: cloned frame naturally retains the original claim while the existing external attacker object remains the PHY sender.
- Flooding: leave the claim as the external sender; it should identify as `UNKNOWN` because the device is not enrolled, even without spoofing a legal address.

- [ ] **Step 3: Write a no-enforcement assertion for every mismatch**

```python
def test_observe_only_mismatch_does_not_change_delivery_or_drop_counts():
    observed = _copied_spoof_runtime(rff_enabled=True)
    disabled = _copied_spoof_runtime(rff_enabled=False)
    observed.run_to_completion()
    disabled.run_to_completion()
    assert observed.metrics()["delivered"] == disabled.metrics()["delivered"]
    assert observed.metrics()["queue_drops"] == disabled.metrics()["queue_drops"]
```

- [ ] **Step 4: Add explicit capability-boundary tests**

Create tests showing that a normal frame emitted by legitimate device 2 remains `MATCH` even when its simulator-side business payload is malicious, and that a pure eavesdropping episode emits no RFF attack alarm. These tests prevent later code from claiming RFF detects a compromised legitimate radio or passive listening.

- [ ] **Step 5: Run attack observation acceptance tests**

Run: `python -m pytest tests/acceptance/test_rff_observe_only.py tests/acceptance/test_v20_fdi_copies.py tests/acceptance/test_v10_application_hmac_semantics.py -v`

Expected: PASS.

- [ ] **Step 6: Commit Task 5**

```bash
git add v8_platform/swarm_sim/runtime.py v8_platform/tests/acceptance/test_rff_observe_only.py
git commit -m "feat: model RFF identity for external retransmissions"
```

---

### Task 6: Truth-Leakage, Dataset, and Regression Closure

**Files:**
- Modify: `swarm_sim/events.py`
- Modify: `swarm_sim/runtime.py`
- Modify: `tests/acceptance/test_rff_observe_only.py`
- Modify: `tests/test_v1_data_interfaces.py`
- Modify: `tests/test_v1_second_round_contracts.py`

**Interfaces:**
- Consumes: all phase-one event and runtime behavior.
- Produces: explicit provenance, recursive truth-leak protection, exported schema-valid datasets, and final compatibility evidence.

- [ ] **Step 1: Write a recursive no-truth-leak test**

```python
def test_rff_online_observation_never_contains_ground_truth_identity_or_baseline():
    runtime = _copied_spoof_runtime()
    runtime.run_to_completion()
    online = json.dumps(
        [event["online_features"] for event in runtime.events],
        ensure_ascii=False, sort_keys=True,
    )
    assert "actual_transmitter_id" not in online
    assert "noiseless_baseline" not in online
    assert "attack_family" not in online
    assert "attacker_node_id" not in online
```

- [ ] **Step 2: Expand forbidden-field checks for RFF-specific truth aliases**

Add `true_device_id`, `rff_ground_truth_id`, `noiseless_rff_vector`, and `device_rff_baseline` to `FORBIDDEN_ONLINE_FIELDS`. Keep `predicted_device_id` allowed because it is a detector output, not simulator truth.

- [ ] **Step 3: Persist RFF provenance in the run record**

Add an `rff_simulation` section to `run_record()` containing only:

```json
{
  "enabled": true,
  "policy_mode": "OBSERVE_ONLY",
  "feature_schema": "RFF_FEATURE_V1",
  "provider": "SIMULATED_FEATURE_TEMPLATE",
  "calibration_status": "UNCALIBRATED_BASELINE",
  "enrollment_samples": 20,
  "quality_threshold": 0.45,
  "distance_threshold": 3.0,
  "min_identity_margin": 0.5
}
```

Do not export profile baselines or receiver-template vectors in the run record.

- [ ] **Step 4: Validate exported datasets with RFF enabled and disabled**

```python
def test_rff_observe_only_export_validates(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, rff_enabled=True), run_id="rff-export")
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
```

Add a disabled-mode assertion that all RFF observation/result fields are null and existing events remain schema-valid.

- [ ] **Step 5: Run the focused phase-one suite**

Run: `python -m pytest tests/test_rff_profiles.py tests/integration/test_rff_receive_pipeline.py tests/acceptance/test_rff_observe_only.py tests/test_v1_data_interfaces.py tests/test_v1_second_round_contracts.py -v`

Expected: PASS.

- [ ] **Step 6: Run existing attack, PHY, event, API, and schema regressions**

Run: `python -m pytest tests/test_v1_attacks_security.py tests/test_csi_channel.py tests/test_nr_channel_model.py tests/test_v1_api.py tests/acceptance/test_v10_application_hmac_semantics.py tests/acceptance/test_v20_fdi_copies.py tests/acceptance/test_schema_migration_final.py -v`

Expected: PASS.

- [ ] **Step 7: Run the full suite with progress output**

Run: `python -m pytest -v`

Expected: PASS. If an existing unrelated test hangs, record the exact last test name and rerun the two focused suites above; do not report full-suite success without a completed exit code.

- [ ] **Step 8: Commit Task 6**

```bash
git add v8_platform/swarm_sim/events.py v8_platform/swarm_sim/runtime.py v8_platform/tests/acceptance/test_rff_observe_only.py v8_platform/tests/test_v1_data_interfaces.py v8_platform/tests/test_v1_second_round_contracts.py
git commit -m "test: close RFF observe-only data contracts"
```

---

## Phase-One Completion Gate

Phase one is complete only when:

- every normal direct and multi-hop receive event has correct hop-local RFF semantics;
- external copied spoofing, FDI, replay, and flooding produce observable identity outcomes;
- RFF never changes delivery, queue, defense, or business state in `OBSERVE_ONLY`;
- all online truth-leak tests and dataset validation pass;
- the focused regression suites complete with zero failures;
- observed normal-sample distances and qualities are reviewed before an enforcement threshold is accepted.

Only after this gate should a second plan add `MISMATCH` drops and DoS `RFF_STRICT_WHITELIST` state transitions.
