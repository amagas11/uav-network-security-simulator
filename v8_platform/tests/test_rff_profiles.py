from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import math
import statistics

import pytest

from swarm_sim.rff import (
    DeviceRffProfileRegistry,
    RFF_FEATURE_NAMES,
    RFF_FEATURE_SCHEMA,
    RffObservationGenerator,
    RffObservation,
    RffTemplate,
    RffService,
)
from swarm_sim.simulation import RNGRegistry


def generator(seed=42):
    rng = RNGRegistry(seed)
    profiles = DeviceRffProfileRegistry(rng)
    return profiles, RffObservationGenerator(profiles, rng)


def observe(source, **changes):
    arguments = dict(
        actual_device_id=2, receiver_id=1, sim_time_s=1.0,
        sinr_db=20.0, measurement_quality=0.95, sample_id="rff-sample-1",
    )
    arguments.update(changes)
    return source.observe(**arguments)


def test_device_profiles_are_reproducible_and_device_specific():
    first = DeviceRffProfileRegistry(RNGRegistry(42))
    second = DeviceRffProfileRegistry(RNGRegistry(42))
    assert first.ensure(2).baseline == second.ensure(2).baseline
    assert first.ensure(2).baseline != first.ensure(3).baseline
    assert first.ensure(2).baseline != first.ensure(-1).baseline
    assert first.ensure(2).baseline != DeviceRffProfileRegistry(RNGRegistry(43)).ensure(2).baseline
    assert len(first.ensure(2).baseline) == len(RFF_FEATURE_NAMES) == 8
    assert first.ensure(2) is first.ensure(2)
    assert first.ensure(2).feature_schema == "RFF_FEATURE_V1"
    with pytest.raises(FrozenInstanceError):
        first.ensure(2).device_id = 3


def test_profiles_are_independent_of_registration_order_and_other_streams():
    rng = RNGRegistry(42)
    first = DeviceRffProfileRegistry(rng)
    second = DeviceRffProfileRegistry(RNGRegistry(42))
    rng.python("phy").random()
    first.ensure(-1)
    first.ensure(3)
    assert first.ensure(2) == second.ensure(2)


def test_profile_dimensions_use_the_specified_physical_ranges():
    ranges = (
        (-12, 12), (-1.2, 1.2), (-4, 4), (-0.08, 0.08),
        (-0.08, 0.08), (0.92, 1.08), (-3, 3), (-8, 8),
    )
    profiles = DeviceRffProfileRegistry(RNGRegistry(42))
    for device_id in range(-2, 20):
        assert all(low <= value <= high for value, (low, high) in zip(
            profiles.ensure(device_id).baseline, ranges,
        ))


@pytest.mark.parametrize("device_id", [None, True, 2.0, "2"])
def test_profile_registry_rejects_invalid_device_ids(device_id):
    with pytest.raises(ValueError):
        DeviceRffProfileRegistry(RNGRegistry(42)).ensure(device_id)


def test_observation_is_reproducible_and_quality_controls_noise():
    high = observe(generator()[1], sinr_db=18.0, measurement_quality=0.9)
    low = observe(generator()[1], sinr_db=18.0, measurement_quality=0.3)
    assert high == observe(generator()[1], sinr_db=18.0, measurement_quality=0.9)
    assert high.feature_vector != low.feature_vector
    assert high.quality == pytest.approx(0.828)
    assert low.quality == pytest.approx(0.276)
    assert high.extraction_status == "AVAILABLE"
    assert low.extraction_status == "LOW_QUALITY"
    assert low.missing_reason == "QUALITY_BELOW_THRESHOLD"


def test_lower_quality_increases_empirical_measurement_error():
    errors = []
    for quality in (0.95, 0.2):
        profiles, source = generator()
        center = profiles.ensure(2).baseline[0] + source.receiver_bias(1)[0]
        values = [observe(source, measurement_quality=quality).feature_vector[0] - center
                  for _ in range(500)]
        errors.append(statistics.pstdev(values))
    assert errors[1] > errors[0] * 3


def test_receiver_bias_is_fixed_reproducible_and_receiver_specific():
    _, source = generator()
    assert source.receiver_bias(1) == source.receiver_bias(1)
    assert source.receiver_bias(1) == generator()[1].receiver_bias(1)
    assert source.receiver_bias(1) != source.receiver_bias(0)


def test_same_time_extra_reception_does_not_advance_device_drift():
    _, first = generator()
    _, second = generator()
    assert observe(first) == observe(second)
    for _ in range(10):
        observe(first, receiver_id=9)
    assert observe(first, sim_time_s=2.0) == observe(second, sim_time_s=2.0)


def test_drift_depends_on_elapsed_time_not_reception_count():
    _, first = generator()
    _, second = generator()
    observe(first, sim_time_s=0.0)
    observe(second, sim_time_s=0.0)
    assert observe(first, sim_time_s=1.0) != observe(second, sim_time_s=100.0)


def test_elapsed_ar1_drift_is_shared_by_receivers(monkeypatch):
    rng = RNGRegistry(42)
    profiles = DeviceRffProfileRegistry(rng)
    source = RffObservationGenerator(profiles, rng)
    for name in ("rff-online:2:1", "rff-online:2:9", "rff-channel:2:1", "rff-channel:2:9"):
        monkeypatch.setattr(rng.python(name), "gauss", lambda mean, sigma: 0.0)
    monkeypatch.setattr(rng.python("rff-drift:2"), "gauss", lambda mean, sigma: sigma)
    baseline = profiles.ensure(2).baseline
    initial = observe(source, sim_time_s=0.0)
    assert initial.feature_vector == pytest.approx(tuple(
        value + bias for value, bias in zip(baseline, source.receiver_bias(1))
    ))
    first = observe(source, sim_time_s=1.0)
    other = observe(source, receiver_id=9, sim_time_s=1.0)
    drift = tuple(value - base - bias for value, base, bias in zip(
        first.feature_vector, baseline, source.receiver_bias(1),
    ))
    assert drift == pytest.approx((0.03, 0.005, 0.015, 0.0004, 0.0004, 0.0005, 0.01, 0.02))
    assert tuple(value - base - bias for value, base, bias in zip(
        other.feature_vector, baseline, source.receiver_bias(9),
    )) == pytest.approx(drift)
    later = observe(source, sim_time_s=3.0)
    expected_scale = 0.98 ** 2 + math.sqrt(1 + 0.98 ** 2)
    assert tuple(value - base - bias for value, base, bias in zip(
        later.feature_vector, baseline, source.receiver_bias(1),
    )) == pytest.approx(tuple(value * expected_scale for value in drift))


def test_channel_residual_is_separate_zero_mean_noise(monkeypatch):
    rng = RNGRegistry(42)
    profiles = DeviceRffProfileRegistry(rng)
    source = RffObservationGenerator(profiles, rng)
    monkeypatch.setattr(rng.python("rff-online:2:1"), "gauss", lambda mean, sigma: 0.0)
    center = profiles.ensure(2).baseline[0] + source.receiver_bias(1)[0]
    residuals = [observe(source, sim_time_s=0.0).feature_vector[0] - center for _ in range(1000)]
    assert statistics.pstdev(residuals) > 0.01
    assert abs(statistics.fmean(residuals)) < statistics.pstdev(residuals) * 0.1


@pytest.mark.parametrize("changes,reason", [
    ({"sinr_db": None}, "PHY_QUALITY_UNAVAILABLE"),
    ({"measurement_quality": None}, "PHY_QUALITY_UNAVAILABLE"),
    ({"sinr_db": math.nan}, "INVALID_PHY_QUALITY"),
    ({"sinr_db": math.inf}, "INVALID_PHY_QUALITY"),
    ({"sinr_db": "20"}, "INVALID_PHY_QUALITY"),
    ({"measurement_quality": -math.inf}, "INVALID_PHY_QUALITY"),
    ({"measurement_quality": True}, "INVALID_PHY_QUALITY"),
    ({"sim_time_s": math.nan}, "INVALID_SIM_TIME"),
    ({"sim_time_s": -1}, "INVALID_SIM_TIME"),
])
def test_missing_or_nonfinite_phy_input_is_explicitly_unavailable(changes, reason):
    result = observe(generator()[1], **changes)
    assert result.extraction_status == "UNAVAILABLE"
    assert result.feature_vector == ()
    assert result.quality == 0.0
    assert result.missing_reason == reason
    json.dumps(result.to_online_dict(), allow_nan=False)


@pytest.mark.parametrize("changes,quality", [
    ({"sinr_db": -10}, 0.0),
    ({"measurement_quality": -1}, 0.0),
    ({"sinr_db": 100, "measurement_quality": 10}, 1.0),
    ({"measurement_quality": 0.45}, 0.45),
])
def test_quality_is_clamped_and_floor_is_inclusive(changes, quality):
    result = observe(generator()[1], **changes)
    assert result.quality == quality
    assert result.extraction_status == ("AVAILABLE" if quality >= 0.45 else "LOW_QUALITY")


def test_time_regression_is_unavailable_without_advancing_streams():
    _, first = generator()
    _, second = generator()
    observe(first)
    observe(second)
    invalid = observe(first, sim_time_s=0.5)
    assert invalid.extraction_status == "UNAVAILABLE"
    assert invalid.missing_reason == "NON_MONOTONIC_SIM_TIME"
    assert observe(first, sim_time_s=2.0) == observe(second, sim_time_s=2.0)


def test_online_observation_is_immutable_and_excludes_private_truth():
    profiles, source = generator()
    result = observe(source)
    payload = result.to_online_dict()
    assert set(payload) == {
        "sample_id", "feature_schema", "feature_vector", "quality",
        "extraction_status", "missing_reason",
    }
    assert payload["feature_schema"] == RFF_FEATURE_SCHEMA
    assert payload["feature_vector"] != list(profiles.ensure(2).baseline)
    payload["feature_vector"][0] = 999
    assert result.feature_vector[0] != 999
    with pytest.raises(FrozenInstanceError):
        result.quality = 0


def enrolled_service(seed=42, receiver_id=1, legal_ids=(2, 3), **settings):
    service = RffService(RNGRegistry(seed), **settings)
    for device_id in legal_ids:
        service.register_device(device_id)
        service.enroll(receiver_id=receiver_id, device_id=device_id)
    return service


def test_templates_are_receiver_specific_and_exclude_external_devices():
    service = RffService(RNGRegistry(42), enrollment_samples=20)
    service.register_device(2)
    service.register_device(-1)
    service.enroll(receiver_id=1, device_id=2)
    assert service.template_store.is_whitelisted(1, 2)
    assert not service.template_store.is_whitelisted(1, -1)
    assert not service.template_store.is_whitelisted(0, 2)


def test_identification_compares_prediction_with_claimed_hop_sender():
    service = enrolled_service()
    observation = observe(service)
    matched = service.identify(1, 2, observation)
    mismatched = service.identify(1, 3, observation)
    assert matched.identity_result == "MATCH"
    assert matched.predicted_device_id == 2
    assert mismatched.identity_result == "MISMATCH"
    assert mismatched.predicted_device_id == 2
    assert matched.distance == mismatched.distance
    assert matched.confidence == mismatched.confidence


def test_enrollment_is_reproducible_receiver_biased_and_floored():
    first = enrolled_service()
    second = enrolled_service(legal_ids=(3, 2))
    first.enroll(receiver_id=0, device_id=2)
    templates = first.template_store.templates_for_receiver(1)
    assert templates == second.template_store.templates_for_receiver(1)
    template = templates[0]
    assert template.device_id == 2
    assert template.sample_count == 20
    assert template.feature_schema == "RFF_FEATURE_V1"
    floors = (0.10, 0.015, 0.04, 0.001, 0.001, 0.0015, 0.025, 0.05)
    assert all(std >= floor for std, floor in zip(template.feature_std, floors))
    other = first.template_store.templates_for_receiver(0)[0]
    assert template.feature_mean != other.feature_mean
    with pytest.raises(FrozenInstanceError):
        template.sample_count = 0


def test_enrollment_does_not_consume_online_drift_channel_or_noise_streams():
    first = RffService(RNGRegistry(42))
    second = RffService(RNGRegistry(42))
    assert observe(first) == observe(second)
    first.register_device(2)
    first.enroll(receiver_id=1, device_id=2)
    first.enroll(receiver_id=0, device_id=2)
    assert observe(first, sim_time_s=2.0) == observe(second, sim_time_s=2.0)


def test_enrollment_and_good_quality_receptions_have_comparable_noise_variance():
    service = RffService(RNGRegistry(42), enrollment_samples=1000)
    service.register_device(2)
    template = service.enroll(receiver_id=1, device_id=2)
    samples = [observe(service, sim_time_s=0.0).feature_vector for _ in range(2000)]
    for index, registered_std in enumerate(template.feature_std):
        online_std = statistics.pstdev(sample[index] for sample in samples)
        assert 0.85 < online_std / registered_std < 1.15


def test_rff_work_does_not_advance_existing_rng_streams():
    rng = RNGRegistry(42)
    expected = RNGRegistry(42)
    rng.python("phy").random()
    expected.python("phy").random()
    service = RffService(rng)
    service.register_device(2)
    service.enroll(receiver_id=1, device_id=2)
    service.identify(1, 2, observe(service))
    assert rng.python("phy").getstate() == expected.python("phy").getstate()


def test_external_transmitter_is_unknown_and_never_auto_enrolled():
    service = enrolled_service(legal_ids=(2,))
    service.register_device(-1)
    result = service.identify(1, 2, observe(service, actual_device_id=-1))
    assert result.identity_result == "UNKNOWN"
    assert result.predicted_device_id is None
    assert not service.template_store.is_whitelisted(1, -1)
    with pytest.raises(ValueError, match="external"):
        service.enroll(receiver_id=1, device_id=-1)


def test_observing_a_new_device_is_not_authorized_registration():
    service = enrolled_service(legal_ids=(2,))
    observe(service, actual_device_id=99)
    assert not service.template_store.is_whitelisted(1, 99)
    with pytest.raises(ValueError, match="registered"):
        service.enroll(receiver_id=1, device_id=99)
    service.register_device(99)
    service.enroll(receiver_id=1, device_id=99)
    assert service.template_store.is_whitelisted(1, 99)


def controlled_service(*, second_mean=None, **settings):
    service = RffService(RNGRegistry(42), **settings)
    first = RffTemplate(1, 2, "RFF_FEATURE_V1", (0.0,) * 8, (1.0,) * 8, 20)
    # Hand-built templates isolate distance/margin decisions from random enrollment.
    service.template_store._templates[(1, 2)] = first
    if second_mean is not None:
        second = replace(first, device_id=3, feature_mean=(second_mean,) * 8)
        service.template_store._templates[(1, 3)] = second
    return service


def controlled_observation(value=0.0, quality=0.9, **changes):
    observation = RffObservation(
        "controlled-sample", "RFF_FEATURE_V1", (value,) * 8, quality, "AVAILABLE", None,
    )
    return replace(observation, **changes)


@pytest.mark.parametrize("value,status,predicted", [
    (0.0, "MATCH", 2), (1.0, "MATCH", 2), (3.0, "MATCH", 2),
    (3.0001, "UNKNOWN", None),
])
def test_rms_distance_and_inclusive_distance_threshold(value, status, predicted):
    result = controlled_service().identify(1, 2, controlled_observation(value))
    assert result.identity_result == status
    assert result.predicted_device_id == predicted
    assert result.distance == pytest.approx(value)
    assert result.threshold == 3.0


def test_distance_uses_all_dimensions_and_population_standard_deviations():
    service = controlled_service()
    observation = controlled_observation(feature_vector=(2.0,) + (0.0,) * 7)
    result = service.identify(1, 2, observation)
    assert result.distance == pytest.approx(math.sqrt(0.5))


def test_template_standard_deviation_floor_is_applied_during_identification():
    service = controlled_service()
    template = service.template_store._templates[(1, 2)]
    service.template_store._templates[(1, 2)] = replace(template, feature_std=(1e-9,) * 8)
    floors = (0.10, 0.015, 0.04, 0.001, 0.001, 0.0015, 0.025, 0.05)
    result = service.identify(1, 2, controlled_observation(feature_vector=floors))
    assert result.distance == pytest.approx(1.0)


@pytest.mark.parametrize("separation,status", [
    (0.0, "AMBIGUOUS"), (0.4999, "AMBIGUOUS"), (0.5, "MATCH"),
])
def test_identity_margin_boundary_and_ties(separation, status):
    result = controlled_service(second_mean=separation).identify(1, 2, controlled_observation())
    assert result.identity_result == status
    assert result.predicted_device_id == (2 if status == "MATCH" else None)


def test_unknown_takes_precedence_when_nearest_candidates_are_both_far():
    result = controlled_service(second_mean=0.1).identify(1, 2, controlled_observation(100))
    assert result.identity_result == "UNKNOWN"
    assert result.predicted_device_id is None


def test_tie_break_is_device_id_not_template_insertion_order_when_margin_is_zero():
    service = controlled_service(second_mean=0.0, min_identity_margin=0.0)
    service.template_store._templates = dict(reversed(list(service.template_store._templates.items())))
    result = service.identify(1, 2, controlled_observation())
    assert result.identity_result == "MATCH"
    assert result.predicted_device_id == 2


def test_confidence_combines_quality_distance_and_candidate_margin():
    service = controlled_service(second_mean=4.0)
    high = service.identify(1, 2, controlled_observation(0.5, quality=0.9))
    lower_quality = service.identify(1, 2, controlled_observation(0.5, quality=0.5))
    farther = service.identify(1, 2, controlled_observation(1.0, quality=0.9))
    narrower = controlled_service(second_mean=1.6).identify(
        1, 2, controlled_observation(0.5, quality=0.9),
    )
    assert high.confidence > lower_quality.confidence
    assert high.confidence > farther.confidence
    assert high.confidence > narrower.confidence
    assert all(0 <= result.confidence <= result.quality for result in (
        high, lower_quality, farther, narrower,
    ))


def test_single_candidate_has_no_artificial_ambiguity_penalty():
    result = controlled_service().identify(1, 2, controlled_observation(1.0, quality=0.9))
    assert result.confidence == pytest.approx(0.6)


def test_missing_claim_is_not_a_match_even_with_perfect_template_evidence():
    result = controlled_service().identify(1, None, controlled_observation())
    assert result.identity_result == "UNKNOWN"
    assert result.predicted_device_id == 2
    assert result.claimed_link_sender_id is None
    assert result.reason == "CLAIMED_LINK_SENDER_UNAVAILABLE"


@pytest.mark.parametrize("claim", [True, 2.0, "2", [], math.nan])
def test_malformed_claim_is_unavailable_not_a_match(claim):
    result = controlled_service().identify(1, claim, controlled_observation())
    assert result.identity_result == "UNAVAILABLE"
    assert result.claimed_link_sender_id is None
    assert result.reason == "INVALID_CLAIMED_LINK_SENDER_ID"


def test_no_receiver_local_templates_is_unknown():
    result = controlled_service().identify(0, 2, controlled_observation())
    assert result.identity_result == "UNKNOWN"
    assert result.predicted_device_id is None
    assert result.distance is None
    assert result.reason == "NO_ENROLLED_TEMPLATES"


@pytest.mark.parametrize("observation,status", [
    (controlled_observation(quality=0.449), "LOW_QUALITY"),
    (controlled_observation(extraction_status="LOW_QUALITY"), "LOW_QUALITY"),
    (controlled_observation(feature_vector=(), quality=0.0, extraction_status="UNAVAILABLE",
                            missing_reason="PHY_QUALITY_UNAVAILABLE"), "UNAVAILABLE"),
    (None, "UNAVAILABLE"),
])
def test_quality_and_unavailable_results_bypass_template_distance(observation, status):
    service = controlled_service()
    service.template_store._templates[(1, 2)] = None
    result = service.identify(1, 2, observation)
    assert result.identity_result == status
    assert result.distance is None
    assert result.predicted_device_id is None
    assert result.confidence is None


@pytest.mark.parametrize("changes,reason", [
    ({"feature_schema": "RFF_FEATURE_V2"}, "UNSUPPORTED_FEATURE_SCHEMA"),
    ({"feature_vector": ()}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": (0.0,) * 7}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": (0.0,) * 9}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": (math.nan,) * 8}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": (math.inf,) * 8}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": ("0",) * 8}, "INVALID_FEATURE_VECTOR"),
    ({"feature_vector": (False,) * 8}, "INVALID_FEATURE_VECTOR"),
    ({"quality": math.nan}, "INVALID_OBSERVATION_QUALITY"),
    ({"quality": math.inf}, "INVALID_OBSERVATION_QUALITY"),
    ({"quality": -0.1}, "INVALID_OBSERVATION_QUALITY"),
    ({"quality": 1.1}, "INVALID_OBSERVATION_QUALITY"),
    ({"quality": True}, "INVALID_OBSERVATION_QUALITY"),
    ({"extraction_status": "BROKEN"}, "INVALID_EXTRACTION_STATUS"),
    ({"sample_id": None}, "INVALID_SAMPLE_ID"),
])
def test_malformed_observations_return_safe_explicit_results(changes, reason):
    result = controlled_service().identify(1, 2, controlled_observation(**changes))
    assert result.identity_result == "UNAVAILABLE"
    assert result.reason == reason
    assert result.predicted_device_id is None
    json.dumps(result.to_security_state(), allow_nan=False)


@pytest.mark.parametrize("observation", [{}, "observation", object()])
def test_wrong_observation_type_is_unavailable(observation):
    result = controlled_service().identify(1, 2, observation)
    assert result.identity_result == "UNAVAILABLE"
    assert result.reason == "INVALID_OBSERVATION"


@pytest.mark.parametrize("changes", [
    {"feature_schema": "RFF_FEATURE_V2"}, {"feature_mean": ()},
    {"feature_mean": (math.nan,) * 8}, {"feature_std": (math.inf,) * 8},
    {"feature_std": (0.0,) * 8}, {"feature_std": (-1.0,) * 8},
    {"feature_std": (1.0,) * 7}, {"sample_count": 0},
    {"sample_count": True}, {"device_id": -1}, {"device_id": 3}, {"receiver_id": 0},
])
def test_invalid_local_templates_cannot_produce_identity_assertions(changes):
    service = controlled_service()
    template = service.template_store._templates[(1, 2)]
    service.template_store._templates[(1, 2)] = replace(template, **changes)
    result = service.identify(1, 2, controlled_observation())
    assert result.identity_result == "UNAVAILABLE"
    assert result.reason == "INVALID_TEMPLATE"
    assert result.predicted_device_id is None
    json.dumps(result.to_security_state(), allow_nan=False)


def test_identification_never_reads_actual_device_profiles_or_sampler(monkeypatch):
    service = enrolled_service()
    observation = replace(observe(service), sample_id="not-an-identity-3")

    def forbidden(*args, **kwargs):
        raise AssertionError("identifier must use observations and receiver templates only")

    monkeypatch.setattr(service._registry, "ensure", forbidden)
    monkeypatch.setattr(service._observation_generator, "observe", forbidden)
    monkeypatch.setattr(service._observation_generator, "receiver_bias", forbidden)
    assert service.identify(1, 2, observation).identity_result == "MATCH"


def test_result_is_frozen_and_security_mapping_preserves_existing_confidence_name():
    result = controlled_service().identify(1, 2, controlled_observation())
    state = result.to_security_state()
    assert state == {
        "rff_identity_result": "MATCH", "rff_predicted_device_id": 2,
        "rff_claimed_link_sender_id": 2, "rff_distance": 0.0,
        "rff_threshold": 3.0, "rff_identity_confidence": 0.9,
        "rff_quality": 0.9, "rff_reason": "NEAREST_TEMPLATE_ACCEPTED",
    }
    with pytest.raises(FrozenInstanceError):
        result.identity_result = "MISMATCH"
    json.dumps(state, allow_nan=False)


@pytest.mark.parametrize("setting,value", [
    ("enrollment_samples", 0), ("enrollment_samples", -1),
    ("enrollment_samples", 1.5), ("enrollment_samples", True),
    ("quality_threshold", -0.1), ("quality_threshold", 1.1),
    ("quality_threshold", math.nan), ("quality_threshold", True),
    ("distance_threshold", 0), ("distance_threshold", -1),
    ("distance_threshold", math.inf), ("distance_threshold", math.nan),
    ("distance_threshold", True), ("min_identity_margin", -1),
    ("min_identity_margin", math.inf), ("min_identity_margin", math.nan),
    ("min_identity_margin", False),
])
def test_service_rejects_invalid_configuration(setting, value):
    with pytest.raises(ValueError):
        RffService(RNGRegistry(42), **{setting: value})
