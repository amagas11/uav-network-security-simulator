from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.domain import Message
from swarm_sim.events import build_event
from swarm_sim.integrations.person_a.bridge import PersonACryptoProvider
from swarm_sim.validation import DatasetValidator


def test_rff_configuration_roundtrips_and_changes_semantic_fingerprint():
    config = RunConfig(rff_enabled=True, rff_policy_mode="OBSERVE_ONLY")
    disabled = RunConfig(rff_enabled=False)
    assert config.semantic_fingerprint() != disabled.semantic_fingerprint()
    assert RunConfig.from_dict(config.to_dict()).to_dict() == config.to_dict()
    assert config.rff_enrollment_samples == 20
    assert config.rff_quality_threshold == 0.45
    assert config.rff_distance_threshold == 3.0


@pytest.mark.parametrize("name,value", [
    ("rff_enabled", 1), ("rff_strict_on_rate_alarm", "true"),
    ("rff_policy_mode", "DROP_EVERYTHING"), ("rff_policy_mode", None),
    ("rff_enrollment_samples", 0), ("rff_enrollment_samples", True),
    ("rff_enrollment_samples", 2.5), ("rff_quality_threshold", -0.01),
    ("rff_quality_threshold", float("nan")), ("rff_quality_threshold", True),
    ("rff_distance_threshold", 0), ("rff_distance_threshold", float("inf")),
    ("rff_min_identity_margin", -1), ("rff_queue_pressure_ratio", 1.01),
    ("rff_strict_hold_s", 0),
])
def test_invalid_rff_configuration_is_rejected(name, value):
    with pytest.raises(ValueError, match=name):
        RunConfig(**{name: value})


def test_phase_one_runtime_rejects_unimplemented_enforcement():
    with pytest.raises(ValueError, match="RFF_ENFORCEMENT_NOT_IMPLEMENTED"):
        PlatformRuntime(RunConfig(rff_policy_mode="ENFORCE"))


def _message():
    return Message(
        message_id="frame-contract", origin_node_id=2, final_dst_node_id=1,
        claimed_src_id=2, claimed_dst_id=1, packet_type="TELEMETRY",
        payload={"altitude_m": 100}, sequence_no=1, session_id="s",
        key_epoch=1, created_time_s=0.0, route=[2, 1],
    )


@pytest.mark.parametrize("formal_provider", [False, True])
def test_crypto_provider_initializes_claimed_hop_without_adding_rff_to_payload(formal_provider):
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    message = _message()
    if formal_provider:
        frame = PersonACryptoProvider._plaintext_frame(message, 2, 1, "link-2-1", 0)
    else:
        frame = runtime.crypto.protect(message, 2, 1, "link-2-1", 0)
    assert frame.claimed_link_sender_id == 2
    assert frame.clone_for_replay().claimed_link_sender_id == 2
    event = build_event(runtime.context, "TX", runtime.nodes[2], message=frame)
    assert event["online_features"]["packet"]["claimed_link_sender_id"] == 2
    assert "rff" not in json.dumps(frame.protected_payload).lower()


def test_rff_event_fields_are_nullable_before_reception():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    event = runtime.events[0]
    assert event["online_features"]["phy"]["rff_observation"] is None
    security = event["online_features"]["security_state"]
    for name in ("rff_predicted_device_id", "rff_claimed_link_sender_id",
                 "rff_distance", "rff_threshold", "rff_reason"):
        assert security[name] is None


def test_rff_contract_is_additive_for_legacy_datasets(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False))
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    events_path = tmp_path / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    for event in events:
        online = event["online_features"]
        online["packet"].pop("claimed_link_sender_id", None)
        online["phy"].pop("rff_observation", None)
        for name in ("rff_predicted_device_id", "rff_claimed_link_sender_id",
                     "rff_distance", "rff_threshold", "rff_reason"):
            online["security_state"].pop(name, None)
    events_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors


def _rx_events(runtime, message_id=None):
    return [
        event for event in runtime.events
        if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
        and (message_id is None or event["message_id"] == message_id)
    ]


def test_normal_direct_link_observes_receiver_fingerprint_and_matches():
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False), run_id="rff-direct")
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    event = _rx_events(runtime, message_id)[0]
    online = event["online_features"]
    observation = online["phy"]["rff_observation"]
    security = online["security_state"]
    assert observation["feature_schema"] == "RFF_FEATURE_V1"
    assert len(observation["feature_vector"]) == 8
    assert security["rff_identity_result"] == "MATCH"
    assert security["rff_predicted_device_id"] == 2
    assert security["rff_claimed_link_sender_id"] == 2
    assert security["rff_distance"] <= security["rff_threshold"]
    assert security["rff_last_update_s"] == event["sim_time_s"]
    assert online["packet"]["payload_numeric"] is None
    assert runtime.nodes[1].rff_predicted_device_id == 2


def test_multihop_checks_current_relay_not_original_business_source():
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False), run_id="rff-hops")
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    received = _rx_events(runtime, message_id)
    leader = next(event for event in received if event["observer_node_id"] == 1)
    gcs = next(event for event in received if event["observer_node_id"] == 0)
    assert leader["online_features"]["packet"]["claimed_link_sender_id"] == 2
    assert gcs["online_features"]["packet"]["claimed_link_sender_id"] == 1
    assert gcs["online_features"]["packet"]["claimed_src_id"] == 2
    for event, predicted in ((leader, 2), (gcs, 1)):
        security = event["online_features"]["security_state"]
        assert security["rff_identity_result"] == "MATCH"
        assert security["rff_predicted_device_id"] == predicted
    assert runtime.nodes[0].delivered_messages[0].message_id == message_id


def test_templates_enroll_directed_legal_neighbors_only():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    service = runtime.rff_service
    assert service.template_store.is_whitelisted(1, 2)
    assert not service.template_store.is_whitelisted(0, 2)
    runtime._external_node(-1)
    runtime.topology.ensure_external_ingress(-1, [1])
    assert not service.template_store.is_whitelisted(1, -1)


@pytest.mark.parametrize("quality,expected", [(0.1, "LOW_QUALITY"), (None, "UNAVAILABLE")])
def test_failed_decode_records_quality_result_without_claiming_an_identity(quality, expected):
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False))
    sample = runtime.phy.sample

    def fail_decode(*args, **kwargs):
        outcome = sample(*args, **kwargs)
        outcome.decode_success = False
        outcome.observation["measurement_quality"] = quality
        return outcome

    runtime.phy.sample = fail_decode
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    event = _rx_events(runtime, message_id)[0]
    assert event["event_type"] == "RX_FAILURE"
    security = event["online_features"]["security_state"]
    assert security["rff_identity_result"] == expected
    assert security["rff_predicted_device_id"] is None


def test_delayed_authentication_uses_its_own_frame_rff_result():
    runtime = PlatformRuntime(RunConfig(
        duration_s=1.4, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=1,
    ))
    first = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    second = runtime.queue_message(3, 1, "TELEMETRY", {"altitude_m": 101})
    runtime.run_to_completion()
    for message_id, sender in ((first, 2), (second, 3)):
        event = next(event for event in runtime.events
                     if event["event_type"] == "AUTH_RESULT" and event["message_id"] == message_id)
        assert event["online_features"]["security_state"]["rff_predicted_device_id"] == sender


def test_message_scoped_rule_results_keep_received_rff_snapshot():
    runtime = PlatformRuntime(RunConfig(
        duration_s=1.4, auto_traffic=False, tx_service_per_step=8,
        rx_service_per_step=1, replay_timestamp_freshness_s=0.1,
    ))
    first = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    runtime.queue_message(3, 1, "TELEMETRY", {"altitude_m": 101})
    runtime.run_to_completion()
    related = [event for event in runtime.events if event["message_id"] == first
               and event["event_type"] in {"AUTH_RESULT", "MODEL_RESULT", "DEFENSE_RESULT"}]
    assert {event["event_type"] for event in related} == {"AUTH_RESULT", "MODEL_RESULT", "DEFENSE_RESULT"}
    for event in related:
        security = event["online_features"]["security_state"]
        assert security["rff_claimed_link_sender_id"] == 2
        assert security["rff_predicted_device_id"] == 2
        assert security["rff_identity_result"] == "MATCH"
    assert runtime.nodes[1].rff_predicted_device_id == 3


def test_disabled_rff_leaves_observation_and_identity_fields_null():
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, rff_enabled=False))
    runtime.run_to_completion()
    assert _rx_events(runtime)
    for event in runtime.events:
        assert event["online_features"]["phy"]["rff_observation"] is None
        for name, value in event["online_features"]["security_state"].items():
            if name.startswith("rff_"):
                assert value is None


@pytest.mark.parametrize("enabled", [True, False])
def test_rff_provenance_and_observations_export_as_valid_dataset(tmp_path, enabled):
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, rff_enabled=enabled))
    runtime.run_to_completion()
    record = runtime.run_record()["rff_simulation"]
    assert record["enabled"] is enabled
    assert record["provider"] == "SIMULATED_FEATURE_TEMPLATE"
    assert record["calibration_status"] == "UNCALIBRATED_BASELINE"
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors


def test_historical_dataset_without_rff_configuration_keeps_its_fingerprint(tmp_path):
    example = Path(__file__).resolve().parents[2] / "schema_3_2_example_dataset"
    target = tmp_path / "historical"
    shutil.copytree(example, target)
    (target / "rf_samples").mkdir()
    report = DatasetValidator().validate(target)
    assert report.valid, report.errors


@pytest.mark.parametrize("vector", [[0.0] * 7, [float("nan")] * 8, [float("inf")] * 8])
def test_export_validator_rejects_malformed_rff_vectors(tmp_path, vector):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4))
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    events_path = tmp_path / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    event = next(event for event in events if event["event_type"] == "RX_SUCCESS")
    event["online_features"]["phy"]["rff_observation"]["feature_vector"] = vector
    events_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("rff_observation.feature_vector" in error for error in report.errors)


def test_rff_observation_ids_are_run_scoped_while_features_are_reproducible():
    first = PlatformRuntime(RunConfig(seed=81, duration_s=0.8), run_id="first")
    second = PlatformRuntime(RunConfig(seed=81, duration_s=0.8), run_id="second")
    first.run_to_completion()
    second.run_to_completion()
    first_samples = [event["online_features"]["phy"]["rff_observation"]
                     for event in _rx_events(first)]
    second_samples = [event["online_features"]["phy"]["rff_observation"]
                      for event in _rx_events(second)]
    assert first_samples and len(first_samples) == len(second_samples)
    for left, right in zip(first_samples, second_samples):
        assert left["sample_id"] != right["sample_id"]
        assert left["feature_vector"] == right["feature_vector"]
    assert first.reproducible_event_projection() == second.reproducible_event_projection()
