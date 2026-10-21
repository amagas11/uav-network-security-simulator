from __future__ import annotations

import json
from copy import deepcopy

import pytest

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.events import assert_online_truth_free, build_event
from swarm_sim.validation import DatasetValidator
from tests.acceptance.test_v19_onpath import configuration
from tests.acceptance.test_v20_fdi_copies import copied_configuration


def _copied_spoof_runtime(*, enabled=True):
    return PlatformRuntime(RunConfig(
        duration_s=3.2, step_s=0.2, auto_traffic=False,
        queue_capacity=128, tx_service_per_step=64, rx_service_per_step=64,
        rff_enabled=enabled,
        traffic_specs=[dict(
            source_node_id=2, target_node_id=1, packet_type="STATUS",
            payload=dict(status_code=1, value=42), start_s=0.2,
            interval_s=0.4, count=6, session_id="source", sequence_start=100,
        )],
        attack_specs=[dict(
            attack_family="SPOOFING", attack_subtype="KNOWN_ID_CONFLICT",
            scheduled_start_s=0, impact_start_s=0.4, end_s=2.4,
            attacker_node_id=-1, target_node_ids=[1], parameters=dict(
                claimed_src_id=0, source_copy_mode="LEGITIMATE_FRAME_COPY",
                legitimate_source_id=2,
            ),
        )],
    ), run_id="rff-attack")


def _fdi_runtime(*, enabled=True, on_path=False):
    config = configuration() if on_path else copied_configuration()
    config.rff_enabled = enabled
    return PlatformRuntime(config, run_id="rff-attack")


def _on_path_fdi_runtime(*, enabled=True):
    return _fdi_runtime(enabled=enabled, on_path=True)


def _replay_runtime(*, enabled=True):
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.6, auto_traffic=False, rff_enabled=enabled), run_id="rff-attack",
    )
    runtime.schedule_attack(AttackPlan(
        attack_family="REPLAY", attack_subtype="CAPTURE_AND_REPLAY",
        scheduled_start_s=0, impact_start_s=0.6, end_s=1.2,
        attacker_node_id=-1, target_node_ids=[1],
    ))
    runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95})
    return runtime


def _flooding_runtime(*, enabled=True):
    return PlatformRuntime(RunConfig(
        duration_s=1.6, auto_traffic=False, queue_capacity=32,
        tx_service_per_step=20, rx_service_per_step=20, rff_enabled=enabled,
        attack_specs=[dict(
            attack_family="DOS", attack_subtype="FLOODING",
            scheduled_start_s=0, impact_start_s=0.2, end_s=1.2,
            attacker_node_id=-1, target_node_ids=[1],
            intensity=dict(value=100.0, unit="pps"),
        )],
    ), run_id="rff-attack")


def _external_receiver_events(runtime):
    transmissions = runtime.packet_accounting.causal["transmissions"]
    keys = {
        (item["message_id"], item["receiver_id"], item["sent_time_s"])
        for item in transmissions if item["actual_sender_id"] == -1
    }
    return [event for event in runtime.events
            if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
            and (event["message_id"], event["observer_node_id"], event["sim_time_s"]) in keys]


FACTORIES = [_copied_spoof_runtime, _fdi_runtime, _on_path_fdi_runtime,
             _replay_runtime, _flooding_runtime]


@pytest.mark.parametrize("factory", FACTORIES)
def test_external_attack_transmissions_have_unrecognized_physical_source(factory):
    runtime = factory()
    runtime.run_to_completion()
    events = _external_receiver_events(runtime)
    assert events
    high_quality = [event for event in events if
                    event["online_features"]["phy"]["rff_observation"]["extraction_status"] == "AVAILABLE"]
    assert high_quality
    assert all(event["online_features"]["security_state"]["rff_identity_result"]
               in {"UNKNOWN", "MISMATCH"} for event in high_quality)
    if factory is not _flooding_runtime:
        assert all(event["online_features"]["packet"]["claimed_link_sender_id"] == 2
                   for event in events)
    else:
        assert all(event["online_features"]["packet"]["claimed_link_sender_id"] == -1
                   for event in events)
    assert not runtime.rff_service.template_store.is_whitelisted(1, -1)


@pytest.mark.parametrize("factory", FACTORIES)
def test_observation_only_has_identical_existing_traffic_and_defense_behavior(factory):
    observed = factory(enabled=True)
    disabled = factory(enabled=False)
    observed.run_to_completion()
    disabled.run_to_completion()
    assert observed.metrics() == disabled.metrics()
    for node_id, node in observed.nodes.items():
        other = disabled.nodes[node_id]
        assert node.drop_count == other.drop_count
        assert node.delivered_messages == other.delivered_messages
        assert node.position_xyz_m == other.position_xyz_m
        assert node.telemetry_by_source == other.telemetry_by_source
        assert node.rate_limited_peer_ids == other.rate_limited_peer_ids
        assert node.isolated_peer_ids == other.isolated_peer_ids
    assert observed.packet_accounting.causal["actions"] == disabled.packet_accounting.causal["actions"]


def test_legal_radio_with_malicious_payload_still_has_matching_identity():
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, auto_traffic=False))
    runtime.schedule_attack(AttackPlan(
        attack_family="FDI", attack_subtype="OUT_OF_RANGE_VALUE",
        scheduled_start_s=0, impact_start_s=0, end_s=0.8,
        attacker_node_id=2, target_node_ids=[1],
        parameters=dict(field="altitude_m", value=5000),
    ))
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["truth"]["original_value"] != runtime.attack_scheduler.labels()[0]["truth"]["modified_value"]
    events = [event for event in runtime.events if event["event_type"] == "RX_SUCCESS"
              and event["message_id"] == message_id]
    assert events
    assert all(event["online_features"]["security_state"]["rff_identity_result"] == "MATCH"
               for event in events)


def test_passive_listener_does_not_emit_radio_identity_alarm():
    runtime = PlatformRuntime(RunConfig(duration_s=1.2, auto_traffic=False))
    runtime.schedule_attack(AttackPlan(
        attack_family="EAVESDROPPING", attack_subtype="PASSIVE_CAPTURE",
        scheduled_start_s=0, impact_start_s=0, end_s=1.0,
        attacker_node_id=-1, parameters=dict(receiver_radius_m=1000),
    ))
    runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95})
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["outcome"]["captured_count"] > 0
    assert not _external_receiver_events(runtime)
    assert not any(event["online_features"]["security_state"]["rff_identity_result"]
                   in {"UNKNOWN", "MISMATCH"} for event in runtime.events)


@pytest.mark.parametrize("field", ["actual_transmitter_id", "true_device_id",
    "rff_ground_truth_id", "noiseless_rff_vector", "device_rff_baseline", "noiseless_baseline"])
def test_recursive_truth_guard_rejects_private_radio_fields(field):
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    event = deepcopy(runtime.events[0])
    event["online_features"]["phy"]["rff_observation"] = {"nested": [{field: -1}]}
    with pytest.raises(ValueError, match="forbidden simulator truth"):
        assert_online_truth_free(event)


def test_attack_exports_contain_no_rff_truth_in_online_events(tmp_path):
    runtime = _copied_spoof_runtime()
    runtime.run_to_completion()
    online = json.dumps([event["online_features"] for event in runtime.events])
    for field in ("actual_transmitter_id", "attacker_node_id", "attack_family",
                  "noiseless_baseline", "device_rff_baseline"):
        assert field not in online
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors


def test_event_builder_keeps_only_observable_rff_fields():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    raw = dict(sample_id="sample", feature_schema="RFF_FEATURE_V1",
               feature_vector=[0.0] * 8, quality=0.9, extraction_status="AVAILABLE",
               missing_reason=None, actual_transmitter_id=2, device_rff_baseline=[0.0] * 8)
    event = build_event(runtime.context, "PHY_SAMPLE", runtime.nodes[1],
                        phy={"rff_observation": raw})
    observation = event["online_features"]["phy"]["rff_observation"]
    assert "actual_transmitter_id" not in observation
    raw["feature_vector"][0] = 999
    assert observation["feature_vector"][0] == 0.0
