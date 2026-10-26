from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.validation import DatasetValidator
from swarm_sim.security import DefenseResult
from tests.acceptance.test_rff_observe_only import (
    _copied_spoof_runtime, _fdi_runtime, _on_path_fdi_runtime,
    _external_receiver_events, _flooding_runtime,
)


def _enforcing(factory, *, opaque=False, duration=None):
    source = factory()
    config = deepcopy(source.config)
    source.close()
    config.rff_policy_mode = "ENFORCE"
    config.application_layer_available = not opaque
    if duration is not None:
        config.duration_s = duration
    return PlatformRuntime(config, run_id="rff-enforce")


@pytest.mark.parametrize("factory", [_copied_spoof_runtime, _fdi_runtime,
                                    _on_path_fdi_runtime, _flooding_runtime])
def test_external_retransmissions_drop_at_physical_ingress_before_authentication(factory):
    runtime = _enforcing(factory)
    runtime.run_to_completion()
    received = _external_receiver_events(runtime)
    qualified = [event for event in received if event["event_type"] == "RX_SUCCESS"
                 and event["online_features"]["phy"]["rff_observation"]["extraction_status"] == "AVAILABLE"]
    assert qualified
    for event in qualified:
        decision = event["extensions"]["rff_decision"]
        assert decision["drop"] is True
        assert decision["confirmed_identity_anomaly"] is True
        assert decision["reason"] == "RFF_IDENTITY_MISMATCH"
        assert event["extensions"]["air_emission_ref"]
        assert not any(other["event_type"] == "AUTH_RESULT"
                       and other["message_id"] == event["message_id"]
                       and other["observer_node_id"] == event["observer_node_id"]
                       and other["sim_time_s"] >= event["sim_time_s"]
                       for other in runtime.events)
    assert runtime.nodes[1].drop_count >= len(qualified)
    defenses = [event for event in runtime.events if event["event_type"] == "DEFENSE_RESULT"
                and event["extensions"].get("rff_decision", {}).get("drop")]
    assert len(defenses) >= len(qualified)


def test_external_replay_is_blocked_without_sequence_or_hmac_detection():
    runtime = PlatformRuntime(RunConfig(duration_s=2.0, auto_traffic=False,
        rff_policy_mode="ENFORCE", application_layer_available=False))
    runtime.schedule_attack(AttackPlan(
        "REPLAY", "CAPTURE_AND_REPLAY", 0, 0.6, 1.4,
        attacker_node_id=-1, target_node_ids=[1],
    ))
    runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95})
    runtime.run_to_completion()
    replay_events = _external_receiver_events(runtime)
    assert replay_events
    assert any(event["extensions"]["rff_decision"]["drop"] for event in replay_events)
    assert not any(event["event_type"] == "AUTH_RESULT"
                   and event["online_features"]["packet"]["packet_type"] == "TELEMETRY"
                   for event in runtime.events)


def test_physical_only_normal_multihop_does_not_read_or_execute_business_payload():
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False,
        rff_policy_mode="ENFORCE", application_layer_available=False))
    opened = runtime.crypto.open

    def management_only(frame, receiver_id):
        assert frame.packet_type in {"SECURITY_REPORT", "SECURITY_SUMMARY", "SKG_CONTROL"}
        return opened(frame, receiver_id)

    runtime.crypto.open = management_only
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    events = [event for event in runtime.events if event["event_type"] == "RX_SUCCESS"
              and event["message_id"] == message_id]
    assert {event["observer_node_id"] for event in events} == {0, 1}
    assert [event["online_features"]["packet"]["claimed_link_sender_id"] for event in events] == [2, 1]
    assert all(event["online_features"]["security_state"]["rff_identity_result"] == "MATCH" for event in events)
    for event in events:
        packet = event["online_features"]["packet"]
        for name in ("claimed_src_id", "sequence_no", "session_id", "key_epoch", "payload_numeric", "command_type"):
            assert packet[name] is None
    assert runtime.nodes[0].opaque_delivered_count == 1
    assert not runtime.nodes[0].delivered_messages
    assert not runtime.nodes[0].telemetry_by_source


def test_reports_use_real_leader_gcs_transport_and_include_physical_evidence():
    runtime = _enforcing(_copied_spoof_runtime, duration=4.5)
    runtime.run_to_completion()
    reports = [report for report in runtime.reporting.gcs_inbox
               if report["category"].startswith("RFF_")]
    assert reports
    report = next(report for report in reports if report["category"] == "RFF_IDENTITY_MISMATCH")
    assert report["evidence"]["rff_identity_result"] in {"UNKNOWN", "MISMATCH"}
    assert report["source_event_ids"]
    assert report["report_received_time_s"] >= report["first_detection_time_s"]
    assert any(event["event_type"] == "TX" and event["online_features"]["packet"]["packet_type"] == "SECURITY_SUMMARY"
               for event in runtime.events)
    assert "actual_transmitter_id" not in json.dumps(report)


def test_enforcement_exports_a_schema_valid_dataset(tmp_path):
    runtime = _enforcing(_copied_spoof_runtime, opaque=True, duration=4.5)
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
    physical = runtime.evaluation_view()["physical_layer"]
    assert physical["by_family"]["SPOOFING"]["detection_rate"] == 1.0
    assert physical["by_family"]["SPOOFING"]["block_rate"] == 1.0


def test_strict_mode_exits_after_quiet_hold_and_reset_clears_it():
    runtime = _enforcing(_flooding_runtime, duration=4.5)
    runtime.run_to_completion()
    decisions = [event["extensions"]["rff_decision"] for event in _external_receiver_events(runtime)]
    assert any(item["policy_state"] == "RFF_STRICT_WHITELIST" for item in decisions)
    assert runtime.nodes[1].rff_policy_state == "NORMAL"
    exits = [event for event in runtime.events if event["observer_node_id"] == 1
             and event["extensions"].get("rff_policy_transition", {}).get("rff_policy_state") == "NORMAL"]
    assert exits
    runtime.reset()
    assert runtime.nodes[1].rff_policy_state == "NORMAL"
    assert runtime.nodes[1].drop_count == 0
    assert not runtime.reporting.gcs_inbox


def test_queue_pressure_activates_whitelist_without_rejecting_matching_legal_radios():
    runtime = PlatformRuntime(RunConfig(
        duration_s=1.6, auto_traffic=False, rff_policy_mode="ENFORCE",
        queue_capacity=2, tx_service_per_step=4, rx_service_per_step=1,
        flooding_packet_rate_threshold_pps=500, rff_queue_pressure_ratio=0.5,
        rff_strict_hold_s=0.4,
    ))
    ids = [runtime.queue_message(source, 1, "TELEMETRY", {"altitude_m": 100}) for source in (2, 3)]
    runtime.run_to_completion()
    received = [event for event in runtime.events if event["event_type"] == "RX_SUCCESS"
                and event["message_id"] in ids]
    assert len(received) == 2
    assert any(event["extensions"]["rff_decision"]["policy_state"] == "RFF_STRICT_WHITELIST" for event in received)
    assert all(not event["extensions"]["rff_decision"]["drop"] for event in received)
    assert set(ids) <= {message.message_id for message in runtime.nodes[1].delivered_messages}


def test_low_quality_strict_rejection_is_protective_not_confirmed_identity_attack():
    runtime = PlatformRuntime(RunConfig(
        duration_s=1.0, auto_traffic=False, rff_policy_mode="ENFORCE",
        flooding_packet_rate_threshold_pps=2,
    ))
    sample = runtime.phy.sample

    def low_quality(*args, **kwargs):
        outcome = sample(*args, **kwargs)
        outcome.observation["measurement_quality"] = 0.1
        outcome.decode_success = True
        return outcome

    runtime.phy.sample = low_quality
    ids = [runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100}) for _ in range(2)]
    runtime.run_to_completion()
    received = [event for event in runtime.events if event["event_type"] == "RX_SUCCESS"
                and event["message_id"] in ids]
    assert not received[0]["extensions"]["rff_decision"]["drop"]
    assert received[1]["extensions"]["rff_decision"]["drop"]
    assert all(not event["extensions"]["rff_decision"]["confirmed_identity_anomaly"] for event in received)
    assert runtime.evaluation_view()["physical_layer"]["protective_unverified_drops"] > 0


def test_follower_reports_wait_for_disconnected_gcs_link_then_reach_center():
    source = _flooding_runtime()
    config = deepcopy(source.config)
    source.close()
    config.duration_s = 5.0
    config.rff_policy_mode = "ENFORCE"
    config.attack_specs[0]["target_node_ids"] = [2]
    config.attack_specs[0]["intensity"]["value"] = 20.0
    runtime = PlatformRuntime(config)
    runtime.set_bidirectional_link_active(0, 1, False)
    runtime.start()
    while runtime.context.clock.now_s < 1.6:
        runtime.step()
    assert runtime.nodes[2].local_security_cache
    assert not runtime.reporting.gcs_inbox
    runtime.set_bidirectional_link_active(0, 1, True)
    runtime.run_to_completion()
    reports = [report for report in runtime.reporting.gcs_inbox
               if report["category"].startswith("RFF_") and report["source_node_id"] == 2]
    assert reports
    assert all(report["report_received_time_s"] >= 1.6 for report in reports)
    assert any(event["event_type"] == "TX" and event["observer_node_id"] == 2
               and event["online_features"]["packet"]["packet_type"] == "SECURITY_REPORT"
               for event in runtime.events)


def test_failed_decode_does_not_claim_an_executed_physical_drop():
    runtime = _enforcing(_copied_spoof_runtime, opaque=True)
    sample = runtime.phy.sample

    def fail_external(*args, **kwargs):
        outcome = sample(*args, **kwargs)
        if args[1].node_id == -1:
            outcome.decode_success = False
        return outcome

    runtime.phy.sample = fail_external
    runtime.run_to_completion()
    events = _external_receiver_events(runtime)
    assert events and all(event["event_type"] == "RX_FAILURE" for event in events)
    assert all(not event["extensions"]["rff_decision"]["drop"] for event in events)
    assert not any(event["event_type"] == "DEFENSE_RESULT"
                   and event["extensions"].get("rff_decision", {}).get("drop")
                   for event in runtime.events)
    assert runtime.evaluation_view()["physical_layer"]["by_family"]["SPOOFING"]["defense_opportunities"] == 0


def test_legal_compromised_radio_is_not_claimed_as_physical_detection():
    runtime = PlatformRuntime(RunConfig(duration_s=1, auto_traffic=False,
        rff_policy_mode="ENFORCE", application_layer_available=False))
    runtime.schedule_attack(AttackPlan("FDI", "OUT_OF_RANGE_VALUE", 0, 0, 0.8,
        attacker_node_id=2, target_node_ids=[1], parameters={"field": "altitude_m", "value": 5000}))
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100})
    runtime.run_to_completion()
    events = [event for event in runtime.events if event["event_type"] == "RX_SUCCESS"
              and event["message_id"] == message_id]
    assert events and all(not event["extensions"]["rff_decision"]["drop"] for event in events)
    physical = runtime.evaluation_view()["physical_layer"]
    assert physical["by_family"]["FDI"]["detection_rate"] is None
    assert physical["episodes"][0]["unavailable_reason"] == "NO_EXTERNAL_RETRANSMISSION"


def test_short_strict_hold_reports_both_entry_and_exit():
    runtime = PlatformRuntime(RunConfig(duration_s=1, auto_traffic=False,
        rff_policy_mode="ENFORCE", rff_queue_pressure_ratio=0.5, rff_strict_hold_s=0.1))
    node = runtime.nodes[1]
    node.rx_queue.extend([None] * node.queue_capacity)
    runtime._refresh_rff_receiver(node)
    node.rx_queue.clear()
    runtime.context.clock.advance_by(0.1)
    runtime._refresh_rff_receiver(node)
    runtime.context.clock.advance_by(0.1)
    runtime._refresh_rff_receiver(node)
    transitions = [report["evidence"]["transition"] for report in node.local_security_cache
                   if report["category"] == "RFF_STRICT_WHITELIST"]
    assert transitions == ["ENTER_STRICT", "EXIT_STRICT"]


def test_failed_drop_executor_keeps_receive_audit_consistent():
    runtime = _enforcing(_copied_spoof_runtime, opaque=True)

    def fail_drop(request, node, sim_time_s):
        return DefenseResult(asdict(request), "LOCAL", {}, sim_time_s, None, True, False,
                             "INJECTED_EXECUTOR_FAILURE", {})

    runtime.defense.execute = fail_drop
    runtime.run_to_completion()
    events = _external_receiver_events(runtime)
    assert events and all(not event["extensions"]["rff_decision"]["drop"] for event in events)
    assert runtime.evaluation_view()["physical_layer"]["by_family"]["SPOOFING"]["blocked_samples"] == 0
