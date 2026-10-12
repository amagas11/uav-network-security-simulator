from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.application_auth import canonical_mac_data
from swarm_sim.domain import Message


def _message() -> Message:
    return Message(
        message_id="app-hmac-message",
        origin_node_id=2,
        final_dst_node_id=0,
        claimed_src_id=2,
        claimed_dst_id=0,
        packet_type="TELEMETRY",
        payload={"altitude_m": 100.0, "flight_state": "FLYING"},
        sequence_no=7,
        session_id="app-session",
        key_epoch=1,
        created_time_s=1.2344,
        route=[2, 1, 0],
        application_direction="UPLINK",
    )


def _plan(family: str, subtype: str, **values) -> AttackPlan:
    data = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.0,
        "end_s": 0.8,
    }
    data.update(values)
    return AttackPlan(**data)


def _auth_events(runtime: PlatformRuntime, message_id: str | None = None):
    return [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and (message_id is None or event["message_id"] == message_id)
        and event["online_features"]["security_state"][
            "application_hmac_result"
        ]
        != "UNAVAILABLE"
    ]


def test_application_hmac_covers_every_frozen_field_and_never_exports_key():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="hmac-fields")
    message = _message()
    runtime.application_auth.sign(message)
    frame = runtime.crypto.protect(message, 2, 1, "link-2-1", 0)
    assert len(message.app_hmac_tag or "") == 32
    assert runtime.application_auth.verify(frame, message.payload).result == "PASS"

    mutations = [
        ("claimed_src_id", 3),
        ("packet_type", "STATUS"),
        ("sequence_no", 8),
        ("created_time_s", 1.2354),
        ("application_direction", "DOWNLINK"),
    ]
    for field, value in mutations:
        changed = frame.clone_for_replay()
        setattr(changed, field, value)
        assert runtime.application_auth.verify(changed, message.payload).result == "FAIL"

    changed_payload = deepcopy(message.payload)
    changed_payload["altitude_m"] = 100.1
    assert runtime.application_auth.verify(frame, changed_payload).result == "FAIL"
    assert canonical_mac_data(message, message.payload) == canonical_mac_data(
        frame, message.payload
    )
    exported = json.dumps(
        {"events": runtime.events, "run": runtime.run_record()}, sort_keys=True
    )
    assert "application-hmac-master" not in exported
    assert "_keys" not in exported


def test_spoofing_changes_only_device_id_and_is_dropped_by_hmac_gate():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, rx_service_per_step=16)
    )
    runtime.schedule_attack(
        _plan(
            "SPOOFING",
            "KNOWN_ID_CONFLICT",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"claimed_src_id": 0},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["modified_fields"] == ["claimed_src_id"]
    original = label["truth"]["original_application_fields"]
    assert original["claimed_src_id"] == -1
    assert label["truth"]["claimed_src_id"] == 0
    assert label["outcome"]["application_hmac_rejected"] is True
    events = _auth_events(runtime)
    assert events
    state = events[0]["online_features"]["security_state"]
    assert state["application_hmac_result"] == "FAIL"
    assert state["application_hmac_failure_reason"] == "HMAC_MISMATCH"
    assert not runtime.nodes[1].delivered_messages
    assert 0 not in runtime.nodes[1].isolated_peer_ids


def test_unknown_spoof_identity_has_no_verification_key():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=16)
    )
    runtime.schedule_attack(
        _plan(
            "SPOOFING",
            "UNKNOWN_ID",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"claimed_src_id": 999},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    runtime.run_to_completion()
    states = [
        event["online_features"]["security_state"]
        for event in _auth_events(runtime)
    ]
    assert any(state["application_hmac_result"] == "UNKNOWN_DEVICE" for state in states)
    assert any(
        state["application_hmac_failure_reason"] == "UNKNOWN_DEVICE_KEY"
        for state in states
    )


def test_flooding_uses_receiver_total_rate_before_hmac_and_never_peer_rate_limits():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            step_s=0.1,
            auto_traffic=False,
            queue_capacity=128,
            tx_service_per_step=64,
            rx_service_per_step=64,
            flooding_packet_rate_threshold_pps=8.0,
        )
    )
    runtime.schedule_attack(
        _plan(
            "DOS",
            "FLOODING",
            end_s=0.7,
            attacker_node_id=-1,
            target_node_ids=[1],
            intensity={"value": 80.0, "unit": "pps"},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["outcome"]["receiver_total_rate_exceeded"] is True
    assert label["outcome"]["malicious_traffic_blocked"] > 0
    arrival_events = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS"
        and event["observer_node_id"] == 1
        and event["online_features"]["traffic"]["total_packet_count"] is not None
    ]
    assert max(
        event["online_features"]["traffic"]["packet_rate_pps"]
        for event in arrival_events
    ) >= 8.0
    assert any(
        event["online_features"]["security_state"]["application_hmac_result"]
        in {"FAIL", "UNKNOWN_DEVICE"}
        for event in _auth_events(runtime)
    )
    assert not runtime.nodes[1].rate_limited_peer_ids


def test_normal_receiver_total_rate_below_threshold_does_not_alarm():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
            flooding_packet_rate_threshold_pps=8.0,
        )
    )
    runtime.queue_message(2, 1, "STATUS", {"status_code": 1, "value": 1})
    runtime.run_to_completion()
    predictions = [
        event["extensions"]["model_result"]["predicted_label"]
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
    ]
    assert "DOS" not in predictions


def test_fdi_small_post_hmac_change_is_rejected_without_business_rule():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=16)
    )
    runtime.schedule_attack(
        _plan(
            "FDI",
            "TELEMETRY_ABRUPT_CHANGE",
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "absolute_offset": 0.1},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    message_id = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0, "flight_state": "FLYING"},
        encrypt=False,
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["injection_stage"] == "POST_HMAC_PRE_TRANSMISSION"
    assert label["truth"]["application_hmac_recomputed"] is False
    assert label["truth"]["original_value"]["altitude_m"] == 100.0
    assert label["truth"]["modified_value"]["altitude_m"] == pytest.approx(100.1)
    assert label["outcome"]["application_hmac_rejected"] is True
    state = _auth_events(runtime, message_id)[-1]["online_features"]["security_state"]
    assert state["application_hmac_result"] == "FAIL"
    assert state["replay_check_result"] == "UNAVAILABLE"
    assert 2 not in runtime.nodes[1].telemetry_by_source


def test_replay_hmac_passes_before_duplicate_window_rejects():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, rx_service_per_step=16)
    )
    runtime.schedule_attack(
        _plan(
            "REPLAY",
            "IMMEDIATE_REPLAY",
            impact_start_s=0.4,
            end_s=0.9,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"max_capture_age_s": 1.0},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    message_id = runtime.queue_message(2, 1, "STATUS", {"status_code": 1, "value": 2})
    runtime.run_to_completion()
    states = [
        event["online_features"]["security_state"]
        for event in _auth_events(runtime, message_id)
    ]
    assert any(
        state["application_hmac_result"] == "PASS"
        and state["replay_check_result"] == "DUPLICATE"
        for state in states
    )


def test_delayed_replay_hmac_passes_then_timestamp_expires():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.4,
            auto_traffic=False,
            rx_service_per_step=16,
            replay_timestamp_freshness_s=0.3,
        )
    )
    runtime.schedule_attack(
        _plan(
            "REPLAY",
            "DELAYED_REPLAY",
            impact_start_s=0.6,
            end_s=1.1,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"delay_s": 0.5},
        )
    )
    assert runtime.config.encrypt_sensitive is False
    message_id = runtime.queue_message(2, 1, "STATUS", {"status_code": 1, "value": 3})
    runtime.run_to_completion()
    states = [
        event["online_features"]["security_state"]
        for event in _auth_events(runtime, message_id)
    ]
    assert any(
        state["application_hmac_result"] == "PASS"
        and state["replay_check_result"] == "STALE_TIMESTAMP"
        for state in states
    )


def test_unseen_out_of_order_sequence_inside_window_passes():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
        )
    )
    ids = [
        runtime.queue_message(
            2,
            1,
            "STATUS",
            {"status_code": 1, "value": sequence},
            sequence_no=sequence,
            session_id="reorder-session",
        )
        for sequence in (100, 101, 103, 102)
    ]
    runtime.run_to_completion()
    final = _auth_events(runtime, ids[-1])[-1]["online_features"]["security_state"]
    assert final["application_hmac_result"] == "PASS"
    assert final["replay_check_result"] == "PASS"


def test_jamming_attack_plan_is_rejected_and_sources_have_no_shortcut():
    with pytest.raises(ValueError, match="unsupported DOS subtype"):
        _plan("DOS", "JAMMING")
    root = Path(__file__).resolve().parents[2]
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "swarm_sim").rglob("*.py")
    )
    assert "force_auth_failure" not in production
    assert '"JAMMING"' not in (root / "swarm_sim" / "attacks.py").read_text(
        encoding="utf-8"
    )
