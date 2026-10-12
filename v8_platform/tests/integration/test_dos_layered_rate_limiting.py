from __future__ import annotations

import pytest

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.adapters import CryptoOpenResult
from swarm_sim.security import DefenseAction, DefenseRequest


def _config(*, flooding_detection_enabled: bool = True, capacity: float = 2.0):
    return RunConfig(
        seed=42,
        duration_s=0.6,
        step_s=0.2,
        auto_traffic=False,
        queue_capacity=128,
        tx_service_per_step=64,
        rx_service_per_step=64,
        traffic_statistics_window_s=1.0,
        flooding_packet_rate_threshold_pps=1.0,
        flooding_detection_enabled=flooding_detection_enabled,
        flooding_severe_rate_multiplier=1.0,
        flooding_sustained_overload_s=0.1,
        flooding_recovery_rate_multiplier=0.5,
        flooding_recovery_hold_s=2.0,
        flooding_token_refill_rate_pps=0.01,
        flooding_token_bucket_capacity=capacity,
    )


def _flood(attacker_node_id: int, *, attack_id: str | None = None) -> AttackPlan:
    return AttackPlan(
        attack_family="DOS",
        attack_subtype="FLOODING",
        scheduled_start_s=0.0,
        impact_start_s=0.0,
        end_s=0.4,
        attacker_node_id=attacker_node_id,
        target_node_ids=[1],
        intensity={"value": 20.0, "unit": "pps"},
        parameters={"packet_type": "STATUS"},
        attack_id=attack_id,
    )


def _rate_limit_events(runtime: PlatformRuntime, stage: str | None = None):
    events = [
        event
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and "rate_limit_admission" in event["extensions"]
    ]
    if stage is None:
        return events
    return [
        event
        for event in events
        if event["extensions"]["rate_limit_admission"]["stage"] == stage
    ]


def _auth_events(runtime: PlatformRuntime):
    return [event for event in runtime.events if event["event_type"] == "AUTH_RESULT"]


def _message_events(runtime: PlatformRuntime, event_type: str, message_id: str):
    return [
        event
        for event in runtime.events
        if event["event_type"] == event_type and event["message_id"] == message_id
    ]


def test_link_crypto_failure_is_not_recorded_as_application_hmac_rejection(
    monkeypatch,
):
    runtime = PlatformRuntime(
        _config(capacity=4.0), run_id="layered-link-crypto-failure"
    )
    runtime.schedule_attack(
        AttackPlan(
            attack_family="SPOOFING",
            attack_subtype="KNOWN_ID_CONFLICT",
            scheduled_start_s=0.0,
            impact_start_s=0.0,
            end_s=0.4,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"claimed_src_id": 0},
        )
    )

    def fail_link_crypto(frame, receiver_id):
        return CryptoOpenResult(
            status="ERROR",
            auth_result="FAIL",
            payload=None,
            key_state="AVAILABLE",
            key_epoch=frame.key_epoch,
            error_code="AUTH_TAG_MISMATCH",
        )

    monkeypatch.setattr(runtime.crypto, "open", fail_link_crypto)
    runtime.start()
    runtime.step()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    label = runtime.attack_scheduler.labels()[0]
    outcome = label["outcome"]
    generated_ids = set(label["truth"]["generated_message_ids"])
    failed_auth = [
        event for event in _auth_events(runtime) if event["message_id"] in generated_ids
    ]
    assert snapshot["hmac_rejected_count"] == 0
    assert "application_hmac_rejected" not in outcome
    assert "application_hmac_rejected_count" not in outcome
    assert "application_hmac_failure_reason" not in outcome
    assert len(failed_auth) == 1
    assert all(
        event["online_features"]["security_state"]["auth_result"] == "FAIL"
        and event["online_features"]["security_state"]["application_hmac_result"]
        == "UNAVAILABLE"
        for event in failed_auth
    )


def test_not_applicable_control_refunds_pre_auth_without_device_charge(monkeypatch):
    runtime = PlatformRuntime(_config(capacity=1.0), run_id="layered-not-applicable")
    verify_calls: list[str] = []
    real_verify = runtime.application_auth.verify

    def counted_verify(frame, payload):
        verify_calls.append(frame.message_id)
        return real_verify(frame, payload)

    monkeypatch.setattr(runtime.application_auth, "verify", counted_verify)
    message_id = runtime.queue_message(
        2,
        1,
        "SKG_CONTROL",
        {"phase": "TEST_CONTROL"},
        encrypt=False,
    )

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    auth = _message_events(runtime, "AUTH_RESULT", message_id)
    assert verify_calls == [message_id]
    assert len(auth) == 1
    assert auth[0]["online_features"]["security_state"][
        "application_hmac_result"
    ] == "NOT_APPLICABLE"
    assert snapshot["buckets"]["receiver_global"]["tokens"] == 1.0
    assert snapshot["buckets"]["ingress"] == []
    assert snapshot["buckets"]["authenticated_devices"] == []


@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "encrypted"])
def test_covered_frame_refunds_then_charges_device_and_verifies_hmac_once(
    monkeypatch, encrypted: bool
):
    runtime = PlatformRuntime(
        _config(capacity=1.0), run_id=f"layered-covered-{encrypted}"
    )
    verify_calls: list[str] = []
    real_verify = runtime.application_auth.verify

    def counted_verify(frame, payload):
        verify_calls.append(frame.message_id)
        return real_verify(frame, payload)

    monkeypatch.setattr(runtime.application_auth, "verify", counted_verify)
    message_id = runtime.queue_message(
        2,
        1,
        "STATUS",
        {"status_code": 1, "value": 9},
        encrypt=encrypted,
    )

    runtime.start()
    runtime.step()
    runtime.step()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    auth = _message_events(runtime, "AUTH_RESULT", message_id)
    assert verify_calls == [message_id]
    assert len(auth) == 1
    assert auth[0]["online_features"]["security_state"][
        "application_hmac_result"
    ] == "PASS"
    assert snapshot["buckets"]["receiver_global"]["tokens"] == 1.0
    assert snapshot["buckets"]["ingress"] == []
    assert snapshot["buckets"]["authenticated_devices"][0]["device_id"] == 2
    assert snapshot["buckets"]["authenticated_devices"][0]["tokens"] == pytest.approx(
        0.002
    )
    assert [message.message_id for message in runtime.nodes[1].delivered_messages] == [
        message_id
    ]


def test_authenticated_replay_uses_distinct_reservations_and_cached_hmac(monkeypatch):
    config = _config(capacity=2.0)
    config.duration_s = 1.0
    runtime = PlatformRuntime(config, run_id="layered-authenticated-replay")
    runtime.schedule_attack(
        AttackPlan(
            attack_family="REPLAY",
            attack_subtype="IMMEDIATE_REPLAY",
            scheduled_start_s=0.0,
            impact_start_s=0.4,
            end_s=0.8,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"max_capture_age_s": 1.0},
        )
    )
    verify_calls: list[str] = []
    real_verify = runtime.application_auth.verify

    def counted_verify(frame, payload):
        verify_calls.append(frame.message_id)
        return real_verify(frame, payload)

    monkeypatch.setattr(runtime.application_auth, "verify", counted_verify)
    message_id = runtime.queue_message(
        2, 1, "STATUS", {"status_code": 1, "value": 11}, encrypt=False
    )

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    auth = _message_events(runtime, "AUTH_RESULT", message_id)
    assert verify_calls.count(message_id) == 2
    assert len(_message_events(runtime, "RX_SUCCESS", message_id)) == 2
    assert len(auth) == 2
    assert {
        event["online_features"]["security_state"]["replay_check_result"]
        for event in auth
    } == {"PASS", "DUPLICATE"}
    assert {
        event["online_features"]["security_state"]["application_hmac_result"]
        for event in auth
    } == {"PASS"}
    assert snapshot["buckets"]["receiver_global"]["tokens"] == 2.0
    assert snapshot["buckets"]["ingress"] == []
    assert snapshot["buckets"]["authenticated_devices"][0]["tokens"] < 0.1


def test_external_invalid_hmac_flood_is_measured_then_pre_auth_limited():
    runtime = PlatformRuntime(_config(), run_id="layered-external-pre-auth")
    runtime.schedule_attack(_flood(-1))

    runtime.run_to_completion()

    arrivals = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS" and event["observer_node_id"] == 1
    ]
    rejected_hmac = [
        event
        for event in _auth_events(runtime)
        if event["online_features"]["security_state"]["application_hmac_result"]
        == "UNKNOWN_DEVICE"
    ]
    pre_auth_drops = _rate_limit_events(runtime, "PRE_AUTH_RATE_LIMIT")
    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)

    assert len(arrivals) == 4
    assert arrivals[-1]["online_features"]["traffic"]["total_packet_count"] == 4
    assert len(rejected_hmac) == 2
    assert len(pre_auth_drops) == 2
    assert snapshot["pre_auth_drop_count"] == 2
    assert snapshot["hmac_rejected_count"] == 2
    assert snapshot["buckets"]["receiver_global"]["tokens"] < 1.0
    assert snapshot["buckets"]["ingress"][0]["tokens"] < 1.0
    assert runtime.rules[1]._flood_defense._pre_auth_reservations == {}
    assert runtime.nodes[1].drop_count == 4
    assert not runtime.nodes[1].rx_queue
    assert not runtime.nodes[1].rate_limited_peer_ids
    dos_rate_limit = next(
        event
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event["extensions"].get("defense_result", {}).get("request", {}).get(
            "action"
        )
        == "RATE_LIMIT"
        and event["extensions"]["defense_result"]["request"]["reason"] == "DOS"
    )
    assert dos_rate_limit["extensions"]["defense_result"]["executed"] is True
    assert (
        dos_rate_limit["extensions"]["defense_result"]["outcome"]["scope"]
        == "RECEIVER_FLOOD_GUARD"
    )
    for event in pre_auth_drops:
        admission = event["extensions"]["rate_limit_admission"]
        assert set(admission) == {
            "stage",
            "allowed",
            "reason",
            "bucket_scope",
            "tokens_remaining",
            "evidence_event_id",
        }
        assert admission["allowed"] is False
        assert admission["reason"] == "token_bucket_exhausted"
        assert admission["bucket_scope"] in {"receiver_global", "ingress"}
        assert admission["evidence_event_id"]


def test_authenticated_source_flood_refunds_pre_auth_then_post_auth_limits():
    runtime = PlatformRuntime(_config(), run_id="layered-authenticated-post-auth")
    runtime.schedule_attack(_flood(2))

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    pre_auth_drops = _rate_limit_events(runtime, "PRE_AUTH_RATE_LIMIT")
    post_auth_drops = _rate_limit_events(runtime, "POST_AUTH_RATE_LIMIT")
    passed_hmac = [
        event
        for event in _auth_events(runtime)
        if event["online_features"]["security_state"]["application_hmac_result"]
        == "PASS"
    ]

    assert pre_auth_drops == []
    assert len(post_auth_drops) == 2
    assert snapshot["pre_auth_drop_count"] == 0
    assert snapshot["post_auth_drop_count"] == 2
    assert snapshot["buckets"]["receiver_global"]["tokens"] == 2.0
    assert snapshot["buckets"]["ingress"] == []
    assert len(passed_hmac) == 2
    assert len(runtime.nodes[1].delivered_messages) == 2
    assert not runtime.nodes[1].rate_limited_peer_ids


def test_distributed_external_flood_cannot_bypass_receiver_global_bucket():
    runtime = PlatformRuntime(_config(), run_id="layered-distributed-global")
    runtime.schedule_attack(_flood(-1, attack_id="external-a"))
    runtime.schedule_attack(_flood(-2, attack_id="external-b"))

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    pre_auth_drops = _rate_limit_events(runtime, "PRE_AUTH_RATE_LIMIT")

    assert snapshot["total_arrival_count"] == 8
    assert snapshot["pre_auth_drop_count"] == 6
    assert len(pre_auth_drops) == 6
    assert any(
        event["extensions"]["rate_limit_admission"]["bucket_scope"]
        == "receiver_global"
        for event in pre_auth_drops
    )
    assert {bucket["link_sender_id"] for bucket in snapshot["buckets"]["ingress"]} == {-1}
    assert len(
        [
            event
            for event in _auth_events(runtime)
            if event["online_features"]["security_state"][
                "application_hmac_result"
            ]
            == "UNKNOWN_DEVICE"
        ]
    ) == 2


def test_rotating_invalid_hmac_flood_bounds_controller_metadata():
    runtime = PlatformRuntime(_config(capacity=3.0), run_id="layered-rotating-invalid")
    for index in range(1, 21):
        runtime.schedule_attack(_flood(-index, attack_id=f"rotating-{index}"))

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    rejected_hmac = [
        event
        for event in _auth_events(runtime)
        if event["online_features"]["security_state"]["application_hmac_result"]
        == "UNKNOWN_DEVICE"
    ]
    controller = runtime.rules[1]._flood_defense

    assert snapshot["total_arrival_count"] == 80
    assert snapshot["pre_auth_drop_count"] == 77
    assert snapshot["hmac_rejected_count"] == len(rejected_hmac) == 3
    assert controller._pre_auth_reservations == {}
    assert {bucket["link_sender_id"] for bucket in snapshot["buckets"]["ingress"]} == {-1}
    assert snapshot["buckets"]["receiver_global"]["tokens"] < 1.0
    assert snapshot["buckets"]["ingress"][0]["tokens"] < 1.0


def test_disabled_detector_bypasses_admission_and_preserves_hmac_rejection():
    runtime = PlatformRuntime(
        _config(flooding_detection_enabled=False, capacity=1.0),
        run_id="layered-disabled",
    )
    runtime.schedule_attack(_flood(-1))

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    rejected_hmac = [
        event
        for event in _auth_events(runtime)
        if event["online_features"]["security_state"]["application_hmac_result"]
        == "UNKNOWN_DEVICE"
    ]

    assert _rate_limit_events(runtime) == []
    assert snapshot["state"] == "NORMAL"
    assert snapshot["pre_auth_drop_count"] == 0
    assert snapshot["post_auth_drop_count"] == 0
    assert snapshot["hmac_rejected_count"] == 4
    assert len(rejected_hmac) == 4
    assert runtime.nodes[1].drop_count == 4


def test_manual_non_dos_rate_limit_keeps_legacy_persistent_peer_behavior():
    runtime = PlatformRuntime(_config(), run_id="layered-manual-rate-limit")
    request = DefenseRequest(
        request_id="manual-rate-limit",
        action=DefenseAction.RATE_LIMIT,
        requester_node_id=1,
        target_node_id=1,
        peer_id=2,
        requested_time_s=0.0,
        reason="MANUAL_OPERATOR",
    )

    result = runtime.defense.execute(request, runtime.nodes[1], 0.0)

    assert result.executed is True
    assert result.failure_reason is None
    assert runtime.nodes[1].rate_limited_peer_ids == {2}


@pytest.mark.parametrize("reason", ["DOS", "dos", "DoS"])
def test_direct_dos_rate_limit_is_nonpersistent_without_scope(reason: str):
    runtime = PlatformRuntime(_config(), run_id=f"layered-direct-{reason}")
    request = DefenseRequest(
        request_id=f"direct-{reason}",
        action=DefenseAction.RATE_LIMIT,
        requester_node_id=1,
        target_node_id=1,
        peer_id=2,
        requested_time_s=0.0,
        reason=reason,
    )

    result = runtime.defense.execute(request, runtime.nodes[1], 0.0)

    assert result.executed is True
    assert result.failure_reason is None
    assert runtime.nodes[1].rate_limited_peer_ids == set()


def test_runtime_passes_all_dos_configuration_to_initial_and_external_engines():
    config = _config(capacity=3.0)
    config.flooding_severe_rate_multiplier = 2.5
    config.flooding_sustained_overload_s = 0.75
    config.flooding_recovery_rate_multiplier = 0.25
    config.flooding_recovery_hold_s = 4.0
    config.flooding_token_refill_rate_pps = 1.25
    runtime = PlatformRuntime(config, run_id="layered-config-propagation")
    runtime._external_node(-7)

    for node_id in (1, -7):
        controller = runtime.rules[node_id]._flood_defense
        assert controller.severe_multiplier == 2.5
        assert controller.sustained_overload_s == 0.75
        assert controller.recovery_multiplier == 0.25
        assert controller.recovery_hold_s == 4.0
        assert controller.token_refill_rate_pps == 1.25
        assert controller.token_bucket_capacity == 3.0
