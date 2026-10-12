from __future__ import annotations

import json

import pytest

from swarm_sim.flood_defense import (
    FloodDefenseController,
    FloodDefenseState,
    TokenBucket,
)
from swarm_sim.security import DefenseAction, DeterministicRuleEngine


def _controller(*, enabled: bool = True) -> FloodDefenseController:
    return FloodDefenseController(
        window_s=1.0,
        alert_threshold_pps=8.0,
        severe_multiplier=1.5,
        sustained_overload_s=0.5,
        recovery_multiplier=0.7,
        recovery_hold_s=2.0,
        token_refill_rate_pps=8.0,
        token_bucket_capacity=12.0,
        enabled=enabled,
    )


def _record(controller: FloodDefenseController, count: int, now_s: float) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for _ in range(count):
        snapshot = controller.record_arrival(now_s)
    return snapshot


def test_rate_threshold_transitions_from_normal_to_alert():
    controller = _controller()

    assert _record(controller, 7, 0.0)["state"] == FloodDefenseState.NORMAL.value
    snapshot = controller.record_arrival(0.0)

    assert snapshot["rate_pps"] == 8.0
    assert snapshot["state"] == FloodDefenseState.ALERT.value
    assert snapshot["previous_state"] == FloodDefenseState.NORMAL.value
    assert snapshot["state_entered_at_s"] == 0.0


def test_severe_rate_can_jump_directly_from_normal_to_limiting():
    controller = FloodDefenseController(
        window_s=0.05,
        alert_threshold_pps=8.0,
        severe_multiplier=1.5,
        sustained_overload_s=0.5,
        recovery_multiplier=0.7,
        recovery_hold_s=2.0,
        token_refill_rate_pps=8.0,
        token_bucket_capacity=12.0,
        enabled=True,
    )

    snapshot = controller.record_arrival(0.0)

    assert snapshot["rate_pps"] == 20.0
    assert snapshot["state"] == FloodDefenseState.LIMITING.value
    assert snapshot["previous_state"] == FloodDefenseState.NORMAL.value


def test_exact_severe_threshold_enters_limiting():
    controller = _controller()

    snapshot = _record(controller, 12, 0.0)

    assert snapshot["rate_pps"] == 12.0
    assert snapshot["state"] == FloodDefenseState.LIMITING.value


def test_sustained_overload_transitions_from_alert_to_limiting():
    controller = _controller()
    _record(controller, 8, 0.0)
    controller.record_arrival(0.1)

    before_hold = controller.advance(0.599)
    after_hold = controller.advance(0.6)

    assert before_hold["state"] == FloodDefenseState.ALERT.value
    assert after_hold["state"] == FloodDefenseState.LIMITING.value
    assert after_hold["previous_state"] == FloodDefenseState.ALERT.value


def test_expiry_to_alert_threshold_restarts_overload_before_new_arrival():
    controller = _controller()
    controller.record_arrival(0.0)
    _record(controller, 8, 0.4)

    snapshot = controller.record_arrival(1.0001)

    assert snapshot["rate_pps"] == 9.0
    assert snapshot["state"] == FloodDefenseState.ALERT.value
    assert snapshot["overload_started_at_s"] == 1.0001


def test_alert_returns_to_normal_when_rate_drops_below_alert_threshold():
    controller = _controller()
    _record(controller, 8, 0.0)

    snapshot = controller.advance(1.01)

    assert snapshot["state"] == FloodDefenseState.NORMAL.value
    assert snapshot["previous_state"] == FloodDefenseState.ALERT.value


def test_limiting_enters_recovery_below_recovery_rate():
    controller = _controller()
    _record(controller, 12, 0.0)

    snapshot = controller.advance(1.01)

    assert snapshot["rate_pps"] == 0.0
    assert snapshot["recovery_threshold_pps"] == pytest.approx(5.6)
    assert snapshot["state"] == FloodDefenseState.RECOVERING.value
    assert snapshot["previous_state"] == FloodDefenseState.LIMITING.value


def test_exact_recovery_threshold_remains_limiting():
    controller = FloodDefenseController(
        window_s=2.5,
        alert_threshold_pps=8.0,
        severe_multiplier=1.5,
        sustained_overload_s=0.5,
        recovery_multiplier=0.7,
        recovery_hold_s=2.0,
        token_refill_rate_pps=8.0,
        token_bucket_capacity=12.0,
        enabled=True,
    )
    _record(controller, 16, 0.0)
    _record(controller, 14, 0.1)

    snapshot = controller.advance(2.5001)

    assert snapshot["rate_pps"] == pytest.approx(5.6)
    assert snapshot["state"] == FloodDefenseState.LIMITING.value
    assert snapshot["recovery_started_at_s"] is None


def test_advance_completes_recovery_without_a_new_arrival():
    controller = _controller()
    _record(controller, 12, 0.0)
    controller.advance(1.01)

    before_hold = controller.advance(3.009)
    after_hold = controller.advance(3.01)

    assert before_hold["state"] == FloodDefenseState.RECOVERING.value
    assert after_hold["state"] == FloodDefenseState.NORMAL.value
    assert after_hold["previous_state"] == FloodDefenseState.RECOVERING.value


def test_recovery_records_episode_timestamps_and_clears_temporary_admission_state():
    controller = _controller()
    _record(controller, 12, 0.0)
    assert controller.admit_pre_auth(0.0, 7, "link-7", "outstanding").allowed
    assert controller.admit_post_auth(0.0, 7).allowed

    recovering = controller.advance(1.01)
    recovered = controller.advance(3.01)

    assert recovering["limiting_started_at_s"] == 0.0
    assert recovering["recovered_at_s"] is None
    assert recovered["limiting_started_at_s"] == 0.0
    assert recovered["recovered_at_s"] == 3.01
    assert recovered["buckets"] == {
        "receiver_global": None,
        "ingress": [],
        "authenticated_devices": [],
    }
    assert controller._pre_auth_reservations == {}
    _record(controller, 12, 3.02)
    assert controller.admit_pre_auth(3.02, 7, "link-7", "outstanding").allowed
    assert controller.snapshot(3.02)["buckets"]["receiver_global"]["tokens"] == 11.0


def test_reset_clears_flood_episode_timestamps():
    controller = _controller()
    _record(controller, 12, 0.0)
    controller.advance(1.01)
    controller.advance(3.01)

    controller.reset()

    snapshot = controller.snapshot(0.0)
    assert snapshot["limiting_started_at_s"] is None
    assert snapshot["recovered_at_s"] is None


def test_recovery_requires_continuously_low_rate():
    controller = _controller()
    _record(controller, 12, 0.0)
    controller.advance(1.01)
    controller.advance(2.0)
    _record(controller, 6, 2.0)
    controller.advance(2.01)
    controller.advance(3.0)

    snapshot = controller.advance(4.01)

    assert snapshot["state"] == FloodDefenseState.RECOVERING.value


def test_recovery_returns_to_limiting_at_alarm_threshold():
    controller = _controller()
    _record(controller, 12, 0.0)
    controller.advance(1.01)

    snapshot = _record(controller, 8, 1.1)

    assert snapshot["state"] == FloodDefenseState.LIMITING.value
    assert snapshot["previous_state"] == FloodDefenseState.RECOVERING.value


def test_sliding_window_includes_arrivals_at_cutoff_boundary():
    controller = _controller()
    _record(controller, 8, 0.0)

    at_boundary = controller.advance(1.0)
    past_boundary = controller.advance(1.000001)

    assert at_boundary["rate_pps"] == 8.0
    assert past_boundary["rate_pps"] == 0.0


def test_token_bucket_bursts_to_capacity_then_refuses_at_zero():
    bucket = TokenBucket(refill_rate_per_s=8.0, capacity=12.0, bucket_scope="test")

    decisions = [bucket.admit(0.0) for _ in range(12)]
    denied = bucket.admit(0.0)

    assert all(decision.allowed for decision in decisions)
    assert decisions[-1].tokens_remaining == 0.0
    assert denied.allowed is False
    assert denied.reason == "token_bucket_exhausted"
    assert denied.bucket_scope == "test"
    assert denied.tokens_remaining == 0.0


def test_token_bucket_refills_at_configured_rate_and_same_time_is_deterministic():
    bucket = TokenBucket(refill_rate_per_s=8.0, capacity=12.0)
    for _ in range(12):
        bucket.admit(4.0)

    denied = bucket.admit(4.0)
    refilled = bucket.admit(4.125)
    unchanged = bucket.admit(4.125)

    assert denied.allowed is False
    assert refilled.allowed is True
    assert refilled.tokens_remaining == 0.0
    assert unchanged.allowed is False
    assert unchanged.tokens_remaining == 0.0


def test_token_bucket_never_refills_above_capacity():
    bucket = TokenBucket(refill_rate_per_s=8.0, capacity=12.0)
    bucket.admit(0.0)

    decision = bucket.admit(100.0)

    assert decision.allowed is True
    assert decision.tokens_remaining == 11.0


def test_pre_auth_admission_is_atomic_when_global_bucket_is_empty():
    controller = _controller()
    _record(controller, 12, 0.0)
    for sender_id in range(12):
        assert controller.admit_pre_auth(
            0.0, sender_id, f"link-{sender_id}", f"reservation-{sender_id}"
        ).allowed

    denied = controller.admit_pre_auth(0.0, 99, "link-99", "reservation-99")
    snapshot = controller.snapshot(0.0)

    assert denied.allowed is False
    assert denied.bucket_scope == "receiver_global"
    assert all(
        bucket["link_sender_id"] != 99
        for bucket in snapshot["buckets"]["ingress"]
    )
    assert (99, "link-99") not in controller._pre_auth_reservations
    assert snapshot["pre_auth_drop_count"] == 1


def test_pre_auth_admission_is_atomic_when_ingress_bucket_is_empty():
    controller = _controller()
    _record(controller, 12, 0.0)
    assert controller.admit_pre_auth(0.0, 1, "link-1", "reservation-1").allowed
    ingress_bucket = controller._ingress_buckets[(1, "link-1")]
    for _ in range(11):
        assert ingress_bucket.admit(0.0).allowed
    global_tokens_before = controller.snapshot(0.0)["buckets"]["receiver_global"][
        "tokens"
    ]

    denied = controller.admit_pre_auth(0.0, 1, "link-1", "reservation-2")
    global_tokens_after = controller.snapshot(0.0)["buckets"]["receiver_global"][
        "tokens"
    ]

    assert denied.allowed is False
    assert denied.bucket_scope == "ingress"
    assert global_tokens_before == 11.0
    assert global_tokens_after == global_tokens_before


def test_release_pre_auth_refunds_only_the_exact_outstanding_reservation_once():
    controller = _controller()
    _record(controller, 12, 0.0)

    assert controller.admit_pre_auth(0.0, 7, "link-7-1", "rx-event-1").allowed
    assert controller.admit_pre_auth(0.0, 7, "link-7-1", "rx-event-2").allowed
    reserved = controller.snapshot(0.0)["buckets"]
    assert reserved["receiver_global"]["tokens"] == 10.0
    assert reserved["ingress"][0]["tokens"] == 10.0

    controller.release_pre_auth(0.0, 7, "link-7-1", "rx-event-1")
    released = controller.snapshot(0.0)["buckets"]
    assert released["receiver_global"]["tokens"] == 11.0
    assert released["ingress"][0]["tokens"] == 11.0

    controller.release_pre_auth(0.0, 7, "link-7-1", "rx-event-1")
    controller.release_pre_auth(0.0, 7, "link-7-1", "unknown-rx-event")
    duplicate = controller.snapshot(0.0)["buckets"]
    assert duplicate["receiver_global"]["tokens"] == 11.0
    assert duplicate["ingress"][0]["tokens"] == 11.0

    controller.release_pre_auth(0.0, 7, "link-7-1", "rx-event-2")
    complete = controller.snapshot(0.0)["buckets"]
    assert complete["receiver_global"]["tokens"] == 12.0
    assert complete["ingress"][0]["tokens"] == 12.0


def test_finalize_pre_auth_removes_only_the_exact_reservation_without_refund():
    controller = _controller()
    _record(controller, 12, 0.0)
    assert controller.admit_pre_auth(0.0, 7, "link-7", "rx-event-1").allowed
    assert controller.admit_pre_auth(0.0, 7, "link-7", "rx-event-2").allowed

    controller.finalize_pre_auth(0.0, 7, "link-7", "rx-event-1")
    finalized = controller.snapshot(0.0)["buckets"]

    assert finalized["receiver_global"]["tokens"] == 10.0
    assert finalized["ingress"][0]["tokens"] == 10.0
    assert controller._pre_auth_reservations[(7, "link-7")] == {"rx-event-2"}

    controller.finalize_pre_auth(0.0, 7, "link-7", "rx-event-1")
    controller.finalize_pre_auth(0.0, 7, "link-7", "unknown-rx-event")
    assert controller.snapshot(0.0)["buckets"] == finalized

    controller.finalize_pre_auth(0.0, 7, "link-7", "rx-event-2")
    assert (7, "link-7") not in controller._pre_auth_reservations


def test_advance_reclaims_only_full_idle_ingress_buckets():
    controller = _controller()
    _record(controller, 12, 0.0)
    assert controller.admit_pre_auth(0.0, 1, "idle-link", "idle-rx").allowed
    controller.finalize_pre_auth(0.0, 1, "idle-link", "idle-rx")
    assert controller.admit_pre_auth(0.0, 2, "active-link", "active-rx").allowed

    observed = controller.snapshot(2.0)
    assert {bucket["link_sender_id"] for bucket in observed["buckets"]["ingress"]} == {
        1,
        2,
    }
    assert all(bucket["tokens"] == 11.0 for bucket in observed["buckets"]["ingress"])

    advanced = controller.advance(2.0)

    assert [bucket["link_sender_id"] for bucket in advanced["buckets"]["ingress"]] == [2]
    assert advanced["buckets"]["ingress"][0]["tokens"] == 12.0
    assert controller._pre_auth_reservations == {
        (2, "active-link"): {"active-rx"}
    }


def test_post_auth_admission_uses_per_device_bucket_and_counts_drops():
    controller = _controller()
    _record(controller, 12, 0.0)

    for _ in range(12):
        assert controller.admit_post_auth(0.0, authenticated_device_id=7).allowed
    denied = controller.admit_post_auth(0.0, authenticated_device_id=7)

    assert denied.allowed is False
    assert denied.bucket_scope == "authenticated_device"
    assert controller.snapshot(0.0)["post_auth_drop_count"] == 1
    assert controller.admit_post_auth(0.0, authenticated_device_id=8).allowed


def test_admission_outside_limiting_does_not_create_or_consume_buckets():
    controller = _controller()

    pre_auth = controller.admit_pre_auth(0.0, 1, "link-1", "reservation-1")
    post_auth = controller.admit_post_auth(0.0, 1)
    snapshot = controller.snapshot(0.0)

    assert pre_auth.allowed and pre_auth.tokens_remaining is None
    assert post_auth.allowed and post_auth.tokens_remaining is None
    assert snapshot["buckets"] == {
        "receiver_global": None,
        "ingress": [],
        "authenticated_devices": [],
    }


def test_disabled_controller_records_statistics_but_stays_normal_and_admits():
    controller = _controller(enabled=False)

    _record(controller, 20, 0.0)
    decision = controller.admit_pre_auth(0.0, 1, "link-1", "reservation-1")
    snapshot = controller.snapshot(0.0)

    assert snapshot["arrival_count"] == 20
    assert snapshot["rate_pps"] == 20.0
    assert snapshot["state"] == FloodDefenseState.NORMAL.value
    assert decision.allowed is True
    assert snapshot["buckets"]["receiver_global"] is None


def test_snapshots_are_json_serializable_and_deterministically_ordered():
    controller = _controller()
    _record(controller, 12, 0.0)
    controller.admit_pre_auth(0.0, 2, "z-link", "reservation-z")
    controller.admit_pre_auth(0.0, 1, "a-link", "reservation-a")
    controller.admit_post_auth(0.0, 9)
    controller.admit_post_auth(0.0, 3)

    first = controller.snapshot(0.0)
    second = controller.snapshot(0.0)

    assert json.loads(json.dumps(first)) == first
    assert second == first
    assert [item["link_sender_id"] for item in first["buckets"]["ingress"]] == [1, 2]
    assert [item["device_id"] for item in first["buckets"]["authenticated_devices"]] == [3, 9]


def test_snapshot_is_observational_and_advance_refills_every_existing_bucket():
    controller = _controller()
    _record(controller, 12, 0.0)
    for index in range(2):
        assert controller.admit_pre_auth(
            0.0, 7, "link-7", f"reservation-{index}"
        ).allowed
        assert controller.admit_post_auth(0.0, 7).allowed

    before_arrivals = tuple(controller._arrivals)
    before_controller_time = controller._last_time_s
    buckets = [
        controller._receiver_global_bucket,
        *controller._ingress_buckets.values(),
        *controller._authenticated_device_buckets.values(),
    ]
    before_buckets = [(bucket._tokens, bucket._last_time_s) for bucket in buckets]

    observed = controller.snapshot(0.125)

    assert observed["state"] == FloodDefenseState.LIMITING.value
    assert observed["arrival_count"] == 12
    assert tuple(controller._arrivals) == before_arrivals
    assert controller._last_time_s == before_controller_time
    assert [(bucket._tokens, bucket._last_time_s) for bucket in buckets] == before_buckets

    advanced = controller.advance(0.125)

    assert advanced["state"] == FloodDefenseState.LIMITING.value
    assert [bucket._tokens for bucket in buckets] == [11.0, 11.0, 11.0]
    assert [bucket._last_time_s for bucket in buckets] == [0.125, 0.125, 0.125]


def _limiting_engine_with_admission_state() -> DeterministicRuleEngine:
    engine = DeterministicRuleEngine()
    for _ in range(12):
        engine.record_arrival(0.0)
    assert engine.admit_flood_pre_auth(
        0.0, 7, "link-7", "held-reservation"
    ).allowed
    assert engine.admit_flood_post_auth(0.0, 7).allowed
    return engine


def _perform_delayed_flood_operation(
    engine: DeterministicRuleEngine, operation: str
) -> None:
    if operation == "pre":
        assert engine.admit_flood_pre_auth(
            1.01, 7, "link-7", "delayed-reservation"
        ).allowed
    elif operation == "post":
        assert engine.admit_flood_post_auth(1.01, 7).allowed
    else:
        engine.release_flood_pre_auth(
            1.01, 7, "link-7", "held-reservation"
        )


@pytest.mark.parametrize("operation", ["pre", "post", "release"])
def test_delayed_admission_and_refund_leave_recovery_for_explicit_advance(
    operation: str,
):
    engine = _limiting_engine_with_admission_state()
    controller = engine._flood_defense
    arrivals = tuple(controller._arrivals)

    _perform_delayed_flood_operation(engine, operation)

    assert controller._state is FloodDefenseState.LIMITING
    assert controller._recovery_started_at_s is None
    assert tuple(controller._arrivals) == arrivals
    assert controller._last_time_s == 1.01
    assert engine._observed_flood_state == FloodDefenseState.LIMITING.value

    detection, transition = engine.advance_flood_defense(1.01)
    repeated_detection, repeated = engine.advance_flood_defense(1.01)

    assert detection is None
    assert transition["transitioned"] is True
    assert transition["transition_from"] == FloodDefenseState.LIMITING.value
    assert transition["transition_to"] == FloodDefenseState.RECOVERING.value
    assert repeated_detection is None
    assert repeated["transitioned"] is False


@pytest.mark.parametrize("operation", ["pre", "post", "release"])
def test_delayed_admission_and_refund_leave_one_transition_for_record_arrival(
    operation: str,
):
    engine = _limiting_engine_with_admission_state()
    controller = engine._flood_defense

    _perform_delayed_flood_operation(engine, operation)

    changes = []
    for _ in range(2):
        previous = engine.flood_defense_snapshot(1.01)["state"]
        detection, statistics = engine.record_arrival(1.01)
        current = statistics["dos_defense_state"]
        if current != previous:
            changes.append((previous, current))
        assert detection is None

    assert changes == [
        (FloodDefenseState.LIMITING.value, FloodDefenseState.RECOVERING.value)
    ]
    assert controller._state is FloodDefenseState.RECOVERING
    assert engine._observed_flood_state == FloodDefenseState.RECOVERING.value


@pytest.mark.parametrize(
    "operation",
    ["record", "advance", "snapshot", "pre", "post", "release", "finalize"],
)
def test_controller_rejects_decreasing_timestamps(operation: str):
    controller = _controller()
    controller.advance(2.0)

    with pytest.raises(ValueError, match="simulation time cannot decrease"):
        if operation == "record":
            controller.record_arrival(1.0)
        elif operation == "advance":
            controller.advance(1.0)
        elif operation == "snapshot":
            controller.snapshot(1.0)
        elif operation == "pre":
            controller.admit_pre_auth(1.0, 1, "link-1", "reservation-1")
        elif operation == "post":
            controller.admit_post_auth(1.0, 1)
        elif operation == "release":
            controller.release_pre_auth(1.0, 1, "link-1", "reservation-1")
        else:
            controller.finalize_pre_auth(1.0, 1, "link-1", "reservation-1")


def test_token_bucket_rejects_decreasing_timestamps():
    bucket = TokenBucket(refill_rate_per_s=8.0, capacity=12.0)
    bucket.admit(2.0)

    with pytest.raises(ValueError, match="simulation time cannot decrease"):
        bucket.admit(1.0)


def test_reset_clears_transient_state_and_accepts_a_restarted_clock():
    controller = _controller()
    _record(controller, 12, 5.0)
    controller.admit_pre_auth(5.0, 1, "link-1", "old-reservation")
    for _ in range(13):
        controller.admit_post_auth(5.0, 7)

    controller.reset()
    snapshot = controller.snapshot(0.0)

    assert snapshot["state"] == FloodDefenseState.NORMAL.value
    assert snapshot["arrival_count"] == 0
    assert snapshot["pre_auth_drop_count"] == 0
    assert snapshot["post_auth_drop_count"] == 0
    assert snapshot["buckets"]["authenticated_devices"] == []

    _record(controller, 12, 0.0)
    assert controller.admit_pre_auth(
        0.0, 1, "link-1", "new-reservation"
    ).allowed
    controller.release_pre_auth(0.0, 1, "link-1", "old-reservation")
    assert controller.snapshot(0.0)["buckets"]["receiver_global"]["tokens"] == 11.0


def test_hmac_rejection_counter_increments_and_reset_clears_it():
    controller = _controller()

    assert controller.snapshot(0.0)["hmac_rejected_count"] == 0
    controller.record_hmac_rejection()
    controller.record_hmac_rejection()
    assert controller.snapshot(0.0)["hmac_rejected_count"] == 2

    controller.reset()

    assert controller.snapshot(0.0)["hmac_rejected_count"] == 0


def test_rule_engine_record_arrival_preserves_tuple_and_statistics_contract():
    engine = DeterministicRuleEngine(
        traffic_window_s=2.0,
        flooding_threshold_pps=4.0,
        flooding_severe_rate_multiplier=2.0,
        flooding_recovery_rate_multiplier=0.5,
    )

    result = engine.record_arrival(0.0)

    assert isinstance(result, tuple)
    assert len(result) == 2
    detection, statistics = result
    assert detection is None
    assert statistics == {
        "packet_rate_pps": 0.5,
        "total_packet_count": 1,
        "statistics_window_s": 2.0,
        "flooding_threshold_pps": 4.0,
        "dos_defense_state": FloodDefenseState.NORMAL.value,
        "alert_threshold_pps": 4.0,
        "severe_threshold_pps": 8.0,
        "recovery_threshold_pps": 2.0,
        "rate_limit_active": False,
    }


def test_rule_engine_emits_each_alert_and_limiting_transition_once():
    engine = DeterministicRuleEngine()

    detections = [engine.record_arrival(0.0)[0] for _ in range(13)]

    alert = detections[7]
    limiting = detections[11]
    assert alert is not None
    assert alert.label == "DOS"
    assert alert.recommended_action is DefenseAction.INCREASE_MONITORING
    assert alert.evidence["observable_subtype"] == "FLOODING"
    assert alert.evidence["dos_defense_state"] == FloodDefenseState.ALERT.value
    assert limiting is not None
    assert limiting.label == "DOS"
    assert limiting.recommended_action is DefenseAction.RATE_LIMIT
    assert limiting.evidence["dos_defense_state"] == FloodDefenseState.LIMITING.value
    assert [index for index, detection in enumerate(detections) if detection] == [7, 11]
    assert "runtime_attack_id" not in alert.evidence
    assert "runtime_attack_id" not in limiting.evidence


def test_rule_engine_direct_severe_transition_emits_only_rate_limit():
    engine = DeterministicRuleEngine(traffic_window_s=0.05)

    detection, statistics = engine.record_arrival(0.0)

    assert detection is not None
    assert detection.recommended_action is DefenseAction.RATE_LIMIT
    assert statistics["dos_defense_state"] == FloodDefenseState.LIMITING.value


def test_rule_engine_emits_sustained_overload_limiting_transition_once():
    engine = DeterministicRuleEngine()
    for _ in range(8):
        engine.record_arrival(0.0)
    engine.record_arrival(0.1)

    limiting, _ = engine.record_arrival(0.6)
    repeated, _ = engine.record_arrival(0.6)

    assert limiting is not None
    assert limiting.recommended_action is DefenseAction.RATE_LIMIT
    assert repeated is None


def test_rule_engine_delegates_admission_snapshot_advance_and_reset():
    engine = DeterministicRuleEngine()
    for _ in range(12):
        engine.record_arrival(5.0)

    assert engine.flood_defense_snapshot(5.0)["state"] == "LIMITING"
    assert engine.admit_flood_pre_auth(
        5.0, 1, "link-1", "reservation-1"
    ).allowed
    tokens_before_finalize = engine.flood_defense_snapshot(5.0)["buckets"]
    engine.finalize_flood_pre_auth(5.0, 1, "link-1", "reservation-1")
    assert engine.flood_defense_snapshot(5.0)["buckets"] == tokens_before_finalize
    assert engine._flood_defense._pre_auth_reservations == {}
    assert engine.admit_flood_post_auth(5.0, 1).allowed
    detection, advanced = engine.advance_flood_defense(6.01)
    assert detection is None
    assert advanced["state"] == "RECOVERING"
    assert advanced["transitioned"] is True
    assert advanced["transition_from"] == "LIMITING"
    assert advanced["transition_to"] == "RECOVERING"
    assert engine.record_flood_hmac_rejection() is None
    assert engine.flood_defense_snapshot(6.01)["hmac_rejected_count"] == 1

    engine.reset()

    snapshot = engine.flood_defense_snapshot(0.0)
    assert snapshot["state"] == "NORMAL"
    assert snapshot["arrival_count"] == 0
