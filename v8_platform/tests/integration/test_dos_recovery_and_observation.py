from __future__ import annotations

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.security import DefenseAction, DefenseRequest, DeterministicRuleEngine


def _config(**overrides) -> RunConfig:
    values = dict(
        seed=42,
        duration_s=4.0,
        step_s=0.2,
        auto_traffic=False,
        queue_capacity=128,
        tx_service_per_step=64,
        rx_service_per_step=64,
        traffic_statistics_window_s=1.0,
        flooding_packet_rate_threshold_pps=1.0,
        flooding_severe_rate_multiplier=1.0,
        flooding_recovery_rate_multiplier=0.5,
        flooding_recovery_hold_s=0.4,
        flooding_token_refill_rate_pps=0.01,
        flooding_token_bucket_capacity=1.0,
    )
    values.update(overrides)
    return RunConfig(**values)


def _attack() -> AttackPlan:
    return AttackPlan(
        attack_family="DOS",
        attack_subtype="FLOODING",
        scheduled_start_s=0.0,
        impact_start_s=0.0,
        end_s=0.4,
        attacker_node_id=-1,
        target_node_ids=[1],
        intensity={"value": 20.0, "unit": "pps"},
        parameters={"packet_type": "STATUS"},
    )


def _transitions(runtime: PlatformRuntime, node_id: int = 1):
    return [
        event
        for event in runtime.events
        if event["event_type"] == "NODE_STATE"
        and event["observer_node_id"] == node_id
        and "flood_defense_transition" in event["extensions"]
    ]


def _flood_internal_state(engine: DeterministicRuleEngine) -> dict[str, object]:
    controller = engine._flood_defense

    def bucket_state(bucket):
        return None if bucket is None else (bucket._tokens, bucket._last_time_s)

    return {
        "state": controller._state,
        "previous_state": controller._previous_state,
        "state_entered_at_s": controller._state_entered_at_s,
        "overload_started_at_s": controller._overload_started_at_s,
        "recovery_started_at_s": controller._recovery_started_at_s,
        "limiting_started_at_s": controller._limiting_started_at_s,
        "recovered_at_s": controller._recovered_at_s,
        "last_time_s": controller._last_time_s,
        "arrivals": tuple(controller._arrivals),
        "observed_state": engine._observed_flood_state,
        "receiver_global": bucket_state(controller._receiver_global_bucket),
        "ingress": tuple(
            (key, bucket_state(bucket))
            for key, bucket in sorted(controller._ingress_buckets.items())
        ),
        "authenticated_devices": tuple(
            (key, bucket_state(bucket))
            for key, bucket in sorted(controller._authenticated_device_buckets.items())
        ),
    }


def test_attack_end_recovers_without_packets_and_emits_each_transition_once():
    runtime = PlatformRuntime(_config(), run_id="recovery-no-packets")
    runtime.schedule_attack(_attack())

    runtime.run_to_completion()

    snapshot = runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)
    transitions = _transitions(runtime)
    changes = [event["extensions"]["flood_defense_transition"] for event in transitions]
    assert snapshot["state"] == "NORMAL"
    assert snapshot["limiting_started_at_s"] is not None
    assert snapshot["recovered_at_s"] is not None
    assert all(
        event["sim_time_s"] < transitions[1]["sim_time_s"]
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS" and event["observer_node_id"] == 1
    )
    assert [(item["from_state"], item["to_state"]) for item in changes] == [
        ("NORMAL", "LIMITING"),
        ("LIMITING", "RECOVERING"),
        ("RECOVERING", "NORMAL"),
    ]
    assert all(set(item) == {
        "from_state", "to_state", "packet_rate_pps", "rate_limit_active"
    } for item in changes)
    assert [item["rate_limit_active"] for item in changes] == [True, False, False]
    assert all("runtime_attack_id" not in item and "attack_id" not in item for item in changes)
    assert snapshot["buckets"] == {
        "receiver_global": None,
        "ingress": [],
        "authenticated_devices": [],
    }
    dos_models = [
        event for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event["observer_node_id"] == 1
        and event["extensions"].get("model_result", {}).get("predicted_label") == "DOS"
    ]
    dos_actions = [
        event for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event["observer_node_id"] == 1
        and event["extensions"].get("defense_result", {}).get("request", {}).get("reason") == "DOS"
    ]
    assert len(dos_models) == 1
    assert len(dos_actions) == 1


def test_tick_driven_alert_and_limiting_keep_rule_detection_and_action():
    runtime = PlatformRuntime(
        _config(
            duration_s=0.8,
            flooding_packet_rate_threshold_pps=8.0,
            flooding_severe_rate_multiplier=2.0,
            flooding_sustained_overload_s=0.5,
        ),
        run_id="tick-transitions",
    )
    for _ in range(9):
        runtime.rules[1]._flood_defense.record_arrival(0.0)

    runtime.run_to_completion()

    transitions = _transitions(runtime)
    changes = [event["extensions"]["flood_defense_transition"] for event in transitions]
    assert [(item["from_state"], item["to_state"]) for item in changes[:2]] == [
        ("NORMAL", "ALERT"),
        ("ALERT", "LIMITING"),
    ]
    actions = [
        event["extensions"]["defense_result"]["request"]["action"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event["extensions"].get("defense_result", {}).get("request", {}).get("reason") == "DOS"
    ]
    assert actions == ["INCREASE_MONITORING", "RATE_LIMIT"]
    models = [
        event for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event["observer_node_id"] == 1
        and event["extensions"].get("source") == "DETERMINISTIC_RULE"
        and event["extensions"]["model_result"]["predicted_label"] == "DOS"
    ]
    assert [event["extensions"]["model_result"]["evidence_event_ids"] for event in models] == [
        [transitions[0]["event_id"]],
        [transitions[1]["event_id"]],
    ]


def test_each_existing_receiver_advances_once_before_attack_injection(monkeypatch):
    runtime = PlatformRuntime(_config(duration_s=0.4), run_id="tick-order")
    runtime.schedule_attack(_attack())
    initial_node_ids = set(runtime.rules)
    calls = []
    for node_id, engine in runtime.rules.items():
        original = engine.advance_flood_defense

        def counted(now_s, *, receiver_id=node_id, delegate=original, rule=engine):
            calls.append((receiver_id, now_s, rule._flood_defense._total_arrival_count))
            return delegate(now_s)

        monkeypatch.setattr(engine, "advance_flood_defense", counted)

    runtime.start()
    runtime.step()

    assert {node_id for node_id, _, _ in calls} == initial_node_ids
    assert len(calls) == len(initial_node_ids)
    assert all(now_s == 0.2 for _, now_s, _ in calls)
    assert all(arrivals == 0 for _, _, arrivals in calls)
    assert runtime.rules[1].flood_defense_snapshot(0.2)["total_arrival_count"] > 0


def test_late_external_node_is_initialized_once_on_its_creation_tick(monkeypatch):
    runtime = PlatformRuntime(_config(duration_s=0.4), run_id="late-external-init")
    runtime.schedule_attack(_attack())
    initial_engines = dict(runtime.rules)
    calls = []
    original = DeterministicRuleEngine.advance_flood_defense

    def counted(self, now_s):
        calls.append((self, now_s))
        return original(self, now_s)

    monkeypatch.setattr(DeterministicRuleEngine, "advance_flood_defense", counted)

    runtime.start()
    runtime.step()

    external_engine = runtime.rules[-1]
    assert all(calls.count((engine, 0.2)) == 1 for engine in initial_engines.values())
    assert calls.count((external_engine, 0.2)) == 1
    assert external_engine._flood_defense._last_time_s == 0.2
    assert _transitions(runtime, -1) == []

    call_count = len(calls)
    assert runtime._external_node(-1) is runtime.nodes[-1]
    assert len(calls) == call_count


def test_read_apis_do_not_consume_recovery_transition_evidence():
    runtime = PlatformRuntime(
        _config(
            duration_s=2.0,
            flooding_packet_rate_threshold_pps=8.0,
            flooding_severe_rate_multiplier=1.5,
        ),
        run_id="observational-recovery-boundary",
    )
    engine = runtime.rules[1]
    for _ in range(12):
        engine.record_arrival(0.0)
    assert engine.admit_flood_pre_auth(0.0, 2, "link-2", "held").allowed
    assert engine.admit_flood_post_auth(0.0, 2).allowed
    runtime.start()
    runtime.context.clock.advance_to(1.01)
    before = _flood_internal_state(engine)

    snapshot = engine.flood_defense_snapshot(runtime.context.clock.now_s)
    observation = runtime.observation(1)["defense_resource"]
    rl_observation = runtime.rl_observation(1)["defense_resource"]

    assert snapshot["state"] == "LIMITING"
    assert snapshot["arrival_count"] == 12
    assert snapshot["buckets"]["receiver_global"]["tokens"] == 0.0
    assert observation["dos_defense_state"] == "LIMITING"
    assert rl_observation["dos_defense_state"] == "LIMITING"
    assert _flood_internal_state(engine) == before
    assert _transitions(runtime) == []

    runtime.step()

    transitions = _transitions(runtime)
    assert len(transitions) == 1
    assert transitions[0]["extensions"]["flood_defense_transition"] == {
        "from_state": "LIMITING",
        "to_state": "RECOVERING",
        "packet_rate_pps": 0.0,
        "rate_limit_active": False,
    }
    assert engine._observed_flood_state == "RECOVERING"


def test_observations_expose_flat_local_controller_values_and_legacy_limit():
    runtime = PlatformRuntime(
        _config(flooding_packet_rate_threshold_pps=8.0, flooding_severe_rate_multiplier=1.5),
        run_id="recovery-observation",
    )
    controller = runtime.rules[1]._flood_defense
    for _ in range(12):
        controller.record_arrival(0.0)
    assert controller.admit_pre_auth(0.0, 2, "link-2", "held").allowed
    assert not controller.admit_pre_auth(0.0, 3, "link-3", "denied").allowed
    controller.record_hmac_rejection()
    for _ in range(2):
        controller.admit_post_auth(0.0, 2)

    expected = {
        "dos_defense_state": "LIMITING",
        "packet_rate_pps": 12.0,
        "alert_threshold_pps": 8.0,
        "severe_threshold_pps": 12.0,
        "recovery_threshold_pps": 4.0,
        "rate_limit_active": True,
        "global_bucket_tokens": 0.0,
        "pre_auth_limited_count": 1,
        "post_auth_limited_count": 1,
        "hmac_rejected_count": 1,
        "limiting_started_at_s": 0.0,
        "recovered_at_s": None,
    }
    for observed in (runtime.observation(1), runtime.rl_observation(1)):
        assert {key: observed["defense_resource"][key] for key in expected} == expected
    assert runtime.rl_observation(1)["defense_resource"]["rate_limit_state"] is True

    controller.advance(1.01)
    controller.advance(1.41)
    runtime.context.clock.advance_to(1.41)
    request = DefenseRequest(
        request_id="manual-persistent",
        action=DefenseAction.RATE_LIMIT,
        requester_node_id=1,
        target_node_id=1,
        peer_id=9,
        requested_time_s=0.0,
        reason="MANUAL_OPERATOR",
    )
    runtime.defense.execute(request, runtime.nodes[1], 0.0)
    after = runtime.rl_observation(1)["defense_resource"]
    assert after["dos_defense_state"] == "NORMAL"
    assert after["global_bucket_tokens"] is None
    assert after["rate_limit_active"] is False
    assert after["rate_limit_state"] is True
    assert after["active_actions"]["rate_limited_peer_ids"] == [9]


def test_valid_low_rate_frame_is_delivered_after_recovery():
    runtime = PlatformRuntime(_config(), run_id="recovery-delivery")
    runtime.schedule_attack(_attack())
    runtime.start()
    while runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)["state"] != "NORMAL" or runtime.context.clock.now_s < 0.6:
        runtime.step()
    assert runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)["recovered_at_s"] is not None

    message_id = runtime.queue_message(
        2, 1, "STATUS", {"status_code": 1, "value": 9}, encrypt=False
    )
    runtime.run_to_completion()

    assert message_id in [message.message_id for message in runtime.nodes[1].delivered_messages]


def test_runtime_reset_recreates_normal_empty_controller_state():
    runtime = PlatformRuntime(_config(), run_id="recovery-reset")
    runtime.schedule_attack(_attack())
    runtime.run_to_completion()
    assert runtime.rules[1].flood_defense_snapshot(runtime.context.clock.now_s)["total_arrival_count"] > 0

    runtime.reset()

    snapshot = runtime.rules[1].flood_defense_snapshot(0.0)
    assert snapshot["state"] == "NORMAL"
    assert snapshot["total_arrival_count"] == 0
    assert snapshot["pre_auth_drop_count"] == 0
    assert snapshot["post_auth_drop_count"] == 0
    assert snapshot["hmac_rejected_count"] == 0
    assert snapshot["limiting_started_at_s"] is None
    assert snapshot["recovered_at_s"] is None
    assert snapshot["buckets"] == {
        "receiver_global": None,
        "ingress": [],
        "authenticated_devices": [],
    }
    assert runtime.rules[1]._flood_defense._pre_auth_reservations == {}
    assert runtime.observation(1)["defense_resource"]["dos_defense_state"] == "NORMAL"
