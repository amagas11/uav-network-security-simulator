from __future__ import annotations

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.events import find_forbidden_online_fields


def _attack(family: str, subtype: str, **overrides) -> AttackPlan:
    values = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.4,
        "end_s": 1.6,
    }
    values.update(overrides)
    return AttackPlan(**values)


def _security_results(runtime: PlatformRuntime, message_id: str) -> list[str]:
    return [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT" and event["message_id"] == message_id
    ]


def test_immediate_replay_is_detected_and_preserves_message_with_new_events():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.8, auto_traffic=False, rx_service_per_step=8),
        run_id="replay-immediate",
    )
    runtime.schedule_attack(
        _attack(
            "REPLAY",
            "IMMEDIATE_REPLAY",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"max_capture_age_s": 0.6},
        )
    )
    message_id = runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 100.0}, session_id="session-live"
    )
    runtime.run_to_completion()

    label = runtime.attack_scheduler.labels()[0]
    assert label["attack_subtype"] == "IMMEDIATE_REPLAY"
    assert label["truth"]["replayed_message_id"] == message_id
    assert label["truth"]["replay_mode"] == "IMMEDIATE_REPLAY"
    assert label["truth"]["replay_count"] == 1
    assert label["truth"]["replay_time_s"] - label["truth"]["capture_time_s"] <= 0.4
    assert "DUPLICATE" in _security_results(runtime, message_id)

    transmissions = [
        event
        for event in runtime.events
        if event["event_type"] == "TX" and event["message_id"] == message_id
    ]
    assert len(transmissions) >= 2
    assert len({event["event_id"] for event in transmissions}) == len(transmissions)
    all_ids = [event["event_id"] for event in runtime.events]
    assert len(all_ids) == len(set(all_ids))


def test_delayed_replay_uses_simulation_delay_and_is_detected():
    runtime = PlatformRuntime(
        RunConfig(duration_s=2.2, auto_traffic=False, rx_service_per_step=8),
        run_id="replay-delayed",
    )
    runtime.schedule_attack(
        _attack(
            "REPLAY",
            "DELAYED_REPLAY",
            impact_start_s=0.2,
            end_s=2.0,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"delay_s": 0.8},
        )
    )
    message_id = runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 100.0}, session_id="session-live"
    )
    runtime.run_to_completion()

    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["replay_count"] == 1
    assert label["truth"]["replay_time_s"] - label["truth"]["capture_time_s"] >= 0.8
    assert label["truth"]["replayed_message_id"] == message_id
    assert "DUPLICATE" in _security_results(runtime, message_id)


def test_old_session_replay_returns_wrong_session():
    runtime = PlatformRuntime(
        RunConfig(duration_s=2.0, auto_traffic=False, rx_service_per_step=8),
        run_id="replay-old-session",
    )
    runtime.schedule_attack(
        _attack(
            "REPLAY",
            "OLD_SESSION_REPLAY",
            impact_start_s=0.8,
            end_s=1.8,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"stale_session_id": "session-old"},
        )
    )
    old_message_id = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0},
        session_id="session-old",
        sequence_no=1,
    )
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.rotate_security_session(
        2,
        1,
        old_session_id="session-old",
        new_session_id="session-current",
    )
    runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 101.0},
        session_id="session-current",
        sequence_no=1,
    )
    while runtime.state.value == "RUNNING":
        runtime.step()

    assert "WRONG_SESSION" in _security_results(runtime, old_message_id)
    assert runtime.attack_scheduler.labels()[0]["truth"]["replayed_message_id"] == old_message_id


def test_legal_out_of_order_is_accepted_inside_reorder_window():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
        ),
        run_id="normal-reorder",
    )
    for sequence in (100, 102, 101):
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": float(sequence)},
            session_id="reorder-session",
            sequence_no=sequence,
        )
    runtime.run_to_completion()
    online_session = runtime.observable_session_id("reorder-session")

    auth_events = [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["packet"]["session_id"] == online_session
    ]
    assert [event["online_features"]["packet"]["sequence_no"] for event in auth_events] == [100, 102, 101]
    assert all(
        event["online_features"]["security_state"]["replay_check_result"] == "PASS"
        for event in auth_events
    )
    assert not [
        event
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("model_result", {}).get("predicted_label") == "REPLAY"
    ]


def test_replay_state_isolated_by_sender_receiver_session_and_key_epoch():
    runtime = PlatformRuntime(
        RunConfig(
            node_count=5,
            duration_s=1.4,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
        ),
        run_id="replay-isolation",
    )
    first = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 1}, session_id="s-a", sequence_no=7)
    second = runtime.queue_message(3, 1, "TELEMETRY", {"altitude_m": 2}, session_id="s-b", sequence_no=7)
    third = runtime.queue_message(1, 4, "MISSION_COMMAND", {"cmd": "HOVER"}, session_id="s-c", sequence_no=7)
    runtime.run_to_completion()

    for message_id in (first, second, third):
        assert _security_results(runtime, message_id) == ["PASS"]


def test_new_valid_session_does_not_inherit_old_replay_state():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, rx_service_per_step=8),
        run_id="new-session",
    )
    old_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 1}, session_id="old", sequence_no=1)
    runtime.start()
    runtime.step()
    runtime.step()
    new_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 2}, session_id="new", sequence_no=1)
    while runtime.state.value == "RUNNING":
        runtime.step()
    assert _security_results(runtime, old_id) == ["PASS"]
    assert _security_results(runtime, new_id) == ["PASS"]


def test_new_key_epoch_has_fresh_sequence_window_and_invalidates_old_epoch():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.8, auto_traffic=False, rx_service_per_step=8),
        run_id="replay-key-epoch-lifecycle",
    )
    first = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 1},
        session_id="epoch-session",
        sequence_no=9,
    )
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.nodes[2].key_epoch = 2
    second = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 2},
        session_id="epoch-session",
        sequence_no=9,
    )
    while runtime.state.value == "RUNNING":
        runtime.step()

    assert _security_results(runtime, first) == ["PASS"]
    assert _security_results(runtime, second) == ["PASS"]
    active = runtime.rules[1]._active_sessions[(2, 1, 2)]
    assert active == {("epoch-session", "2")}
    assert (2, 1, 2, "epoch-session", "1") in runtime.rules[1]._stale_sessions


def test_runtime_reset_clears_replay_state():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8),
        run_id="before-reset",
    )
    message_ids = [
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 1}, session_id="s", sequence_no=1)
        for _ in range(2)
    ]
    runtime.run_to_completion()
    assert _security_results(runtime, message_ids[0]) == ["PASS"]
    assert _security_results(runtime, message_ids[1]) == ["DUPLICATE"]

    runtime.reset()
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 1}, session_id="s", sequence_no=1)
    runtime.run_to_completion()
    assert _security_results(runtime, message_id) == ["PASS"]


def test_fdi_abrupt_change_is_pre_crypto_and_legitimately_authenticated():
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, auto_traffic=False), run_id="fdi-abrupt")
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_ABRUPT_CHANGE",
            impact_start_s=0.0,
            end_s=0.8,
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "absolute_offset": 50.0},
        )
    )
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True)
    runtime.run_to_completion()

    label = runtime.attack_scheduler.labels()[0]
    change = label["truth"]["modifications"][0]
    assert change["original_value"]["altitude_m"] == 100.0
    assert change["modified_value"]["altitude_m"] == 150.0
    assert label["truth"]["injection_stage"] == "POST_HMAC_PRE_TRANSMISSION"
    auth = [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT" and event["message_id"] == message_id
    ]
    assert auth
    assert all(
        event["online_features"]["security_state"]["application_hmac_result"]
        == "FAIL"
        for event in auth
    )
    assert label["outcome"]["malicious_content_executed"] is False


def test_fdi_gradual_drift_accumulates_105_110_115_from_current_baseline():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="fdi-drift",
    )
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_GRADUAL_DRIFT",
            impact_start_s=0.0,
            end_s=0.8,
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "delta_per_step": 5.0},
        )
    )
    for baseline in (100.0, 100.0, 100.0):
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": baseline}, sensitive=True)
    runtime.run_to_completion()
    modifications = runtime.attack_scheduler.labels()[0]["truth"]["modifications"]
    assert [item["modified_value"]["altitude_m"] for item in modifications] == [105.0, 110.0, 115.0]


def test_fdi_drift_adds_to_each_current_legitimate_value():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="fdi-moving-baseline",
    )
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_GRADUAL_DRIFT",
            impact_start_s=0.0,
            end_s=0.6,
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "delta_per_step": 5.0},
        )
    )
    for baseline in (100.0, 102.0, 104.0):
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": baseline})
    runtime.run_to_completion()
    changes = runtime.attack_scheduler.labels()[0]["truth"]["modifications"]
    assert [item["modified_value"]["altitude_m"] for item in changes] == [105.0, 112.0, 119.0]


def test_fdi_reset_and_independent_attack_plan_do_not_share_drift():
    runtime = PlatformRuntime(RunConfig(duration_s=1.2, auto_traffic=False), run_id="fdi-independent")
    for start, end in ((0.0, 0.4), (0.4, 1.0)):
        runtime.schedule_attack(
            _attack(
                "FDI",
                "TELEMETRY_GRADUAL_DRIFT",
                scheduled_start_s=start,
                impact_start_s=start,
                end_s=end,
                attacker_node_id=2,
                target_node_ids=[1],
                parameters={"field": "altitude_m", "delta_per_step": 5.0},
            )
        )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    while runtime.state.value == "RUNNING":
        runtime.step()
    labels = runtime.attack_scheduler.labels()
    assert labels[0]["truth"]["modifications"][0]["modified_value"]["altitude_m"] == 105.0
    assert labels[1]["truth"]["modifications"][0]["modified_value"]["altitude_m"] == 105.0

    runtime.reset()
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_GRADUAL_DRIFT",
            impact_start_s=0.0,
            end_s=0.8,
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "delta_per_step": 5.0},
        )
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["truth"]["modifications"][0]["modified_value"]["altitude_m"] == 105.0


def test_fdi_original_and_modified_values_remain_truth_only():
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False), run_id="fdi-boundary")
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_ABRUPT_CHANGE",
            impact_start_s=0.0,
            end_s=0.6,
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "replacement": 150.0},
        )
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["truth"]["modifications"]
    assert all(not find_forbidden_online_fields(event["online_features"]) for event in runtime.events)
