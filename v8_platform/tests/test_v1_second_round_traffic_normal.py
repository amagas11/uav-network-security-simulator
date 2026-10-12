from __future__ import annotations

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.normal import NormalDisturbancePlan


def _rx_events(runtime: PlatformRuntime, observer_id: int) -> list[dict]:
    return [
        event
        for event in runtime.events
        if event["observer_node_id"] == observer_id
        and event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
    ]


def _max_rate(runtime: PlatformRuntime, observer_id: int) -> float:
    values = [
        event["online_features"]["traffic"]["packet_rate_pps"]
        for event in runtime.events
        if event["observer_node_id"] == observer_id
        and event["online_features"]["traffic"]["packet_rate_pps"] is not None
    ]
    return max(float(value) for value in values) if values else 0.0


def _normal(kind: str, **overrides) -> NormalDisturbancePlan:
    values = {
        "disturbance_type": kind,
        "start_s": 0.2,
        "end_s": 1.2,
        "target_node_ids": [1],
        "target_link_ids": [],
        "parameters": {},
    }
    values.update(overrides)
    return NormalDisturbancePlan(**values)


def test_local_inter_arrival_and_rolling_rates_are_real_values():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="traffic-values",
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 101.0})
    while runtime.state.value == "RUNNING":
        runtime.step()

    arrivals = [
        event
        for event in _rx_events(runtime, 1)
        if event["online_features"]["packet"]["packet_type"] == "TELEMETRY"
    ]
    assert len(arrivals) >= 2
    assert arrivals[0]["online_features"]["packet"]["inter_arrival_s"] is None
    assert arrivals[1]["online_features"]["packet"]["inter_arrival_s"] is not None
    assert arrivals[1]["online_features"]["packet"]["inter_arrival_s"] > 0
    assert arrivals[1]["online_features"]["traffic"]["packet_rate_pps"] > 0
    assert arrivals[1]["online_features"]["traffic"]["byte_rate_Bps"] > 0
    assert arrivals[1]["online_features"]["traffic"]["latency_ms"] is not None
    assert arrivals[1]["online_features"]["traffic"]["throughput_mbps"] > 0


def test_flooding_increases_observer_local_packet_rate():
    baseline = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, tx_service_per_step=64, rx_service_per_step=64),
        run_id="traffic-baseline",
    )
    baseline.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    baseline.run_to_completion()

    flooded = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, tx_service_per_step=64, rx_service_per_step=64),
        run_id="traffic-flood",
    )
    flooded.schedule_attack(
        {
            "attack_family": "DOS",
            "attack_subtype": "FLOODING",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 1.0,
            "attacker_node_id": 2,
            "target_node_ids": [1],
            "intensity": {"value": 50.0, "unit": "pps"},
        }
    )
    flooded.run_to_completion()
    assert _max_rate(flooded, 1) >= 5 * _max_rate(baseline, 1)


def test_duplicate_and_sequence_gap_are_observer_visible_and_distinct():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="traffic-sequences",
    )
    for sequence in (1, 1, 3):
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 100.0},
            session_id="traffic-seq",
            sequence_no=sequence,
        )
    runtime.run_to_completion()
    arrivals = _rx_events(runtime, 1)
    assert max(event["online_features"]["traffic"]["duplicate_count"] for event in arrivals) >= 1
    assert max(event["online_features"]["traffic"]["sequence_gap_count"] for event in arrivals) >= 1


def test_local_statistics_do_not_leak_to_unrelated_observer():
    runtime = PlatformRuntime(
        RunConfig(node_count=5, duration_s=1.0, auto_traffic=False, tx_service_per_step=16, rx_service_per_step=16),
        run_id="traffic-locality",
    )
    for _ in range(6):
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    observer_one = _max_rate(runtime, 1)
    observer_four = _max_rate(runtime, 4)
    assert observer_one > 0
    assert observer_four == 0


def test_reset_clears_traffic_accumulator():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="traffic-reset",
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert _max_rate(runtime, 1) > 0
    runtime.reset()
    assert runtime.local_traffic_snapshot(1)["packet_rate_pps"] == 0.0
    assert runtime.local_traffic_snapshot(1)["duplicate_count"] == 0
    assert runtime.local_traffic_snapshot(1)["sequence_gap_count"] == 0


def test_legitimate_traffic_burst_is_high_rate_without_attack_label():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, tx_service_per_step=64, rx_service_per_step=64),
        run_id="normal-burst",
    )
    runtime.schedule_normal_disturbance(
        _normal(
            "NORMAL_TRAFFIC_BURST",
            target_node_ids=[1],
            parameters={"source_node_id": 2, "packet_rate_pps": 50.0, "packet_size_bytes": 256},
        )
    )
    runtime.run_to_completion()
    assert _max_rate(runtime, 1) >= 20
    assert runtime.attack_scheduler.labels() == []


def test_natural_low_snr_and_packet_loss_have_no_attack_truth():
    low_snr = PlatformRuntime(RunConfig(duration_s=1.2, auto_traffic=False), run_id="normal-low-snr")
    low_snr.schedule_normal_disturbance(
        _normal(
            "NORMAL_LOW_SNR",
            target_node_ids=[],
            target_link_ids=["link-2-1"],
            parameters={"attenuation_db": 55.0},
        )
    )
    low_snr.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    low_snr.run_to_completion()
    snr_values = [
        event["online_features"]["phy"]["snr_db"]
        for event in _rx_events(low_snr, 1)
        if event["online_features"]["phy"]["snr_db"] is not None
    ]
    assert snr_values and min(snr_values) < 0
    assert low_snr.attack_scheduler.labels() == []

    loss = PlatformRuntime(RunConfig(duration_s=1.0, auto_traffic=False), run_id="normal-loss")
    loss.schedule_normal_disturbance(
        _normal(
            "NORMAL_PACKET_LOSS",
            target_node_ids=[],
            target_link_ids=["link-2-1"],
            parameters={"loss_probability": 1.0},
            end_s=0.8,
        )
    )
    loss.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    loss.run_to_completion()
    assert any(event["event_type"] == "RX_FAILURE" for event in loss.events)
    assert loss.attack_scheduler.labels() == []
    assert loss.evaluation_view()["attack_episode_count"] == 0


def test_normal_out_of_order_is_delivered_without_replay_label_or_alarm():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, tx_service_per_step=16, rx_service_per_step=16),
        run_id="normal-ordered-control",
    )
    runtime.schedule_normal_disturbance(
        _normal(
            "NORMAL_OUT_OF_ORDER",
            parameters={
                "source_node_id": 2,
                "sequence_numbers": [100, 102, 101],
                "session_id": "normal-reorder",
            },
        )
    )
    runtime.run_to_completion()
    online_session = runtime.observable_session_id("normal-reorder")
    results = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["packet"]["session_id"] == online_session
    ]
    assert results == ["PASS", "PASS", "PASS"]
    assert runtime.attack_scheduler.labels() == []
    assert not [
        event
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("model_result", {}).get("predicted_label") == "REPLAY"
    ]


def test_normal_state_change_and_congestion_are_configurable_non_attacks():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, tx_service_per_step=2, rx_service_per_step=1),
        run_id="normal-state-congestion",
    )
    runtime.schedule_normal_disturbance(
        _normal(
            "NORMAL_STATE_CHANGE",
            target_node_ids=[2],
            parameters={"battery_pct": 72.0, "flight_state": "HOVERING"},
        )
    )
    runtime.schedule_normal_disturbance(
        _normal(
            "NORMAL_CONGESTION",
            target_node_ids=[1],
            parameters={"source_node_id": 2, "packet_rate_pps": 20.0},
        )
    )
    runtime.run_to_completion()
    assert runtime.nodes[2].battery_pct == 72.0
    assert runtime.nodes[2].flight_state == "HOVERING"
    assert any(
        event["event_type"] == "NODE_STATE"
        and event["observer_node_id"] == 2
        and event["online_features"]["node_state"]["battery_pct"] == 72.0
        for event in runtime.events
    )
    assert _max_rate(runtime, 1) > 0
    assert runtime.attack_scheduler.labels() == []
