from __future__ import annotations

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.leakage import DatasetLeakageAudit


def _runtime(run_id: str, *, duration_s: float = 1.2) -> PlatformRuntime:
    return PlatformRuntime(
        RunConfig(
            seed=5501,
            duration_s=duration_s,
            auto_traffic=False,
            queue_capacity=96,
            tx_service_per_step=32,
            rx_service_per_step=32,
        ),
        run_id=run_id,
    )


def _burst(*, attack: bool) -> PlatformRuntime:
    runtime = _runtime("v5-hardneg-flood" if attack else "v5-hardneg-burst")
    common = {"packet_type": "STATUS", "packet_size_bytes": 192}
    if attack:
        runtime.schedule_attack(
            {
                "attack_family": "DOS",
                "attack_subtype": "FLOODING",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.0,
                "end_s": 0.8,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "intensity": {"value": 24.0, "unit": "pps"},
                "parameters": common,
            }
        )
    else:
        runtime.schedule_normal_disturbance(
            {
                "disturbance_type": "NORMAL_TRAFFIC_BURST",
                "start_s": 0.0,
                "end_s": 0.8,
                "target_node_ids": [1],
                "parameters": {
                    "source_node_id": 2,
                    "packet_rate_pps": 20.0,
                    **common,
                },
            }
        )
    runtime.run_to_completion()
    return runtime


def test_normal_burst_and_flood_share_type_payload_schema_and_size_support():
    normal = _burst(attack=False)
    attack = _burst(attack=True)
    report = DatasetLeakageAudit.compare_hard_negative_pair(
        normal.events,
        attack.events,
        pair_name="NORMAL_TRAFFIC_BURST_vs_DOS_FLOODING",
    )
    assert report.passed, report.errors
    assert report.statistics["packet_type_overlap"] == ["STATUS"]
    assert report.statistics["packet_size_overlap"] is True
    assert report.statistics["normal_size_range"] == [192, 192]
    assert report.statistics["attack_size_range"] == [192, 192]


def test_legal_out_of_order_and_replay_use_normal_business_packet_space():
    normal = _runtime("v5-hardneg-reorder", duration_s=1.4)
    normal.schedule_normal_disturbance(
        {
            "disturbance_type": "NORMAL_OUT_OF_ORDER",
            "start_s": 0.0,
            "end_s": 0.8,
            "target_node_ids": [1],
            "parameters": {
                "source_node_id": 2,
                "sequence_numbers": [100, 102, 101],
                "session_id": "hardneg-seq",
                "packet_type": "STATUS",
            },
        }
    )
    replay = _runtime("v5-hardneg-replay", duration_s=1.4)
    replay.schedule_attack(
        {
            "attack_family": "REPLAY",
            "attack_subtype": "IMMEDIATE_REPLAY",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.6,
            "end_s": 1.2,
            "attacker_node_id": -1,
            "target_node_ids": [1],
        }
    )
    replay.queue_message(
        2,
        1,
        "STATUS",
        {"altitude_m": 100.0},
        session_id="hardneg-seq",
        sequence_no=100,
    )
    normal.run_to_completion()
    replay.run_to_completion()
    report = DatasetLeakageAudit.compare_hard_negative_pair(
        normal.events,
        replay.events,
        pair_name="LEGAL_OUT_OF_ORDER_vs_REPLAY",
        require_size_overlap=False,
    )
    assert report.passed, report.errors
    normal_checks = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in normal.events
        if event["event_type"] == "AUTH_RESULT" and event["message_id"] is not None
    ]
    assert normal_checks and set(normal_checks) == {"PASS"}


def test_normal_state_change_and_fdi_have_no_scenario_name_shortcut():
    normal = _runtime("v5-hardneg-state")
    normal.schedule_normal_disturbance(
        {
            "disturbance_type": "NORMAL_STATE_CHANGE",
            "start_s": 0.0,
            "end_s": 0.8,
            "target_node_ids": [2],
            "parameters": {"battery_pct": 72.0, "flight_state": "HOVERING"},
        }
    )
    fdi = _runtime("v5-hardneg-fdi")
    fdi.schedule_attack(
        {
            "attack_family": "FDI",
            "attack_subtype": "LOGICAL_INCONSISTENCY",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.0,
            "end_s": 0.8,
            "attacker_node_id": 2,
            "target_node_ids": [1],
        }
    )
    fdi.queue_message(
        2,
        1,
        "TELEMETRY",
        {
            "altitude_m": 100.0,
            "battery_pct": 72.0,
            "flight_state": "FLYING",
        },
    )
    normal.run_to_completion()
    fdi.run_to_completion()
    assert DatasetLeakageAudit.audit_events(normal.events).passed
    assert DatasetLeakageAudit.audit_events(fdi.events).passed
    assert any(
        event["event_type"] == "TX"
        and event["online_features"]["packet"]["packet_type"] == "TELEMETRY"
        for event in normal.events
    )
    report = DatasetLeakageAudit.compare_hard_negative_pair(
        normal.events,
        fdi.events,
        pair_name="NORMAL_STATE_CHANGE_vs_FDI",
        # A post-HMAC FDI frame is rejected before its untrusted payload is
        # exposed as online payload_numeric. That is the intended auth gate,
        # not an attack-label shortcut.
        require_payload_overlap=False,
        require_size_overlap=False,
    )
    assert report.passed, report.errors
    assert "TELEMETRY" in report.statistics["packet_type_overlap"]
