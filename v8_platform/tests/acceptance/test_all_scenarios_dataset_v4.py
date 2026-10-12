from __future__ import annotations

import json
from pathlib import Path

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.events import find_label_proxies
from swarm_sim.validation import DatasetValidator


NORMAL_SCENARIOS = [
    "NORMAL_BASELINE",
    "NORMAL_LOW_SNR",
    "NORMAL_PACKET_LOSS",
    "NORMAL_TRAFFIC_BURST",
    "NORMAL_OUT_OF_ORDER",
    "NORMAL_STATE_CHANGE",
    "NORMAL_CONGESTION",
]
ATTACK_SCENARIOS = [
    "SPOOFING",
    "EAVESDROPPING",
    "DOS_FLOODING",
    "FDI_COMMAND_REPLACEMENT",
    "FDI_TELEMETRY_ABRUPT_CHANGE",
    "FDI_TELEMETRY_GRADUAL_DRIFT",
    "FDI_OUT_OF_RANGE_VALUE",
    "FDI_LOGICAL_INCONSISTENCY",
    "REPLAY_IMMEDIATE_REPLAY",
    "REPLAY_DELAYED_REPLAY",
    "REPLAY_OLD_SESSION_REPLAY",
]
ALL_SCENARIOS = NORMAL_SCENARIOS + ATTACK_SCENARIOS


def _runtime(name: str) -> PlatformRuntime:
    duration = 1.4 if name.startswith("REPLAY_") else 1.0
    return PlatformRuntime(
        RunConfig(
            seed=4404,
            duration_s=duration,
            step_s=0.2,
            auto_traffic=False,
            queue_capacity=64,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        run_id=f"v4-matrix-{name.lower()}",
    )


def _normal_plan(name: str) -> dict:
    base = {
        "disturbance_type": name,
        "start_s": 0.0,
        "end_s": 0.8,
        "target_node_ids": [],
        "target_link_ids": [],
        "parameters": {},
    }
    if name == "NORMAL_LOW_SNR":
        base["target_link_ids"] = ["link-2-1"]
        base["parameters"] = {"attenuation_db": 35.0}
    elif name == "NORMAL_PACKET_LOSS":
        base["target_link_ids"] = ["link-2-1"]
        base["parameters"] = {"loss_probability": 0.4}
    elif name in {"NORMAL_TRAFFIC_BURST", "NORMAL_CONGESTION"}:
        base["target_node_ids"] = [1]
        base["parameters"] = {
            "source_node_id": 2,
            "packet_rate_pps": 20.0,
            "packet_type": "STATUS",
        }
        if name == "NORMAL_CONGESTION":
            base["parameters"]["busy_ratio_addition"] = 0.2
    elif name == "NORMAL_OUT_OF_ORDER":
        base["target_node_ids"] = [1]
        base["parameters"] = {
            "source_node_id": 2,
            "sequence_numbers": [100, 102, 101],
            "session_id": "matrix-reorder",
        }
    elif name == "NORMAL_STATE_CHANGE":
        base["target_node_ids"] = [2]
        base["parameters"] = {"battery_pct": 70.0, "flight_state": "HOVERING"}
    return base


def _attack_plan(name: str) -> dict:
    if name.startswith("DOS_"):
        family, subtype = "DOS", name.removeprefix("DOS_")
    elif name.startswith("FDI_"):
        family, subtype = "FDI", name.removeprefix("FDI_")
    elif name.startswith("REPLAY_"):
        family, subtype = "REPLAY", name.removeprefix("REPLAY_")
    elif name == "SPOOFING":
        family, subtype = "SPOOFING", "UNKNOWN_ID"
    elif name == "EAVESDROPPING":
        family, subtype = "EAVESDROPPING", "PASSIVE_CAPTURE"
    else:  # pragma: no cover - guarded by the scenario matrix
        raise ValueError(name)
    plan = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 0.8,
        "attacker_node_id": 2 if family == "FDI" else -1,
        "target_node_ids": [1],
        "target_link_ids": [],
        "intensity": {},
        "parameters": {},
    }
    if name == "DOS_FLOODING":
        plan["intensity"] = {"value": 30.0, "unit": "pps"}
        plan["parameters"] = {"packet_type": "STATUS", "packet_size_bytes": 128}
    elif family == "FDI":
        plan["impact_start_s"] = 0.0
        if subtype == "COMMAND_REPLACEMENT":
            plan["parameters"] = {"replacement": {"cmd": "LAND", "altitude_m": 0.0}}
        elif subtype == "TELEMETRY_ABRUPT_CHANGE":
            plan["parameters"] = {"field": "altitude_m", "absolute_offset": 50.0}
        elif subtype == "TELEMETRY_GRADUAL_DRIFT":
            plan["parameters"] = {"field": "altitude_m", "delta_per_step": 5.0}
        elif subtype == "OUT_OF_RANGE_VALUE":
            plan["parameters"] = {"field": "altitude_m", "value": 5000.0}
        elif subtype == "LOGICAL_INCONSISTENCY":
            plan["parameters"] = {"altitude_m": 120.0}
    elif name == "EAVESDROPPING":
        plan["target_link_ids"] = ["link-2-1"]
        plan["parameters"] = {"receiver_radius_m": 500.0}
    elif family == "REPLAY":
        plan["attacker_node_id"] = -1
        plan["impact_start_s"] = 0.6 if subtype != "DELAYED_REPLAY" else 0.2
        plan["end_s"] = 1.2
        if subtype == "DELAYED_REPLAY":
            plan["parameters"] = {"delay_s": 0.6}
        elif subtype == "OLD_SESSION_REPLAY":
            plan["impact_start_s"] = 0.8
            plan["parameters"] = {"stale_session_id": "matrix-old"}
    return plan


def _prepare(runtime: PlatformRuntime, scenario: str) -> None:
    if scenario == "NORMAL_BASELINE":
        runtime.queue_message(2, 1, "STATUS", {"value": 1})
        return
    if scenario.startswith("NORMAL_"):
        runtime.schedule_normal_disturbance(_normal_plan(scenario))
        if scenario in {"NORMAL_LOW_SNR", "NORMAL_PACKET_LOSS"}:
            runtime.queue_message(2, 1, "STATUS", {"value": 1})
        return

    plan = _attack_plan(scenario)
    runtime.schedule_attack(plan)
    if scenario == "EAVESDROPPING":
        runtime.queue_message(2, 1, "STATUS", {"value": 1}, encrypt=False)
    elif scenario.startswith("FDI_"):
        packet_type = "MISSION_COMMAND" if scenario.endswith("COMMAND_REPLACEMENT") else "TELEMETRY"
        payload = {"cmd": "HOVER", "altitude_m": 100.0, "flight_state": "FLYING"}
        count = 3 if scenario.endswith("GRADUAL_DRIFT") else 1
        for _ in range(count):
            runtime.queue_message(2, 1, packet_type, payload, sensitive=True)
    elif scenario.startswith("REPLAY_"):
        session = "matrix-old" if scenario.endswith("OLD_SESSION_REPLAY") else "matrix-replay"
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}, session_id=session, sequence_no=1)


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_every_required_v4_scenario_exports_a_valid_leak_free_dataset(tmp_path: Path, scenario: str):
    runtime = _runtime(scenario)
    _prepare(runtime, scenario)
    if scenario == "REPLAY_OLD_SESSION_REPLAY":
        runtime.start()
        runtime.step()
        runtime.step()
        runtime.rotate_security_session(2, 1, old_session_id="matrix-old", new_session_id="matrix-new")
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 101.0}, session_id="matrix-new", sequence_no=1)
    runtime.run_to_completion()
    root = tmp_path / scenario.lower()
    runtime.export_dataset(root)
    report = DatasetValidator().validate(root)
    assert report.valid, (scenario, report.errors)
    assert len({event["event_id"] for event in runtime.events}) == len(runtime.events)
    assert all(not find_label_proxies(event) for event in runtime.events)
    assert runtime.run_record()["security_providers"]["key_provider"]["status"] == "TEST_ONLY_NOT_SKG"
    if scenario.startswith("NORMAL_"):
        assert runtime.attack_scheduler.labels() == []
        assert runtime.run_record()["normal_disturbance_plan"] or scenario == "NORMAL_BASELINE"
    else:
        assert len(runtime.attack_scheduler.labels()) == 1
        assert runtime.run_record()["profiles"]["attack_plan_id"]


def test_hard_negative_packet_types_overlap_without_answer_literals():
    burst = _runtime("NORMAL_TRAFFIC_BURST")
    flood = _runtime("DOS_FLOODING")
    _prepare(burst, "NORMAL_TRAFFIC_BURST")
    _prepare(flood, "DOS_FLOODING")
    burst.run_to_completion()
    flood.run_to_completion()
    packet_types = lambda runtime: {
        event["online_features"]["packet"]["packet_type"]
        for event in runtime.events
        if event["message_id"] is not None
    }
    assert packet_types(burst) & packet_types(flood) == {"STATUS"}
    assert "NORMAL_" not in json.dumps(burst.events)
    assert "FLOOD" not in json.dumps(
        [event["online_features"] for event in flood.events]
    )

