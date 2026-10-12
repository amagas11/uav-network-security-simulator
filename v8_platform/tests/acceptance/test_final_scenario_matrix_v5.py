from __future__ import annotations

from pathlib import Path

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.validation import DatasetValidator


SCENARIOS = [
    "NORMAL_BASELINE",
    "NORMAL_LOW_SNR",
    "NORMAL_PACKET_LOSS",
    "NORMAL_TRAFFIC_BURST",
    "NORMAL_OUT_OF_ORDER",
    "NORMAL_STATE_CHANGE",
    "NORMAL_CONGESTION",
    "SPOOFING_UNKNOWN_ID",
    "SPOOFING_KNOWN_ID_CONFLICT",
    "EAVESDROPPING_PASSIVE",
    "DOS_FLOODING",
    "FDI_COMMAND_REPLACEMENT",
    "FDI_ABRUPT_CHANGE",
    "FDI_GRADUAL_DRIFT",
    "FDI_OUT_OF_RANGE",
    "FDI_LOGICAL_INCONSISTENCY",
    "REPLAY_IMMEDIATE",
    "REPLAY_DELAYED",
    "REPLAY_OLD_SESSION",
]


def _runtime(name: str) -> PlatformRuntime:
    return PlatformRuntime(
        RunConfig(
            seed=5505,
            duration_s=1.4,
            step_s=0.2,
            auto_traffic=False,
            queue_capacity=96,
            tx_service_per_step=32,
            rx_service_per_step=32,
        ),
        run_id=f"v5-final-{name.lower()}",
    )


def _normal(runtime: PlatformRuntime, name: str) -> None:
    if name == "NORMAL_BASELINE":
        runtime.queue_message(2, 1, "STATUS", {"value": 1})
        return
    plan = {
        "disturbance_type": name,
        "start_s": 0.0,
        "end_s": 0.8,
        "target_node_ids": [],
        "target_link_ids": [],
        "parameters": {},
    }
    if name == "NORMAL_LOW_SNR":
        plan["target_link_ids"] = ["link-2-1"]
        plan["parameters"] = {"attenuation_db": 34.0}
        runtime.queue_message(2, 1, "STATUS", {"value": 1})
    elif name == "NORMAL_PACKET_LOSS":
        plan["target_link_ids"] = ["link-2-1"]
        plan["parameters"] = {"loss_probability": 0.4}
        runtime.queue_message(2, 1, "STATUS", {"value": 1})
    elif name in {"NORMAL_TRAFFIC_BURST", "NORMAL_CONGESTION"}:
        plan["target_node_ids"] = [1]
        plan["parameters"] = {
            "source_node_id": 2,
            "packet_rate_pps": 20.0,
            "packet_type": "STATUS",
            "packet_size_bytes": 192,
        }
        if name == "NORMAL_CONGESTION":
            plan["parameters"]["busy_ratio_addition"] = 0.2
    elif name == "NORMAL_OUT_OF_ORDER":
        plan["target_node_ids"] = [1]
        plan["parameters"] = {
            "source_node_id": 2,
            "sequence_numbers": [100, 102, 101],
            "session_id": "v5-normal-reorder",
        }
    elif name == "NORMAL_STATE_CHANGE":
        plan["target_node_ids"] = [2]
        plan["parameters"] = {"battery_pct": 71.0, "flight_state": "HOVERING"}
    runtime.schedule_normal_disturbance(plan)


def _attack(runtime: PlatformRuntime, name: str) -> None:
    plan = {
        "attack_family": "SPOOFING",
        "attack_subtype": "UNKNOWN_ID",
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 0.8,
        "attacker_node_id": -1,
        "target_node_ids": [1],
        "target_link_ids": [],
        "intensity": {},
        "parameters": {},
    }
    if name.startswith("SPOOFING_"):
        plan["attack_subtype"] = name.removeprefix("SPOOFING_")
        if name.endswith("KNOWN_ID_CONFLICT"):
            plan["parameters"] = {"claimed_src_id": 0}
    elif name == "EAVESDROPPING_PASSIVE":
        plan.update(
            attack_family="EAVESDROPPING",
            attack_subtype="PASSIVE_CAPTURE",
            target_link_ids=["link-2-1"],
            parameters={"receiver_radius_m": 500.0},
        )
        runtime.queue_message(2, 1, "STATUS", {"value": 1}, encrypt=False)
    elif name == "DOS_FLOODING":
        plan.update(
            attack_family="DOS",
            attack_subtype="FLOODING",
            attacker_node_id=-1,
            impact_start_s=0.0,
            intensity={"value": 24.0, "unit": "pps"},
            parameters={"packet_type": "STATUS", "packet_size_bytes": 192},
        )
    elif name.startswith("FDI_"):
        subtype = {
            "FDI_COMMAND_REPLACEMENT": "COMMAND_REPLACEMENT",
            "FDI_ABRUPT_CHANGE": "TELEMETRY_ABRUPT_CHANGE",
            "FDI_GRADUAL_DRIFT": "TELEMETRY_GRADUAL_DRIFT",
            "FDI_OUT_OF_RANGE": "OUT_OF_RANGE_VALUE",
            "FDI_LOGICAL_INCONSISTENCY": "LOGICAL_INCONSISTENCY",
        }[name]
        parameters = {
            "COMMAND_REPLACEMENT": {"replacement": {"cmd": "LAND", "altitude_m": 0.0}},
            "TELEMETRY_ABRUPT_CHANGE": {"field": "altitude_m", "absolute_offset": 50.0},
            "TELEMETRY_GRADUAL_DRIFT": {"field": "altitude_m", "delta_per_step": 5.0},
            "OUT_OF_RANGE_VALUE": {"field": "altitude_m", "value": 5000.0},
            "LOGICAL_INCONSISTENCY": {"altitude_m": 120.0},
        }[subtype]
        plan.update(
            attack_family="FDI",
            attack_subtype=subtype,
            attacker_node_id=2,
            impact_start_s=0.0,
            parameters=parameters,
        )
        packet_type = "MISSION_COMMAND" if subtype == "COMMAND_REPLACEMENT" else "TELEMETRY"
        count = 3 if subtype == "TELEMETRY_GRADUAL_DRIFT" else 1
        for _ in range(count):
            runtime.queue_message(
                2,
                1,
                packet_type,
                {"cmd": "HOVER", "altitude_m": 100.0, "flight_state": "FLYING"},
                sensitive=True,
            )
    elif name.startswith("REPLAY_"):
        subtype = {
            "REPLAY_IMMEDIATE": "IMMEDIATE_REPLAY",
            "REPLAY_DELAYED": "DELAYED_REPLAY",
            "REPLAY_OLD_SESSION": "OLD_SESSION_REPLAY",
        }[name]
        plan.update(
            attack_family="REPLAY",
            attack_subtype=subtype,
            impact_start_s=0.6 if subtype != "OLD_SESSION_REPLAY" else 0.8,
            end_s=1.2,
            parameters=(
                {"delay_s": 0.4}
                if subtype == "DELAYED_REPLAY"
                else ({"stale_session_id": "v5-old"} if subtype == "OLD_SESSION_REPLAY" else {})
            ),
        )
        session = "v5-old" if subtype == "OLD_SESSION_REPLAY" else "v5-replay"
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 100.0},
            session_id=session,
            sequence_no=1,
        )
    runtime.schedule_attack(plan)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_v5_final_scenario_exports_valid_traceable_leak_free_data(
    tmp_path: Path, scenario: str
):
    runtime = _runtime(scenario)
    if scenario.startswith("NORMAL_"):
        _normal(runtime, scenario)
    else:
        _attack(runtime, scenario)
    if scenario == "REPLAY_OLD_SESSION":
        runtime.start()
        runtime.step()
        runtime.step()
        runtime.rotate_security_session(
            2, 1, old_session_id="v5-old", new_session_id="v5-new"
        )
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 101.0},
            session_id="v5-new",
            sequence_no=1,
        )
    runtime.run_to_completion()
    root = tmp_path / scenario.lower()
    runtime.export_dataset(root)
    validation = DatasetValidator().validate(root)
    assert validation.valid, (scenario, validation.errors)
    leakage = DatasetLeakageAudit.audit_events(runtime.events)
    assert leakage.passed, (scenario, leakage.errors)
    run = runtime.run_record()
    assert run["schema_version"] == "3.2.0"
    assert run["software_version"].startswith("platform-v7")
    assert run["legitimate_node_count"] == run["node_count"] == 4
    assert len({event["event_id"] for event in runtime.events}) == len(runtime.events)
    if scenario.startswith("NORMAL_"):
        assert runtime.attack_scheduler.labels() == []
    else:
        label = runtime.attack_scheduler.labels()[0]
        assert label["attacker_node_id"] is not None
        assert label["target_node_ids"]
        assert label["truth"]["resolved_plan"] == run["attack_plan"][0]
        assert set(
            {
                "attempted",
                "injected",
                "reached_target",
                "malicious_content_executed",
                "mission_impact",
                "attack_effective",
            }
        ) <= set(label["outcome"])
