"""V6 final gate: data validity and mechanism occurrence are independent."""

from __future__ import annotations

from pathlib import Path

import pytest

from swarm_sim import PlatformRuntime, RunConfig, ScenarioMechanismValidator
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.validation import DatasetValidator


SCENARIOS = (
    "NORMAL_BASELINE",
    "NORMAL_LOW_SNR",
    "NORMAL_PACKET_LOSS",
    "NORMAL_TRAFFIC_BURST",
    "NORMAL_OUT_OF_ORDER",
    "NORMAL_STATE_CHANGE",
    "NORMAL_CONGESTION",
    "SPOOFING_UNKNOWN_ID",
    "SPOOFING_KNOWN_ID_CONFLICT",
    "EAVESDROPPING_NONSENSITIVE_PLAINTEXT_CONTROL",
    "EAVESDROPPING_CIPHERTEXT_ONLY",
    "EAVESDROPPING_PLAINTEXT_EXPOSURE",
    "DOS_FLOODING",
    "FDI_COMMAND_REPLACEMENT",
    "FDI_TELEMETRY_ABRUPT_CHANGE",
    "FDI_TELEMETRY_GRADUAL_DRIFT",
    "FDI_OUT_OF_RANGE_VALUE",
    "FDI_LOGICAL_INCONSISTENCY",
    "REPLAY_IMMEDIATE_REPLAY",
    "REPLAY_DELAYED_REPLAY",
    "REPLAY_OLD_SESSION_REPLAY",
)


def _traffic(
    *,
    source: int = 2,
    target: int = 1,
    packet_type: str = "TELEMETRY",
    payload: dict | None = None,
    start_s: float = 0.2,
    count: int = 3,
    interval_s: float = 0.2,
    sensitive: bool = False,
    encrypt: bool | None = None,
    session_id: str | None = None,
) -> dict:
    return {
        "source_node_id": source,
        "target_node_id": target,
        "packet_type": packet_type,
        "start_s": start_s,
        "payload": payload or {"altitude_m": 100.0},
        "interval_s": interval_s,
        "count": count,
        "sensitive": sensitive,
        "encrypt": encrypt,
        "session_id": session_id,
        "sequence_start": 100,
    }


def _attack(family: str, subtype: str, **updates) -> dict:
    plan = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 1.6,
        "attacker_node_id": -1,
        "target_node_ids": [1],
        "target_link_ids": [],
        "intensity": {},
        "parameters": {},
    }
    plan.update(updates)
    return plan


def _config_for(scenario: str, seed: int) -> RunConfig:
    values: dict = {
        "seed": seed,
        "duration_s": 2.4,
        "step_s": 0.2,
        "auto_traffic": False,
        "queue_capacity": 128,
        "tx_service_per_step": 64,
        "rx_service_per_step": 64,
        "phy_sample_interval_s": 0.2,
        "traffic_specs": [],
        "attack_specs": [],
        "normal_disturbance_specs": [],
        "session_lifecycle_specs": [],
    }
    if scenario == "NORMAL_BASELINE":
        values["traffic_specs"] = [_traffic()]
    elif scenario.startswith("NORMAL_"):
        parameters: dict = {}
        targets = [1]
        links: list[str] = []
        if scenario == "NORMAL_LOW_SNR":
            parameters = {"attenuation_db": 55.0}
            links = ["link-2-1"]
            targets = []
            values["traffic_specs"] = [_traffic(count=4)]
        elif scenario == "NORMAL_PACKET_LOSS":
            parameters = {"loss_probability": 1.0}
            links = ["link-2-1"]
            targets = []
            values["traffic_specs"] = [_traffic(count=4)]
        elif scenario == "NORMAL_TRAFFIC_BURST":
            parameters = {
                "source_node_id": 2,
                "packet_rate_pps": 30.0,
                "packet_type": "STATUS",
                "target_packet_size_bytes": 192,
            }
        elif scenario == "NORMAL_OUT_OF_ORDER":
            parameters = {
                "source_node_id": 2,
                "sequence_numbers": [100, 102, 101],
                "session_id": "business-sequence-control",
                "packet_type": "TELEMETRY",
            }
        elif scenario == "NORMAL_STATE_CHANGE":
            targets = [2]
            parameters = {
                "battery_pct": 88.0,
                "flight_state": "CRUISE",
                "position_xyz_m": [120.0, 20.0, 130.0],
            }
        elif scenario == "NORMAL_CONGESTION":
            links = ["link-2-1"]
            parameters = {
                "source_node_id": 2,
                "packet_rate_pps": 40.0,
                "packet_type": "STATUS",
                "target_packet_size_bytes": 192,
                "busy_ratio_addition": 0.65,
            }
        values["normal_disturbance_specs"] = [
            {
                "disturbance_type": scenario,
                "start_s": 0.2,
                "end_s": 1.4,
                "target_node_ids": targets,
                "target_link_ids": links,
                "parameters": parameters,
            }
        ]
    elif scenario == "SPOOFING_UNKNOWN_ID":
        values["attack_specs"] = [
            _attack("SPOOFING", "UNKNOWN_ID", parameters={"claimed_src_id": 999})
        ]
    elif scenario == "SPOOFING_KNOWN_ID_CONFLICT":
        values["attack_specs"] = [
            _attack(
                "SPOOFING",
                "KNOWN_ID_CONFLICT",
                parameters={"claimed_src_id": 0},
            )
        ]
    elif scenario.startswith("EAVESDROPPING_"):
        subtype = scenario.removeprefix("EAVESDROPPING_")
        protected = subtype == "CIPHERTEXT_ONLY"
        sensitive = subtype != "NONSENSITIVE_PLAINTEXT_CONTROL"
        values["encrypt_sensitive"] = protected
        values["attack_specs"] = [
            _attack(
                "EAVESDROPPING",
                subtype,
                target_link_ids=["link-2-1"],
                parameters={"receiver_radius_m": 1000.0},
            )
        ]
        values["traffic_specs"] = [
            _traffic(
                packet_type="MISSION_COMMAND" if sensitive else "STATUS",
                payload=(
                    {"cmd": "FLY_TO", "altitude_m": 100.0}
                    if sensitive
                    else {"status_code": 1, "value": 12.0}
                ),
                count=3,
                sensitive=sensitive,
                encrypt=protected,
            )
        ]
    elif scenario == "DOS_FLOODING":
        values["attack_specs"] = [
            _attack(
                "DOS",
                "FLOODING",
                attacker_node_id=-1,
                intensity={"value": 60.0, "unit": "pps"},
                parameters={
                    "packet_type": "STATUS",
                    "target_packet_size_bytes": 192,
                },
            )
        ]
    elif scenario.startswith("FDI_"):
        subtype = scenario.removeprefix("FDI_")
        parameters: dict
        traffic = _traffic(count=3)
        target = 1
        attacker = 2
        if subtype == "COMMAND_REPLACEMENT":
            parameters = {"replacement": {"cmd": "LAND"}}
            target = 2
            attacker = 0
            traffic = _traffic(
                source=0,
                target=2,
                packet_type="MISSION_COMMAND",
                payload={"cmd": "FLY_TO", "altitude_m": 100.0},
                count=1,
                sensitive=True,
            )
        elif subtype == "TELEMETRY_ABRUPT_CHANGE":
            parameters = {"field": "altitude_m", "absolute_offset": 50.0}
        elif subtype == "TELEMETRY_GRADUAL_DRIFT":
            parameters = {"field": "altitude_m", "delta_per_step": 5.0}
        elif subtype == "OUT_OF_RANGE_VALUE":
            parameters = {"field": "altitude_m", "value": 5000.0}
        else:
            parameters = {"altitude_m": 120.0}
            traffic["payload"] = {"altitude_m": 100.0, "flight_state": "CRUISE"}
        values["attack_specs"] = [
            _attack(
                "FDI",
                subtype,
                attacker_node_id=attacker,
                target_node_ids=[target],
                parameters=parameters,
            )
        ]
        values["traffic_specs"] = [traffic]
    elif scenario.startswith("REPLAY_"):
        subtype = scenario.removeprefix("REPLAY_")
        parameters: dict = {}
        impact = 0.6
        session = "business-live-session"
        if subtype == "IMMEDIATE_REPLAY":
            parameters = {"max_capture_age_s": 0.8}
        elif subtype == "DELAYED_REPLAY":
            parameters = {"delay_s": 0.6}
            impact = 0.4
        else:
            session = "business-session-a"
            parameters = {"stale_session_id": session}
            impact = 0.8
            values["session_lifecycle_specs"] = [
                {
                    "sender_node_id": 2,
                    "receiver_node_id": 1,
                    "rotate_at_s": 0.6,
                    "old_session_id": session,
                    "new_session_id": "business-session-b",
                }
            ]
        values["attack_specs"] = [
            _attack(
                "REPLAY",
                subtype,
                impact_start_s=impact,
                end_s=2.0,
                parameters=parameters,
            )
        ]
        values["traffic_specs"] = [_traffic(count=1, session_id=session)]
    else:  # pragma: no cover - SCENARIOS is the frozen list.
        raise AssertionError(scenario)
    return RunConfig.from_dict(values)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_v6_final_scenario_requires_contract_and_mechanism(
    tmp_path: Path, scenario: str
):
    seed = 6600 + SCENARIOS.index(scenario)
    runtime = PlatformRuntime(
        _config_for(scenario, seed), run_id=f"v6-matrix-{scenario.lower()}"
    )
    runtime.run_to_completion()

    output = tmp_path / scenario.lower()
    runtime.export_dataset(output)
    contract = DatasetValidator().validate(output)
    leakage = DatasetLeakageAudit.audit_events(runtime.events)
    mechanism = ScenarioMechanismValidator.validate(runtime, scenario)

    assert contract.valid, (scenario, contract.errors)
    assert leakage.passed, (scenario, leakage.errors)
    assert mechanism.passed, (scenario, mechanism.errors, mechanism.evidence)


def test_v6_fdi_gradual_evidence_is_accumulated_not_merely_present():
    runtime = PlatformRuntime(
        _config_for("FDI_TELEMETRY_GRADUAL_DRIFT", 6699),
        run_id="v6-gradual-proof",
    )
    runtime.run_to_completion()
    result = ScenarioMechanismValidator.validate(
        runtime, "FDI_TELEMETRY_GRADUAL_DRIFT"
    )
    assert result.passed, result.errors
    assert result.evidence["drift_values"][:3] == [105.0, 110.0, 115.0]
