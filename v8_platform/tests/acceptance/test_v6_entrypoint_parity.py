"""Direct, batch, FastAPI and RL must execute one ScenarioConfig alike."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.app import CreateRunRequest, app, controller
from swarm_sim import PlatformRuntime, RunConfig, ScenarioMechanismValidator
from swarm_sim.rl import UavDefenseEnv
from tools.run_experiment import run_batch


def _base() -> dict:
    return {
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


def _values(scenario: str) -> dict:
    values = _base()
    traffic = {
        "source_node_id": 2,
        "target_node_id": 1,
        "packet_type": "TELEMETRY",
        "start_s": 0.2,
        "payload": {"altitude_m": 100.0},
        "interval_s": 0.2,
        "count": 3,
        "sequence_start": 100,
    }
    if scenario == "FDI_TELEMETRY_GRADUAL_DRIFT":
        values["attack_specs"] = [
            {
                "attack_family": "FDI",
                "attack_subtype": "TELEMETRY_GRADUAL_DRIFT",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.2,
                "end_s": 1.4,
                "attacker_node_id": 2,
                "target_node_ids": [1],
                "parameters": {"field": "altitude_m", "delta_per_step": 5.0},
            }
        ]
        values["traffic_specs"] = [traffic]
    elif scenario == "REPLAY_OLD_SESSION_REPLAY":
        traffic.update({"count": 1, "session_id": "session-a"})
        values["traffic_specs"] = [traffic]
        values["session_lifecycle_specs"] = [
            {
                "sender_node_id": 2,
                "receiver_node_id": 1,
                "rotate_at_s": 0.6,
                "old_session_id": "session-a",
                "new_session_id": "session-b",
            }
        ]
        values["attack_specs"] = [
            {
                "attack_family": "REPLAY",
                "attack_subtype": "OLD_SESSION_REPLAY",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.8,
                "end_s": 2.0,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "parameters": {"stale_session_id": "session-a"},
            }
        ]
    elif scenario == "DOS_FLOODING":
        values["attack_specs"] = [
            {
                "attack_family": "DOS",
                "attack_subtype": "FLOODING",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.0,
                "end_s": 1.4,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "target_link_ids": [],
                "intensity": {"value": 60.0, "unit": "pps"},
                "parameters": {
                    "packet_type": "STATUS",
                    "target_packet_size_bytes": 192,
                },
            }
        ]
    elif scenario == "EAVESDROPPING_PLAINTEXT_EXPOSURE":
        traffic.update(
            {
                "packet_type": "MISSION_COMMAND",
                "payload": {"cmd": "FLY_TO", "altitude_m": 100.0},
                "sensitive": True,
                "encrypt": False,
            }
        )
        values["traffic_specs"] = [traffic]
        values["attack_specs"] = [
            {
                "attack_family": "EAVESDROPPING",
                "attack_subtype": "PLAINTEXT_EXPOSURE",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.2,
                "end_s": 1.4,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "target_link_ids": ["link-2-1"],
                "parameters": {"receiver_radius_m": 1000.0},
            }
        ]
    else:  # pragma: no cover - parameter list is frozen below.
        raise AssertionError(scenario)
    return values


def _run_direct(values: dict, seed: int) -> PlatformRuntime:
    runtime = PlatformRuntime(
        RunConfig.from_dict({**values, "seed": seed}),
        run_id="v6-entry-direct",
    )
    runtime.run_to_completion()
    return runtime


def _run_api(values: dict, seed: int) -> PlatformRuntime:
    config = RunConfig.from_dict({**values, "seed": seed})
    allowed = set(CreateRunRequest.model_fields)
    request = {
        key: value for key, value in asdict(config).items() if key in allowed
    }
    request.update({"auto_advance": False, "wall_interval_s": 0.05})
    with TestClient(app) as client:
        response = client.post("/api/runs", json=request)
        assert response.status_code == 201, response.text
        while client.get("/api/runs/status").json()["state"] != "COMPLETED":
            assert client.post("/api/debug/step").status_code == 200
        assert controller.manager.runtime is not None
        return controller.manager.runtime


def _run_rl(values: dict, seed: int) -> PlatformRuntime:
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(seed, values)
    assert env.episode is not None
    env.episode.runtime.run_to_completion()
    return env.episode.runtime


def _key_evidence(runtime: PlatformRuntime, scenario: str) -> dict:
    result = ScenarioMechanismValidator.validate(runtime, scenario)
    assert result.passed, result.errors
    evidence = result.evidence
    if scenario == "FDI_TELEMETRY_GRADUAL_DRIFT":
        return {
            "injected": evidence["injected"],
            "values": evidence["drift_values"][:3],
        }
    if scenario == "REPLAY_OLD_SESSION_REPLAY":
        return {
            "injected": evidence["injected"],
            "wrong_session": "WRONG_SESSION" in evidence["replay_check_results"],
        }
    if scenario == "DOS_FLOODING":
        return {
            "injected": evidence["injected"],
            "receiver_rate_exceeded": evidence["receiver_total_rate_exceeded"],
            "hmac_rejected_count": evidence["hmac_rejected_count"],
        }
    return {
        "injected": evidence["injected"],
        "plaintext_exposure": evidence["plaintext_exposure_count"] > 0,
    }


@pytest.mark.parametrize(
    "scenario",
    (
        "FDI_TELEMETRY_GRADUAL_DRIFT",
        "REPLAY_OLD_SESSION_REPLAY",
        "DOS_FLOODING",
        "EAVESDROPPING_PLAINTEXT_EXPOSURE",
    ),
)
def test_same_scenario_semantics_across_direct_batch_api_and_rl(
    tmp_path: Path, scenario: str
):
    seed = 6710
    values = _values(scenario)
    direct = _run_direct(values, seed)

    batch = run_batch(
        tmp_path / scenario.lower(),
        seeds=[seed],
        run_config={**values, "seed": seed},
    )
    assert batch["all_valid"], batch["runs"][0]["mechanism_validation"]
    batch_evidence = batch["runs"][0]["mechanism_validation"]["evidence"]

    api_runtime = _run_api(values, seed)
    rl_runtime = _run_rl(values, seed)
    expected = _key_evidence(direct, scenario)
    assert _key_evidence(api_runtime, scenario) == expected
    assert _key_evidence(rl_runtime, scenario) == expected

    if scenario == "FDI_TELEMETRY_GRADUAL_DRIFT":
        actual_batch = {
            "injected": batch_evidence["injected"],
            "values": batch_evidence["drift_values"][:3],
        }
    elif scenario == "REPLAY_OLD_SESSION_REPLAY":
        actual_batch = {
            "injected": batch_evidence["injected"],
            "wrong_session": "WRONG_SESSION"
            in batch_evidence["replay_check_results"],
        }
    elif scenario == "DOS_FLOODING":
        actual_batch = {
            "injected": batch_evidence["injected"],
            "receiver_rate_exceeded": batch_evidence[
                "receiver_total_rate_exceeded"
            ],
            "hmac_rejected_count": batch_evidence["hmac_rejected_count"],
        }
    else:
        actual_batch = {
            "injected": batch_evidence["injected"],
            "plaintext_exposure": batch_evidence["plaintext_exposure_count"] > 0,
        }
    assert actual_batch == expected


def test_subtype_parameter_contract_is_strict_in_batch_api_and_rl(tmp_path: Path):
    bad_attack = {
        **_values("FDI_TELEMETRY_GRADUAL_DRIFT"),
        "attack_specs": [
            {
                **_values("FDI_TELEMETRY_GRADUAL_DRIFT")["attack_specs"][0],
                "parameters": {"field": "altitude_m", "delta_per_stpe": 5.0},
            }
        ],
    }
    with pytest.raises(ValueError, match="UNKNOWN_ATTACK_PARAMETER"):
        run_batch(tmp_path / "bad-batch", seeds=[1], run_config=bad_attack)

    api_request = {
        key: value
        for key, value in {**bad_attack, "seed": 1}.items()
        if key in CreateRunRequest.model_fields
    }
    api_request["auto_advance"] = False
    with TestClient(app) as client:
        response = client.post("/api/runs", json=api_request)
        assert response.status_code == 422
        assert "UNKNOWN_ATTACK_PARAMETER" in response.text

    env = UavDefenseEnv(observer_node_id=1)
    with pytest.raises(ValueError, match="UNKNOWN_ATTACK_PARAMETER"):
        env.reset(1, bad_attack)

    bad_normal = {
        **_base(),
        "normal_disturbance_specs": [
            {
                "disturbance_type": "NORMAL_LOW_SNR",
                "start_s": 0.2,
                "end_s": 1.0,
                "target_link_ids": ["link-2-1"],
                "parameters": {"attenuatio_db": 20.0},
            }
        ],
    }
    with pytest.raises(ValueError, match="UNKNOWN_NORMAL_PARAMETER"):
        run_batch(tmp_path / "bad-normal", seeds=[1], run_config=bad_normal)
