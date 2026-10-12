from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from swarm_sim import ConfigValidationError, PlatformRuntime, RunConfig
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch
from .test_all_scenarios_dataset_v4 import (
    ALL_SCENARIOS,
    _prepare,
    _runtime,
)
from ..regression.test_v3_audit_regressions import OneShotAdapter


def test_gate_every_required_scenario_validates(tmp_path: Path):
    results: dict[str, bool] = {}
    for scenario in ALL_SCENARIOS:
        runtime = _runtime(scenario)
        _prepare(runtime, scenario)
        if scenario == "REPLAY_OLD_SESSION_REPLAY":
            runtime.start()
            runtime.step()
            runtime.step()
            runtime.rotate_security_session(
                2,
                1,
                old_session_id="matrix-old",
                new_session_id="matrix-new",
            )
            runtime.queue_message(
                2,
                1,
                "TELEMETRY",
                {"altitude_m": 101.0},
                session_id="matrix-new",
                sequence_no=1,
            )
        runtime.run_to_completion()
        root = tmp_path / scenario.lower()
        runtime.export_dataset(root)
        report = DatasetValidator().validate(root)
        results[scenario] = report.valid
    # DOS/JAMMING was removed from the supported attack contract.
    assert len(results) == 18
    assert all(results.values()), results


def test_gate_rl_reset_dispatch_traffic_and_provenance_are_training_ready():
    attack = {
        "attack_family": "DOS",
        "attack_subtype": "FLOODING",
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 0.8,
        "attacker_node_id": 2,
        "target_node_ids": [1],
        "intensity": {"value": 20.0, "unit": "pps"},
        "parameters": {"packet_type": "STATUS"},
    }
    env = UavDefenseEnv(observer_node_id=1)
    observation = env.reset(
        404,
        {
            "duration_s": 1.0,
            "decision_step_s": 0.4,
            "auto_traffic": False,
            "attack_specs": [attack],
        },
    )
    assert env.episode is not None
    runtime = env.episode.runtime
    assert len(runtime.attack_scheduler.records) == 1
    _, outcome, _ = env.step(
        {"action": "RECOMMEND_RATE_LIMIT", "peer_id": 2, "target_node_id": 1}
    )
    assert runtime.context.clock.now_s >= 0.4
    assert outcome["throughput_mbps"] is not None
    assert observation["security"]["rff_anomaly_count"] == 0
    record = runtime.run_record()
    assert record["profiles"]["attack_plan_id"]
    assert record["attack_plan"][0]["parameters"]["packet_type"] == "STATUS"
    assert record["security_providers"]["key_provider"]["status"] == "TEST_ONLY_NOT_SKG"


def test_gate_rff_prediction_reaches_security_and_model_recommendation_reaches_b_policy():
    rff = OneShotAdapter("rff-gate", {"RX_SUCCESS"}, "RX_SUCCESS", "UNKNOWN", None)
    bilstm = OneShotAdapter(
        "bilstm-gate",
        {"RX_SUCCESS"},
        "RX_SUCCESS",
        "FDI",
        "RECOMMEND_DATA_ISOLATION",
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8),
        run_id="v4-formal-model-gate",
        model_adapters={"rff": rff, "bilstm": bilstm},
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert runtime.nodes[1].rff_identity_result == "UNKNOWN"
    assert runtime.rl_observation(1)["security"]["rff_anomaly_count"] == 1
    fused = [
        event
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("decision_audit", {}).get("source")
        == "FUSION"
    ]
    assert fused
    assert any(
        event["extensions"]["defense_result"]["executed"] for event in fused
    )
    assert 2 in runtime.nodes[1].isolated_peer_ids


def test_gate_old_session_attack_has_no_detector_oracle_call():
    source = inspect.getsource(PlatformRuntime._transmit_replay_frame)
    assert "expire_session" not in source
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, rx_service_per_step=8),
        run_id="v4-formal-old-session",
    )
    runtime.schedule_attack(
        {
            "attack_family": "REPLAY",
            "attack_subtype": "OLD_SESSION_REPLAY",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.8,
            "end_s": 1.2,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "parameters": {"stale_session_id": "old"},
        }
    )
    message_id = runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 100.0}, session_id="old", sequence_no=1
    )
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.rotate_security_session(2, 1, old_session_id="old", new_session_id="new")
    while not runtime.is_terminated:
        runtime.debug_step()
    assert any(
        event["event_type"] == "AUTH_RESULT"
        and event["message_id"] == message_id
        and event["online_features"]["security_state"]["replay_check_result"]
        == "WRONG_SESSION"
        for event in runtime.events
    )


def test_gate_strict_config_metadata_semantics_and_formal_provider_guard():
    with pytest.raises(ConfigValidationError):
        RunConfig.from_dict({"attak_specs": []})
    first = RunConfig(seed=9, episode_phases={"x": 1}, traffic_profile_id="metadata-a")
    second = RunConfig(seed=9, episode_phases={"x": 2}, traffic_profile_id="metadata-b")
    assert first.semantic_fingerprint() == second.semantic_fingerprint()
    with pytest.raises(ValueError, match="FORMAL_SECURITY_REQUIRED"):
        PlatformRuntime(RunConfig(require_formal_security=True))


def test_gate_batch_refuses_final_output_with_builtin_mock_security(tmp_path: Path):
    with pytest.raises(ValueError, match="FORMAL_SECURITY_REQUIRED"):
        run_batch(
            tmp_path,
            seeds=[7],
            duration_s=0.2,
            step_s=0.2,
            node_count=4,
            require_formal_security=True,
            dataset_maturity="FORMAL",
        )


def test_gate_reciprocal_channel_probe_and_provider_provenance():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="v4-formal-probe")
    runtime.phy.switch_channel("link-2-1")
    assert (
        runtime.phy.states["link-2-1"].frequency_hz
        == runtime.phy.states["link-1-2"].frequency_hz
    )
    first, second = runtime.probes.probe(2, 1)
    assert not first.missing and not second.missing
    assert first.probe_id == second.probe_id and first.freq_hz == second.freq_hz
    providers = runtime.run_record()["security_providers"]
    assert set(providers) == {
        "key_provider",
        "crypto_provider",
        "terminal_credential_provider",
    }
    encoded = json.dumps(providers).lower()
    assert "key_material" not in encoded and "mock-key-root" not in encoded


def test_gate_validator_catches_cross_file_and_nested_corruption(tmp_path: Path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False), run_id="v4-formal-corrupt"
    )
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    events_path = tmp_path / "events.jsonl"
    rows = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["observer_node_id"] = 999
    rows[0]["online_features"]["phy"]["unexpected_field"] = 1
    events_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("observer_node_id" in error for error in report.errors)
    assert any("unexpected_field" in error for error in report.errors)


def test_gate_checked_current_schema_example_dataset_is_loader_valid(tmp_path):
    root = tmp_path / "schema_3_1_example_dataset"
    runtime = PlatformRuntime(
        RunConfig(seed=4410, duration_s=0.6, auto_traffic=True),
        run_id="schema-3-1-example",
    )
    runtime.run_to_completion()
    runtime.export_dataset(root)
    report = DatasetValidator().validate(root)
    assert report.valid, report.errors
    run = json.loads((root / "runs.jsonl").read_text(encoding="utf-8"))
    assert run["schema_version"] == "3.2.0"
    assert run["software_version"].startswith("platform-v7")
    assert run["dataset_maturity"] == "DEVELOPMENT"
