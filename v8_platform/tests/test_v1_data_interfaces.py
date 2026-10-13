from __future__ import annotations

import json

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.calibration import (
    CalibrationLoader,
    CalibrationParameter,
    CalibrationProfile,
    DatasetManifest,
    compare_observations,
)
from swarm_sim.dataset import schema_v1
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.redundancy import RedundantExecutor, Replica, SwitchRecovery
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.terminal import TerminalAuthorizer, TerminalProfile
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch


def test_event_contract_has_all_groups_and_explicit_missing_values():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="schema")
    event = runtime.events[0]
    assert event["schema_version"] == SCHEMA_VERSION
    assert set(event["online_features"]) == {
        "packet",
        "phy",
        "traffic",
        "node_state",
        "topology",
        "security_state",
        "resource_state",
    }
    assert event["online_features"]["phy"]["rssi_dbm"] is None
    assert event["availability"]["phy_available"] is False


def test_frozen_schema_enumerates_exact_source_kinds_and_no_fake_iq():
    schema = schema_v1()
    assert schema["schema_version"] == SCHEMA_VERSION
    assert schema["data_source_kinds"] == [
        "simulation",
        "calibrated_simulation",
        "real_measurement",
        "augmented_real",
    ]
    assert schema["rf_sample_contract"]["no_synthetic_iq_is_included"] is True


def test_exported_dataset_passes_validator(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.6), run_id="export")
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
    assert report.counts["events"] == len(runtime.events)
    assert (tmp_path / "events.jsonl").read_text(encoding="utf-8").endswith("\n")


def test_validator_catches_truth_leak_in_online_features(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.2), run_id="leak")
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    path = tmp_path / "events.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["online_features"]["node_state"]["attacker_node_id"] = -1
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("forbidden online fields" in error for error in report.errors)


def test_validator_rejects_unknown_enumeration(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.2), run_id="bad-enum")
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    path = tmp_path / "events.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["event_type"] = "MAGIC_SUCCESS"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("unsupported event_type" in error for error in report.errors)


def test_unconfigured_models_report_health_without_per_event_noise():
    runtime = PlatformRuntime(RunConfig(duration_s=0.2), run_id="models")
    runtime.run_to_completion()
    results = [
        event["extensions"]["model_result"]
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
    ]
    assert results == []
    assert all(
        status["status"] == "UNAVAILABLE"
        and status["error_code"] == "MODEL_NOT_CONFIGURED"
        for status in runtime.model_status().values()
    )


def test_run_record_marks_uncalibrated_simulation_without_real_data_claim():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="provenance")
    record = runtime.context.run_record()
    assert record["data_source"]["kind"] == "simulation"
    assert record["data_source"]["source_dataset_version"] is None
    assert record["calibration_status"] == "UNCALIBRATED_BASELINE"


def test_runtime_rejects_unproven_calibrated_source_claim():
    with pytest.raises(ValueError, match="REQUIRES_CALIBRATION_PROFILE"):
        PlatformRuntime(
            RunConfig(
                auto_traffic=False,
                data_source_kind="calibrated_simulation",
                calibration_status="CALIBRATED",
            )
        )


def test_calibration_profile_has_parameter_level_provenance():
    profile = CalibrationProfile.uncalibrated_baseline()
    assert profile.calibration_status == "UNCALIBRATED_BASELINE"
    assert profile.parameters
    assert all(item.source == "simulation_baseline" for item in profile.parameters)
    assert all(item.fitting_method == "not_fitted" for item in profile.parameters)


def test_calibration_config_round_trip_and_comparison():
    profile = CalibrationLoader.load("config/calibration_baseline.json")
    assert profile.profile_id == "uncalibrated-static-a2a-v1"
    assert compare_observations([1.0, 2.0], [2.0, 2.0]) == {
        "reference_count": 2,
        "simulated_count": 2,
        "mean_error": 0.5,
        "mean_absolute_error": 0.5,
    }


def test_calibration_profile_is_injected_into_persistent_phy():
    profile = CalibrationProfile(
        profile_id="verified-lab-v1",
        calibration_version="1",
        calibration_status="CALIBRATED",
        data_source_kind="calibrated_simulation",
        parameters=[
            CalibrationParameter(
                "tx_power_dbm", 17.0, "dBm", "lab-dataset-v1", "least_squares", [0, 40], "1", "1"
            )
        ],
        dataset_manifest=DatasetManifest(
            dataset_id="lab-a2a",
            version="1",
            source_kind="real_measurement",
            source_uri="institutional://lab-a2a/1",
            license="internal-research",
            sha256="a" * 64,
            fields=["tx_power_dbm"],
        ),
    )
    runtime = PlatformRuntime(
        RunConfig(auto_traffic=False), calibration_profile=profile
    )
    assert runtime.config.data_source_kind == "calibrated_simulation"
    assert runtime.config.calibration_status == "CALIBRATED"
    assert runtime.phy.states["link-0-1"].tx_power_dbm == 17.0


def test_passive_eavesdropping_metrics_do_not_invent_detection_accuracy():
    result = ExperimentEvaluator().evaluate([], [])
    assert result["scope"] == "GROUND_TRUTH_OFFLINE_EVALUATION"
    assert result["eavesdropping"]["online_detection_rate"] is None


def test_logical_redundancy_reports_scope_and_majority():
    executor = RedundantExecutor(
        [
            Replica("a", lambda value: value + 1),
            Replica("b", lambda value: value + 1),
            Replica("c", lambda value: value + 2),
        ]
    )
    result = executor.execute(2)
    assert result["implementation_scope"] == "LOGICAL_REDUNDANCY_BASELINE"
    assert result["adjudication"]["status"] == "CONSENSUS"
    assert result["adjudication"]["output"] == 3


def test_replica_failure_is_visible_and_recoverable():
    def fail(_: object):
        raise RuntimeError("failure")

    replica = Replica("bad", fail)
    assert replica.run(None)["status"] == "FAILED"
    recovery = SwitchRecovery.recover(replica)
    assert recovery["event"] == "REPLICA_RECOVERED"
    assert replica.healthy


def test_terminal_binding_rejects_copied_profile_or_credential():
    first = TerminalProfile("uav-1", {"board": "a"}, {"app": "1"}, {"os": "x"})
    copied = TerminalProfile("uav-1", {"board": "b"}, {"app": "1"}, {"os": "x"})
    authorizer = TerminalAuthorizer()
    authorizer.enroll(first, "opaque-handle-1")
    assert authorizer.authorize("NETWORK_JOIN", first, "opaque-handle-1")["allowed"]
    assert not authorizer.authorize("NETWORK_JOIN", copied, "opaque-handle-1")["allowed"]
    assert not authorizer.authorize("NETWORK_JOIN", first, "copied-handle")["allowed"]


def test_rl_environment_returns_execution_outcome_without_reward():
    environment = UavDefenseEnv(observer_node_id=1)
    observation = environment.reset(7, {"duration_s": 0.4, "auto_traffic": False})
    assert observation["observer_node_id"] == 1
    next_observation, outcome, terminated = environment.step("NO_CHANGE")
    assert next_observation["sim_time_s"] == 0.2
    assert outcome["allowed"] and outcome["executed"]
    assert "reward" not in outcome
    assert terminated is False


def test_batch_runner_exports_each_seed_and_summary(tmp_path):
    summary = run_batch(
        tmp_path,
        seeds=[3, 4],
        duration_s=0.4,
        step_s=0.2,
        node_count=4,
    )
    assert summary["all_valid"]
    assert summary["run_count"] == 2
    assert (tmp_path / "batch_summary.json").is_file()
    assert all(row["validation"]["valid"] for row in summary["runs"])
