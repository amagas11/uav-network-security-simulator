from __future__ import annotations

import json
from pathlib import Path

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.simulation import ConfigValidationError, SCHEMA_VERSION, SOFTWARE_VERSION
from swarm_sim.validation import DatasetValidator
from .test_final_scenario_matrix_v5 import SCENARIOS


def test_gate_declares_nineteen_distinct_v5_compatible_scenarios():
    # The retired DOS/JAMMING capability is intentionally absent. The newer
    # three-way eavesdropping matrix is covered by the V6/current gate.
    assert len(SCENARIOS) == 19
    assert len(SCENARIOS) == len(set(SCENARIOS))
    assert {"SPOOFING_UNKNOWN_ID", "SPOOFING_KNOWN_ID_CONFLICT"} <= set(SCENARIOS)


def test_gate_frozen_software_schema_and_contract_descriptors():
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "dataset" / "schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert SCHEMA_VERSION == schema["schema_version"] == "3.2.0"
    assert SOFTWARE_VERSION == "platform-v7"
    packet_size = schema["objects"]["online_features.packet"]["fields"][
        "packet_size_bytes"
    ]
    gaps = schema["objects"]["online_features.traffic"]["fields"][
        "sequence_gap_count"
    ]
    assert packet_size["semantic_id"] == "packet.canonical_application_size"
    assert gaps["semantic_id"] == "traffic.recent_window_sequence_gaps"
    assert schema["objects"]["labels"]["fields"]["outcome"]["object_ref"] == "AttackOutcome"


def test_gate_strict_public_config_rejects_typo():
    with pytest.raises(ConfigValidationError, match="attak_specs"):
        RunConfig.from_dict({"attak_specs": []})


def test_gate_external_participant_is_separate_from_legitimate_node_count(tmp_path: Path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False), run_id="v5-external-contract"
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "KNOWN_ID_CONFLICT",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.0,
            "end_s": 0.6,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "parameters": {"claimed_src_id": 0},
        }
    )
    runtime.run_to_completion()
    run = runtime.run_record()
    assert run["node_count"] == run["legitimate_node_count"] == 4
    assert len(run["legitimate_node_roles"]) == 4
    assert run["node_roles"]["-1"] == "EXTERNAL"
    assert run["external_participants"] == [{"node_id": -1, "role": "EXTERNAL"}]
    runtime.export_dataset(tmp_path)
    assert DatasetValidator().validate(tmp_path).valid


def test_gate_mock_security_provenance_prevents_formal_maturity():
    development = PlatformRuntime(RunConfig(auto_traffic=False)).run_record()
    assert development["dataset_maturity"] == "DEVELOPMENT"
    assert "TEST_ONLY" in development["security_providers"]["key_provider"]["status"]
    with pytest.raises(ValueError, match="FORMAL_SECURITY_REQUIRED"):
        PlatformRuntime(
            RunConfig(
                auto_traffic=False,
                dataset_maturity="FORMAL",
                require_formal_security=True,
            )
        )


def test_gate_cross_file_validator_rejects_unknown_observer_and_attack_id(tmp_path: Path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.6, auto_traffic=False), run_id="v5-validator-gate"
    )
    runtime.schedule_attack(
        {
            "attack_family": "FDI",
            "attack_subtype": "TELEMETRY_ABRUPT_CHANGE",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.0,
            "end_s": 0.4,
            "attacker_node_id": 2,
            "target_node_ids": [1],
        }
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    event_path = tmp_path / "events.jsonl"
    events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines()]
    events[0]["observer_node_id"] = 999
    event_path.write_text(
        "\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8"
    )
    label_path = tmp_path / "labels.jsonl"
    labels = [json.loads(line) for line in label_path.read_text(encoding="utf-8").splitlines()]
    labels[0]["attack_id"] = "not-in-plan"
    label_path.write_text(
        "\n".join(json.dumps(item) for item in labels) + "\n", encoding="utf-8"
    )
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("node is not declared" in error for error in report.errors)
    assert any("not present in the run attack_plan" in error for error in report.errors)
