from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch


ATTACK_SPEC = {
    "attack_family": "DOS",
    "attack_subtype": "FLOODING",
    "scheduled_start_s": 0.0,
    "impact_start_s": 0.2,
    "end_s": 0.8,
    "attacker_node_id": 2,
    "target_node_ids": [1],
    "intensity": {"value": 40.0, "unit": "pps"},
    "parameters": {"packet_size_bytes": 128},
}


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


class RecordingAdapter:
    def __init__(
        self,
        name: str,
        accepted_event_types: set[str],
        *,
        emit_on: set[str] | None = None,
    ) -> None:
        self.name = name
        self.accepted_event_types = frozenset(accepted_event_types)
        self.emit_on = set(emit_on or set())
        self.received: list[dict[str, Any]] = []
        self._run_info: dict[str, Any] = {}
        self._counter = 0

    def reset(self, run_info: dict[str, Any]) -> None:
        self._run_info = deepcopy(run_info)
        self.received.clear()
        self._counter = 0

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        self.received.append(deepcopy(event))
        if event["event_type"] not in self.emit_on:
            return []
        self._counter += 1
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id=f"{self.name}-result-{self._counter}",
                observer_node_id=event["observer_node_id"],
                decision_time_s=event["sim_time_s"],
                model_name=self.name,
                model_version="recording-v1",
                status="OK",
                predicted_label="DOS",
                scores={"DOS": 0.9},
                confidence=0.9,
                quality=1.0,
                recommended_action="RECOMMEND_RATE_LIMIT",
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=0.0,
                error_code=None,
            )
        ]

    def health(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "status": "OK",
            "model_version": "recording-v1",
            "error_code": None,
        }


def _export_runtime(tmp_path: Path, run_id: str) -> Path:
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False), run_id=run_id
    )
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    return tmp_path


def _rewrite_first_event(path: Path, mutate) -> None:
    events_path = path / "events.jsonl"
    rows = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    mutate(rows[0])
    events_path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_case_1_rl_reset_attack_specs_populates_scheduler_without_manual_call():
    env = UavDefenseEnv(observer_node_id=1)
    observation = env.reset(
        701,
        {
            "duration_s": 1.2,
            "auto_traffic": False,
            "decision_step_s": 0.4,
            "attack_specs": [ATTACK_SPEC],
        },
    )
    assert len(env.episode.runtime.attack_scheduler.records) == 1
    assert not ({"attack_family", "attack_subtype", "attacker_node_id", "labels"} & set(_walk_keys(observation)))


def test_cases_2_3_dispatcher_routes_auth_and_bilstm_result_to_dueling_q():
    bilstm = RecordingAdapter(
        "bilstm-recording",
        {"TX", "RX_SUCCESS", "RX_FAILURE", "PHY_SAMPLE", "QUEUE_SAMPLE", "NODE_STATE", "TOPOLOGY_UPDATE", "AUTH_RESULT"},
        emit_on={"AUTH_RESULT"},
    )
    dueling = RecordingAdapter(
        "dueling-q-recording",
        {"PHY_SAMPLE", "QUEUE_SAMPLE", "NODE_STATE", "TOPOLOGY_UPDATE", "AUTH_RESULT", "MODEL_RESULT", "DEFENSE_RESULT"},
        emit_on={"MODEL_RESULT"},
    )
    rff = RecordingAdapter(
        "rff-recording", {"RX_SUCCESS", "RX_FAILURE", "PHY_SAMPLE"}
    )
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
        ),
        run_id="v3-dispatch-regression",
        model_adapters={"bilstm": bilstm, "dueling_q": dueling, "rff": rff},
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()

    bilstm_types = {event["event_type"] for event in bilstm.received}
    dueling_types = {event["event_type"] for event in dueling.received}
    rff_types = {event["event_type"] for event in rff.received}
    assert {"RX_SUCCESS", "PHY_SAMPLE", "AUTH_RESULT", "QUEUE_SAMPLE", "NODE_STATE", "TOPOLOGY_UPDATE"} <= bilstm_types
    assert {"QUEUE_SAMPLE", "PHY_SAMPLE", "AUTH_RESULT", "MODEL_RESULT"} <= dueling_types
    assert {"RX_SUCCESS", "PHY_SAMPLE"} <= rff_types

    downstream_results = [
        event
        for event in dueling.received
        if event["event_type"] == "MODEL_RESULT"
    ]
    assert downstream_results
    assert all(
        event["extensions"].get("source_adapter") == "bilstm"
        for event in downstream_results
    )
    # A Dueling-Q result is terminal for online routing and cannot recurse.
    assert not any(
        event["extensions"].get("source_adapter") == "dueling_q"
        for event in dueling.received
    )
    assert len(runtime.events) < 1000


def test_case_4_bad_sim_time_returns_invalid_report_without_exception(tmp_path):
    root = _export_runtime(tmp_path, "v3-bad-time")
    _rewrite_first_event(root, lambda row: row.__setitem__("sim_time_s", "bad"))
    report = DatasetValidator().validate(root)
    assert not report.valid
    assert any("sim_time_s" in error and "number" in error for error in report.errors)


def test_case_5_bad_nested_rssi_type_is_invalid(tmp_path):
    root = _export_runtime(tmp_path, "v3-bad-rssi")
    _rewrite_first_event(
        root,
        lambda row: row["online_features"]["phy"].__setitem__(
            "rssi_dbm", "NOT_A_NUMBER"
        ),
    )
    report = DatasetValidator().validate(root)
    assert not report.valid
    assert any("rssi_dbm" in error and "number" in error for error in report.errors)


@pytest.mark.parametrize(
    ("field_path", "bad_value", "expected_error"),
    [
        (("online_features", "phy", "per_estimate"), 1.5, "per_estimate"),
        (("online_features", "traffic", "rx_queue_length"), -1, "rx_queue_length"),
        (("online_features", "node_state", "battery_pct"), 101.0, "battery_pct"),
        (("online_features", "security_state", "auth_result"), "MAGIC", "auth_result"),
    ],
)
def test_validator_rejects_nested_range_and_enum_corruption(
    tmp_path, field_path, bad_value, expected_error
):
    root = _export_runtime(tmp_path, f"v3-corrupt-{expected_error}")

    def mutate(row):
        target = row
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = bad_value

    _rewrite_first_event(root, mutate)
    report = DatasetValidator().validate(root)
    assert not report.valid
    assert any(expected_error in error for error in report.errors)


def test_validator_accepts_nullable_null_and_rejects_missing_required(tmp_path):
    valid_root = _export_runtime(tmp_path / "valid", "v3-null-valid")
    assert DatasetValidator().validate(valid_root).valid

    invalid_root = _export_runtime(tmp_path / "invalid", "v3-required-missing")
    _rewrite_first_event(invalid_root, lambda row: row.pop("event_id"))
    report = DatasetValidator().validate(invalid_root)
    assert not report.valid
    assert any("event_id" in error and "missing required" in error for error in report.errors)


@pytest.mark.parametrize(
    ("field_path", "bad_value"),
    [
        (("event_type",), []),
        (("online_features", "phy", "rf_sample_ref"), []),
        (("online_features", "traffic", "throughput_mbps"), float("nan")),
    ],
)
def test_validator_unhashable_or_non_finite_corruption_never_crashes(
    tmp_path, field_path, bad_value
):
    root = _export_runtime(tmp_path, "v3-untrusted-corruption")

    def mutate(row):
        target = row
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = bad_value

    _rewrite_first_event(root, mutate)
    report = DatasetValidator().validate(root)
    assert report.valid is False
    assert report.errors


def test_case_6_duplicate_seeds_have_unique_run_ids_and_output_directories(tmp_path):
    summary = run_batch(
        tmp_path,
        seeds=[7, 7],
        duration_s=0.4,
        step_s=0.2,
        node_count=4,
    )
    run_ids = [row["run_id"] for row in summary["runs"]]
    output_dirs = [row["export"]["output_dir"] for row in summary["runs"]]
    assert len(set(run_ids)) == 2
    assert len(set(output_dirs)) == 2
    assert all(Path(path).is_dir() for path in output_dirs)
    assert len({row["semantic_event_fingerprint"] for row in summary["runs"]}) == 1


def test_case_7_fdi_parameter_change_changes_semantic_fingerprint():
    def record(delta: float) -> dict[str, Any]:
        spec = {
            "attack_family": "FDI",
            "attack_subtype": "TELEMETRY_GRADUAL_DRIFT",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 0.8,
            "attacker_node_id": 2,
            "target_node_ids": [2],
            "parameters": {"field": "altitude_m", "delta_per_step": delta},
        }
        runtime = PlatformRuntime(
            RunConfig.from_dict(
                {"duration_s": 1.0, "auto_traffic": False, "attack_specs": [spec]}
            )
        )
        return runtime.run_record()

    five = record(5.0)
    fifty = record(50.0)
    assert five["config_fingerprint"] != fifty["config_fingerprint"]
    assert five["attack_plan"][0]["parameters"]["delta_per_step"] == 5.0


def test_case_8_normal_disturbance_change_changes_fingerprint_and_provenance():
    def record(attenuation: float) -> dict[str, Any]:
        runtime = PlatformRuntime(
            RunConfig.from_dict(
                {
                    "duration_s": 1.0,
                    "auto_traffic": False,
                    "normal_disturbance_specs": [
                        {
                            "disturbance_type": "NORMAL_LOW_SNR",
                            "start_s": 0.2,
                            "end_s": 0.8,
                            "target_link_ids": ["link-1-2"],
                            "parameters": {"attenuation_db": attenuation},
                        }
                    ],
                }
            )
        )
        return runtime.run_record()

    first = record(10.0)
    second = record(30.0)
    assert first["config_fingerprint"] != second["config_fingerprint"]
    assert first["normal_disturbance_plan"][0]["parameters"]["attenuation_db"] == 10.0


def test_case_9_two_followers_forwarded_on_same_leader_gcs_hop_are_valid():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.2,
            auto_traffic=False,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        run_id="v3-multisource-session",
    )
    first = runtime.queue_message(
        2, 0, "TELEMETRY", {"altitude_m": 100.0}, session_id="business-f2"
    )
    second = runtime.queue_message(
        3, 0, "TELEMETRY", {"altitude_m": 110.0}, session_id="business-f3"
    )
    runtime.run_to_completion()
    gcs_auth = [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["observer_node_id"] == 0
        and event["message_id"] in {first, second}
    ]
    assert {event["message_id"] for event in gcs_auth} == {first, second}
    assert all(
        event["online_features"]["security_state"]["replay_check_result"] == "PASS"
        for event in gcs_auth
    )


def test_case_10_passive_eavesdrop_without_alarm_is_not_a_detection_fn():
    label = {
        "attack_id": "passive-1",
        "label_id": "label-passive-1",
        "attack_family": "EAVESDROPPING",
        "attack_subtype": "PASSIVE_CAPTURE",
        "impact_start_s": 1.0,
        "end_s": 2.0,
        "target_node_ids": [2],
        "truth": {},
        "outcome": {
            "attack_effective": False,
            "ciphertext_count": 2,
            "plaintext_exposure_count": 0,
            "content_recovery_count": 0,
        },
    }
    result = ExperimentEvaluator().evaluate(
        [], [label], run_record={"duration_s": 3.0}
    )
    assert result["eavesdropping"]["detection_evaluation_applicable"] is False
    assert result["detection_attack_episode_count"] == 0
    assert "EAVESDROPPING" not in result["per_attack_family"]
    assert result["eavesdropping"]["ciphertext_protected_count"] == 2
    assert result["eavesdropping"]["protection_effective"] is True


def _phy_event(at_s: float, sinr: float, per: float) -> dict[str, Any]:
    return {
        "sim_time_s": at_s,
        "event_type": "PHY_SAMPLE",
        "observer_node_id": 2,
        "message_id": None,
        "online_features": {
            "traffic": {},
            "phy": {
                "sinr_db": sinr,
                "snr_db": sinr + 1.0,
                "per_estimate": per,
                "decode_success": None,
            },
        },
        "extensions": {},
    }


def _service_event(at_s: float, success: bool, throughput: float, latency: float) -> dict[str, Any]:
    return {
        "sim_time_s": at_s,
        "event_type": "RX_SUCCESS" if success else "RX_FAILURE",
        "observer_node_id": 2,
        "message_id": f"legitimate-{at_s}",
        "online_features": {
            "traffic": {"throughput_mbps": throughput, "latency_ms": latency, "drop_count": 0},
            "phy": {"decode_success": success, "sinr_db": 10.0 if success else -5.0, "per_estimate": 0.05 if success else 0.95},
        },
        "extensions": {},
    }


def _model_event(at_s: float, family: str, result_id: str) -> dict[str, Any]:
    return {
        "sim_time_s": at_s,
        "event_type": "MODEL_RESULT",
        "observer_node_id": 2,
        "extensions": {
            "model_result": {
                "result_id": result_id,
                "predicted_label": family,
                "evidence_event_ids": [f"evidence-{result_id}"],
            }
        },
        "online_features": {"traffic": {}, "phy": {}},
    }


def _defense_event(at_s: float, family: str, action: str) -> dict[str, Any]:
    return {
        "sim_time_s": at_s,
        "event_type": "DEFENSE_RESULT",
        "observer_node_id": 2,
        "extensions": {
            "defense_result": {
                "executed": True,
                "executed_time_s": at_s,
                "request": {"action": action, "reason": family},
                "outcome": {"legitimate_traffic_harm_score": 0.0},
            }
        },
        "online_features": {"traffic": {}, "phy": {}},
    }


@pytest.mark.parametrize(
    ("family", "subtype", "action", "expected_policy"),
    [
        ("DOS", "FLOODING", "DROP_PACKET", "FLOODING_RECEIVER_RATE_AND_HMAC_GATE"),
        ("REPLAY", "IMMEDIATE_REPLAY", "DROP_PACKET", "REPLAY_REJECTION_WITH_LEGITIMATE_CONTINUITY"),
    ],
)
def test_packet_attack_family_policy_accepts_actual_block_with_service_continuity(
    family, subtype, action, expected_policy
):
    events = [
        _service_event(0.5, True, 10.0, 10.0),
        _model_event(1.1, family, f"{family}-alarm"),
        _defense_event(1.2, family, action),
        _service_event(2.2, True, 9.5, 11.0),
    ]
    label = {
        "attack_id": f"{family.lower()}-effective",
        "label_id": f"label-{family.lower()}-effective",
        "attack_family": family,
        "attack_subtype": subtype,
        "impact_start_s": 1.0,
        "end_s": 2.0,
        "target_node_ids": [2],
        "truth": {},
        "outcome": {
            "attack_effective": True,
            "malicious_traffic_blocked": 3,
            "malicious_traffic_delivered_after_action": 0,
            "receiver_total_rate_exceeded": family == "DOS",
            "application_hmac_passed_before_replay_check": family == "REPLAY",
            "malicious_content_executed": False,
        },
    }
    episode = ExperimentEvaluator(evaluation_window_s=0.5).evaluate(
        events, [label], run_record={"duration_s": 2.5}
    )["episodes"][0]
    assert episode["defense_effective"] is True
    assert episode["defense_policy"] == expected_policy
