from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.events import find_label_proxies
from swarm_sim.simulation import ConfigValidationError, SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator


def _attack(family: str, subtype: str, **values: Any) -> dict[str, Any]:
    result = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.0,
        "end_s": 0.6,
        "target_node_ids": [1],
    }
    result.update(values)
    return result


def _export(runtime: PlatformRuntime, root: Path) -> Path:
    runtime.run_to_completion()
    runtime.export_dataset(root)
    return root


def _rewrite(path: Path, file_name: str, mutate) -> None:
    target = path / file_name
    rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    mutate(rows)
    target.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def _model_event(time_s: float, observer: int, label: str, result_id: str) -> dict[str, Any]:
    return {
        "event_id": f"evt-{result_id}",
        "sim_time_s": time_s,
        "event_type": "MODEL_RESULT",
        "observer_node_id": observer,
        "message_id": None,
        "online_features": {"packet": {}, "phy": {}, "traffic": {}},
        "extensions": {
            "model_result": {
                "result_id": result_id,
                "predicted_label": label,
                "evidence_event_ids": [],
            }
        },
    }


def _phy_event(time_s: float, observer: int, sinr: float, per: float) -> dict[str, Any]:
    return {
        "event_id": f"phy-{observer}-{time_s}",
        "sim_time_s": time_s,
        "event_type": "PHY_SAMPLE",
        "observer_node_id": observer,
        "message_id": None,
        "online_features": {
            "packet": {},
            "traffic": {},
            "phy": {"sinr_db": sinr, "per_estimate": per},
        },
        "extensions": {},
    }


def _defense_event(time_s: float, observer: int, action: str) -> dict[str, Any]:
    return {
        "event_id": f"def-{observer}-{time_s}",
        "sim_time_s": time_s,
        "event_type": "DEFENSE_RESULT",
        "observer_node_id": observer,
        "message_id": None,
        "online_features": {"packet": {}, "phy": {}, "traffic": {}},
        "extensions": {
            "defense_result": {
                "executed": True,
                "executed_time_s": time_s,
                "request": {"action": action, "reason": "DOS"},
                "target": {"node_id": observer, "link_id": None, "peer_id": None},
                "outcome": {"legitimate_traffic_harm_score": 0.0},
            }
        },
    }


class OneShotAdapter:
    def __init__(
        self,
        name: str,
        accepted: set[str],
        trigger: str,
        predicted: str,
        action: str | None,
        confidence: float = 0.99,
    ) -> None:
        self.name = name
        self.accepted_event_types = frozenset(accepted)
        self.trigger = trigger
        self.predicted = predicted
        self.action = action
        self.confidence = confidence
        self.emitted = False

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.emitted = False

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if self.emitted or event["event_type"] != self.trigger:
            return []
        self.emitted = True
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id=f"{self.name}-one",
                observer_node_id=event["observer_node_id"],
                decision_time_s=event["sim_time_s"],
                model_name=self.name,
                model_version="fake-observable-v1",
                status="OK",
                predicted_label=self.predicted,
                scores={self.predicted: self.confidence},
                confidence=self.confidence,
                quality=1.0,
                recommended_action=self.action,
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=0.0,
                error_code=None,
            )
        ]

    def health(self) -> dict[str, Any]:
        return {"model_name": self.name, "status": "OK", "model_version": "fake-observable-v1", "error_code": None}


def test_case_1_flooding_dedicated_emitter_exports_valid_observable_references(tmp_path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, step_s=0.2, auto_traffic=False, queue_capacity=20, tx_service_per_step=1),
        run_id="v4-flood-backlog",
    )
    runtime.schedule_attack(
        _attack(
            "DOS",
            "FLOODING",
            attacker_node_id=2,
            intensity={"value": 100.0, "unit": "pps"},
            parameters={"packet_type": "STATUS", "packet_size_bytes": 128},
            end_s=0.4,
        )
    )
    root = _export(runtime, tmp_path)
    report = DatasetValidator().validate(root)
    assert report.valid, report.errors
    label = runtime.attack_scheduler.labels()[0]
    event_messages = {event["message_id"] for event in runtime.events if event["message_id"]}
    # V11 intentionally retired the old "flood the attacker's ordinary TX
    # queue" behavior.  The configured pps now represents actual air-TX
    # attempts, independently of the legitimate tx_service_per_step=1 budget.
    assert label["truth"]["generated_packets"] == 20
    assert label["truth"]["transmitted_packets"] == 20
    assert not label["truth"]["backlogged_message_ids"]
    assert set(label["truth"]["affected_message_ids"]) <= event_messages
    assert set(label["truth"]["generated_message_ids"]) <= event_messages
    assert label["outcome"]["queued_backlog_count"] == 0
    assert label["outcome"].get("queue_pressure_observed", False) is False


def test_case_2_flooding_and_normal_burst_share_business_type_without_shortcut():
    normal = PlatformRuntime(RunConfig(duration_s=0.6, auto_traffic=False, tx_service_per_step=16), run_id="v4-normal-burst")
    normal.schedule_normal_disturbance({"disturbance_type": "NORMAL_TRAFFIC_BURST", "start_s": 0.0, "end_s": 0.4, "target_node_ids": [1], "parameters": {"source_node_id": 2, "packet_rate_pps": 20.0, "packet_type": "STATUS"}})
    attack = PlatformRuntime(RunConfig(duration_s=0.6, auto_traffic=False, tx_service_per_step=16), run_id="v4-flood")
    attack.schedule_attack(_attack("DOS", "FLOODING", attacker_node_id=2, intensity={"value": 20.0, "unit": "pps"}, parameters={"packet_type": "STATUS"}, end_s=0.4))
    normal.run_to_completion()
    attack.run_to_completion()
    normal_types = {event["online_features"]["packet"]["packet_type"] for event in normal.events if event["message_id"]}
    attack_types = {event["online_features"]["packet"]["packet_type"] for event in attack.events if event["message_id"]}
    assert normal_types == attack_types == {"STATUS"}
    assert all(not find_label_proxies(event) for event in normal.events + attack.events)


def test_case_3_normal_disturbance_truth_is_provenance_only(tmp_path):
    specs = [
        {"disturbance_type": "NORMAL_LOW_SNR", "start_s": 0.0, "end_s": 0.6, "target_link_ids": ["link-2-1"], "parameters": {"attenuation_db": 20.0}},
        {"disturbance_type": "NORMAL_PACKET_LOSS", "start_s": 0.0, "end_s": 0.6, "target_link_ids": ["link-2-1"], "parameters": {"loss_probability": 0.1}},
        {"disturbance_type": "NORMAL_TRAFFIC_BURST", "start_s": 0.0, "end_s": 0.6, "target_node_ids": [1], "parameters": {"source_node_id": 2, "packet_rate_pps": 10.0}},
        {"disturbance_type": "NORMAL_OUT_OF_ORDER", "start_s": 0.0, "end_s": 0.6, "target_node_ids": [1], "parameters": {"source_node_id": 2}},
        {"disturbance_type": "NORMAL_STATE_CHANGE", "start_s": 0.0, "end_s": 0.6, "target_node_ids": [2], "parameters": {"battery_pct": 75.0}},
        {"disturbance_type": "NORMAL_CONGESTION", "start_s": 0.0, "end_s": 0.6, "target_node_ids": [1], "parameters": {"source_node_id": 2, "packet_rate_pps": 10.0}},
    ]
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False, normal_disturbance_specs=specs), run_id="v4-normal-six")
    _export(runtime, tmp_path)
    assert all(not find_label_proxies(event) for event in runtime.events)
    encoded_events = json.dumps(runtime.events)
    assert "NORMAL_" not in encoded_events
    assert len(runtime.run_record()["normal_disturbance_plan"]) == 6
    assert runtime.attack_scheduler.labels() == []


def test_case_4_fdi_attacker_and_target_have_distinct_business_semantics():
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8), run_id="v4-fdi-scope")
    runtime.schedule_attack(_attack("FDI", "TELEMETRY_ABRUPT_CHANGE", attacker_node_id=2, target_node_ids=[1], parameters={"field": "altitude_m", "absolute_offset": 50.0}))
    attacked = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True)
    untouched_origin = runtime.queue_message(3, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True)
    untouched_target = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True)
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    changed_ids = {item["message_id"] for item in label["truth"]["modifications"]}
    assert changed_ids == {attacked}
    assert untouched_origin not in changed_ids and untouched_target not in changed_ids
    assert label["attacker_node_id"] == label["truth"]["actual_transmitter_id"] == 2
    assert label["target_node_ids"] == [1]
    assert any(
        event["event_type"] == "AUTH_RESULT"
        and event["message_id"] == attacked
        and event["online_features"]["security_state"][
            "application_hmac_result"
        ]
        == "FAIL"
        for event in runtime.events
    )
    assert label["outcome"]["malicious_content_executed"] is False


def test_case_5_unrelated_alarm_is_not_target_episode_tp():
    label = {"attack_id": "scope-a", "attack_family": "DOS", "attack_subtype": "FLOODING", "impact_start_s": 1.0, "end_s": 2.0, "target_node_ids": [2], "truth": {}, "outcome": {}}
    result = ExperimentEvaluator().evaluate([_model_event(1.2, 3, "DOS", "wrong-node")], [label], run_record={"duration_s": 3.0})
    family = result["per_attack_family"]["DOS"]
    assert (family["TP"], family["FN"], family["FP"]) == (0, 1, 1)


def test_case_7_old_session_uses_lifecycle_not_attack_detector_oracle(monkeypatch):
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False, rx_service_per_step=8), run_id="v4-old-lifecycle")
    runtime.schedule_attack(_attack("REPLAY", "OLD_SESSION_REPLAY", impact_start_s=0.8, end_s=1.2, attacker_node_id=-1, parameters={"stale_session_id": "A"}))
    old_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}, session_id="A", sequence_no=1)
    runtime.start()
    runtime.step()
    runtime.step()
    runtime.rotate_security_session(2, 1, old_session_id="A", new_session_id="B")

    def forbidden(*args, **kwargs):
        raise AssertionError("attack injection called detector.expire_session")

    monkeypatch.setattr(runtime.rules[1], "expire_session", forbidden)
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 101.0}, session_id="B", sequence_no=1)
    while not runtime.is_terminated:
        runtime.debug_step()
    results = [event["online_features"]["security_state"]["replay_check_result"] for event in runtime.events if event["event_type"] == "AUTH_RESULT" and event["message_id"] == old_id]
    assert "WRONG_SESSION" in results


def test_case_8_rff_unknown_updates_local_security_and_rl_state():
    rff = OneShotAdapter("rff-fake", {"RX_SUCCESS"}, "RX_SUCCESS", "UNKNOWN", None)
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8), run_id="v4-rff-state", model_adapters={"rff": rff})
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert runtime.nodes[1].rff_identity_result == "UNKNOWN"
    assert runtime.nodes[1].rff_anomaly_count == 1
    assert runtime.rl_observation(1)["security"]["rff_anomaly_count"] > 0


def test_case_9_model_recommendation_flows_through_fusion_and_executor():
    model = OneShotAdapter("bilstm-fake", {"RX_SUCCESS"}, "RX_SUCCESS", "FDI", "RECOMMEND_DATA_ISOLATION")
    runtime = PlatformRuntime(RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8), run_id="v4-model-defense", model_adapters={"bilstm": model})
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    fused = [event for event in runtime.events if event["event_type"] == "DEFENSE_RESULT" and event.get("extensions", {}).get("decision_audit", {}).get("model_result_id") == "bilstm-fake-one"]
    assert fused
    result = next(
        event["extensions"]["defense_result"]
        for event in fused
        if event["extensions"]["defense_result"]["executed"]
    )
    assert result["allowed"] is True and result["executed"] is True
    assert result["request"]["action"] == "DATA_ISOLATION"
    assert 2 in runtime.nodes[1].isolated_peer_ids


def test_case_10_validator_rejects_unknown_observer(tmp_path):
    root = _export(PlatformRuntime(RunConfig(duration_s=0.2, auto_traffic=False), run_id="v4-bad-observer"), tmp_path)
    _rewrite(root, "events.jsonl", lambda rows: rows[0].__setitem__("observer_node_id", 999))
    report = DatasetValidator().validate(root)
    assert not report.valid and any("observer_node_id" in error and "not declared" in error for error in report.errors)


def test_case_11_validator_rejects_observer_role_mismatch(tmp_path):
    root = _export(PlatformRuntime(RunConfig(duration_s=0.2, auto_traffic=False), run_id="v4-bad-role"), tmp_path)
    _rewrite(root, "events.jsonl", lambda rows: rows[0].__setitem__("observer_role", "FOLLOWER"))
    report = DatasetValidator().validate(root)
    assert not report.valid and any("observer_role" in error and "does not match" in error for error in report.errors)


def test_case_12_validator_rejects_label_attack_id_not_in_run_plan(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False), run_id="v4-bad-attack-id")
    runtime.schedule_attack(_attack("DOS", "FLOODING", attacker_node_id=2, intensity={"value": 5.0, "unit": "pps"}, end_s=0.4))
    root = _export(runtime, tmp_path)
    _rewrite(root, "labels.jsonl", lambda rows: rows[0].__setitem__("attack_id", "not-in-plan"))
    report = DatasetValidator().validate(root)
    assert not report.valid and any("attack_id" in error and "run attack_plan" in error for error in report.errors)


def test_case_13_validator_rejects_unknown_core_nested_field(tmp_path):
    root = _export(PlatformRuntime(RunConfig(duration_s=0.2, auto_traffic=False), run_id="v4-unknown-phy"), tmp_path)
    _rewrite(root, "events.jsonl", lambda rows: rows[0]["online_features"]["phy"].__setitem__("unexpected_field", 1))
    report = DatasetValidator().validate(root)
    assert not report.valid and any("unexpected_field" in error and "unknown" in error for error in report.errors)


def test_case_14_run_config_typo_fails_fast():
    with pytest.raises(ConfigValidationError, match="attak_specs"):
        RunConfig.from_dict({"attak_specs": []})
    assert RunConfig.from_dict({"attak_specs": []}, strict=False).attack_specs == []


def test_case_15_metadata_only_phase_and_unimplemented_traffic_profile_do_not_change_semantic_hash():
    base = RunConfig(seed=1)
    changed = RunConfig(seed=1, episode_phases={"normal_end_s": 99}, traffic_profile_id="not-loaded")
    assert base.semantic_fingerprint() == changed.semantic_fingerprint()


def test_case_16_channel_switch_is_reciprocal_and_probe_rejects_mismatch():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="v4-probe-channel")
    before = runtime.phy.states["link-2-1"].frequency_hz
    result = runtime.phy.switch_channel("link-2-1")
    assert result["affected_link_ids"] == ["link-2-1", "link-1-2"]
    assert runtime.phy.states["link-2-1"].frequency_hz == runtime.phy.states["link-1-2"].frequency_hz != before
    first, second = runtime.probes.probe(2, 1)
    assert not first.missing and first.freq_hz == second.freq_hz
    runtime.phy.states["link-1-2"].frequency_hz += 1e6
    first, second = runtime.probes.probe(2, 1)
    assert first.missing and second.missing
    assert first.missing_reason == second.missing_reason == "FREQUENCY_MISMATCH"
