from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.traffic import LocalTrafficAccumulator
from swarm_sim.validation import DatasetValidator
from .test_v3_audit_regressions import OneShotAdapter


def _attack(family: str, subtype: str, **values: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.0,
        "end_s": 0.8,
        "target_node_ids": [1],
    }
    result.update(values)
    return result


def _fusion_results(runtime: PlatformRuntime, result_id: str | None = None) -> list[dict[str, Any]]:
    values = [
        event["extensions"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("decision_audit", {}).get("source")
        == "FUSION"
    ]
    if result_id is not None:
        values = [
            item
            for item in values
            if item.get("decision_audit", {}).get("model_result_id") == result_id
        ]
    return values


class LinkSampleAdapter(OneShotAdapter):
    def __init__(self) -> None:
        super().__init__(
            "bilstm-link",
            {"PHY_SAMPLE"},
            "PHY_SAMPLE",
            "DOS",
            "RECOMMEND_CHANNEL_SWITCH",
        )
        self.observable_link_id: str | None = None

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if event.get("extensions", {}).get("sample_link_id") != self.observable_link_id:
            return []
        return super().observe(event)


def test_case_1_spoofed_claimed_gcs_cannot_trigger_legitimate_gcs_isolation():
    model = OneShotAdapter(
        "bilstm-spoof",
        {"RX_SUCCESS"},
        "RX_SUCCESS",
        "SPOOFING",
        "RECOMMEND_DATA_ISOLATION",
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, rx_service_per_step=8),
        run_id="v5-spoof-target",
        model_adapters={"bilstm": model},
    )
    runtime.schedule_attack(
        _attack(
            "SPOOFING",
            "KNOWN_ID_CONFLICT",
            attacker_node_id=-1,
            parameters={"claimed_src_id": 0},
        )
    )
    runtime.run_to_completion()
    assert 0 not in runtime.nodes[1].isolated_peer_ids
    audited = _fusion_results(runtime, "bilstm-spoof-one")
    assert audited
    assert all(
        item["defense_result"].get("target", {}).get("peer_id") != 0
        or not item["defense_result"].get("executed")
        for item in audited
    )


def test_case_2_phy_sample_model_channel_switch_resolves_real_direct_link():
    adapter = LinkSampleAdapter()
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.6, auto_traffic=False),
        run_id="v5-phy-target",
        model_adapters={"bilstm": adapter},
    )
    adapter.observable_link_id = runtime.observable_link_id("link-2-1")
    before = runtime.phy.states["link-2-1"].frequency_hz
    runtime.run_to_completion()
    attempts = _fusion_results(runtime, "bilstm-link-one")
    executed = [item["defense_result"] for item in attempts if item["defense_result"]["executed"]]
    assert executed
    assert executed[0]["target"]["link_id"] == runtime.observable_link_id("link-2-1")
    assert runtime.phy.states["link-2-1"].frequency_hz != before


def _defense_event(
    time_s: float, *, executed: bool, failure: str | None, source: str
) -> dict[str, Any]:
    return {
        "event_id": f"def-{time_s}",
        "sim_time_s": time_s,
        "event_type": "DEFENSE_RESULT",
        "observer_node_id": 1,
        "message_id": None,
        "online_features": {"packet": {}, "phy": {}, "traffic": {}},
        "extensions": {
            "defense_result": {
                "allowed": executed,
                "executed": executed,
                "executed_time_s": time_s if executed else None,
                "failure_reason": failure,
                "request": {"action": "DROP_PACKET", "reason": "DOS"},
                "target": {"node_id": 1, "link_id": None, "peer_id": 2},
                "outcome": {"legitimate_traffic_harm_score": 0.0},
            },
            "decision_audit": {
                "source": source,
                "recommendation_source": "MODEL" if source == "FUSION" else "RULE",
            },
        },
    }


def test_case_3_denied_model_attempt_does_not_hide_later_executed_rule_defense():
    events = [
        _defense_event(0.2, executed=False, failure="MODEL_POLICY_DENIED", source="FUSION"),
        _defense_event(0.4, executed=True, failure=None, source="RULE"),
    ]
    label = {
        "attack_id": "multi-defense",
        "attack_family": "DOS",
        "attack_subtype": "FLOODING",
        "impact_start_s": 0.0,
        "end_s": 0.8,
        "target_node_ids": [1],
        "target_link_ids": [],
        "truth": {},
        "outcome": {"malicious_traffic_blocked": 1},
    }
    episode = ExperimentEvaluator().evaluate(
        events, [label], run_record={"duration_s": 1.0}
    )["episodes"][0]
    assert episode["action_executed"] is True
    assert episode["action_delay_s"] == pytest.approx(0.4)
    assert episode["denied_action_count"] == 1
    assert episode["denied_recommendation_count"] == 1
    assert len(episode["defense_attempts"]) == 2


def test_case_3b_multiple_executed_defenses_use_first_relevant_execution_time():
    events = [
        _defense_event(0.3, executed=True, failure=None, source="RULE"),
        _defense_event(0.5, executed=True, failure=None, source="RULE"),
    ]
    label = {
        "attack_id": "multiple-executed-defense",
        "attack_family": "DOS",
        "attack_subtype": "FLOODING",
        "impact_start_s": 0.0,
        "end_s": 0.8,
        "target_node_ids": [1],
        "target_link_ids": [],
        "truth": {},
        "outcome": {"malicious_traffic_blocked": 1},
    }
    episode = ExperimentEvaluator().evaluate(
        events, [label], run_record={"duration_s": 1.0}
    )["episodes"][0]
    assert episode["action_executed"] is True
    assert episode["action_delay_s"] == pytest.approx(0.3)
    assert episode["executed_defense_count"] == 2
    assert len(episode["defense_attempts"]) == 2


def _authenticated_payload_key_support(runtime: PlatformRuntime) -> set[str]:
    support: set[str] = set()
    for event in runtime.events:
        if event["event_type"] != "AUTH_RESULT":
            continue
        numeric = event["online_features"]["packet"].get("payload_numeric") or {}
        support.update(numeric)
    return support


def _burst_and_flood() -> tuple[PlatformRuntime, PlatformRuntime]:
    normal = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=16, rx_service_per_step=16),
        run_id="v5-normal-template",
    )
    normal.schedule_normal_disturbance(
        {
            "disturbance_type": "NORMAL_TRAFFIC_BURST",
            "start_s": 0.0,
            "end_s": 0.6,
            "target_node_ids": [1],
            "parameters": {
                "source_node_id": 2,
                "packet_rate_pps": 20.0,
                "packet_type": "STATUS",
                "packet_size_bytes": 256,
            },
        }
    )
    flood = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=16, rx_service_per_step=16),
        run_id="v5-flood-template",
    )
    flood.schedule_attack(
        _attack(
            "DOS",
            "FLOODING",
            attacker_node_id=2,
            intensity={"value": 20.0, "unit": "pps"},
            parameters={"packet_type": "STATUS", "packet_size_bytes": 256},
            end_s=0.6,
        )
    )
    normal.run_to_completion()
    flood.run_to_completion()
    return normal, flood


def test_case_4_flood_and_normal_burst_share_one_business_payload_schema():
    normal, flood = _burst_and_flood()
    normal_keys = _authenticated_payload_key_support(normal)
    flood_keys = _authenticated_payload_key_support(flood)
    assert normal_keys == flood_keys
    assert "burst_index" not in normal_keys
    assert "padding_bytes" not in flood_keys


def test_case_5_configured_packet_size_is_canonical_serialized_application_size():
    normal, flood = _burst_and_flood()

    def sizes(runtime: PlatformRuntime) -> set[int]:
        return {
            int(event["online_features"]["packet"]["packet_size_bytes"])
            for event in runtime.events
            if event["event_type"] == "TX"
            and event["online_features"]["packet"]["packet_type"] == "STATUS"
        }

    assert sizes(normal) == sizes(flood) == {256}


def test_case_6_fdi_injected_but_lost_before_target_is_not_effective():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="v5-fdi-lost",
    )
    runtime.schedule_normal_disturbance(
        {
            "disturbance_type": "NORMAL_PACKET_LOSS",
            "start_s": 0.0,
            "end_s": 0.8,
            "target_link_ids": ["link-2-1"],
            "parameters": {"loss_probability": 1.0},
        }
    )
    runtime.schedule_attack(
        _attack(
            "FDI",
            "TELEMETRY_ABRUPT_CHANGE",
            attacker_node_id=2,
            parameters={"field": "altitude_m", "absolute_offset": 50.0},
        )
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True)
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["attempted"] is True
    assert outcome["injected"] is True
    assert outcome["reached_target"] is False
    assert outcome["malicious_content_executed"] is False
    assert outcome["attack_effective"] is False


def test_case_7_rff_unknown_persists_in_later_auth_and_local_snapshots():
    rff = OneShotAdapter("rff-v5", {"RX_SUCCESS"}, "RX_SUCCESS", "UNKNOWN", None)
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8),
        run_id="v5-rff-consistency",
        model_adapters={"rff": rff},
    )
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    later = [
        event
        for event in runtime.events
        if event["observer_node_id"] == 1
        and event["sim_time_s"] >= runtime.nodes[1].rff_last_update_s
        and event["event_type"] in {"AUTH_RESULT", "PHY_SAMPLE", "QUEUE_SAMPLE"}
    ]
    assert any(event["event_type"] == "AUTH_RESULT" and event["message_id"] == message_id for event in later)
    assert all(
        event["online_features"]["security_state"]["rff_identity_result"] == "UNKNOWN"
        for event in later
    )


def test_case_8_multi_target_plan_is_explicitly_rejected_in_v6():
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, auto_traffic=False))
    with pytest.raises(ValueError, match="MULTI_TARGET_NOT_SUPPORTED_V6"):
        runtime.schedule_attack(
            _attack(
                "DOS",
                "FLOODING",
                attacker_node_id=2,
                target_node_ids=[1, 3],
                intensity={"value": 10.0, "unit": "pps"},
            )
        )


def test_case_9_runtime_defaults_are_resolved_into_run_and_label_truth():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False), run_id="v5-resolved-default"
    )
    runtime.schedule_attack(
        _attack("SPOOFING", "UNKNOWN_ID", attacker_node_id=None, target_node_ids=[])
    )
    runtime.run_to_completion()
    run_plan = runtime.run_record()["attack_plan"][0]
    label = runtime.attack_scheduler.labels()[0]
    assert run_plan["attacker_node_id"] == label["attacker_node_id"] == -1
    assert run_plan["target_node_ids"] == label["target_node_ids"] == [1]
    assert label["truth"]["resolved_plan"]["target_node_ids"] == [1]
    assert label["truth"]["requested_plan"]["target_node_ids"] == []


def test_case_10_unmeasured_rl_overhead_is_null_with_unavailable_reason():
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False))
    resource = runtime.rl_observation(1)["defense_resource"]
    assert resource["communication_overhead_bytes"] is None
    assert resource["compute_overhead_ms"] is None
    assert resource["availability"]["communication_overhead_bytes"] is False
    assert resource["availability"]["compute_overhead_ms"] is False


def _arrival(time_s: float, sequence: int) -> dict[str, Any]:
    return {
        "observer_node_id": 1,
        "sim_time_s": time_s,
        "event_type": "RX_SUCCESS",
        "online_features": {
            "packet": {
                "packet_type": "STATUS",
                "claimed_src_id": 2,
                "session_id": "gap-v5",
                "key_epoch": 1,
                "sequence_no": sequence,
                "packet_size_bytes": 64,
            },
            "traffic": {"latency_ms": 1.0},
        },
    }


def test_case_11_gap_outside_recent_window_is_no_longer_counted():
    traffic = LocalTrafficAccumulator(default_window_s=1.0)
    traffic.enrich(_arrival(0.0, 100))
    traffic.enrich(_arrival(0.1, 102))
    assert traffic.snapshot(1, 0.1)["sequence_gap_count"] == 1
    assert traffic.snapshot(1, 1.2)["sequence_gap_count"] == 0


def test_case_12_known_id_conflict_scenario_exports_valid_auth_failure(tmp_path: Path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=8),
        run_id="v5-known-id-conflict",
    )
    runtime.schedule_attack(
        _attack(
            "SPOOFING",
            "KNOWN_ID_CONFLICT",
            attacker_node_id=-1,
            parameters={"claimed_src_id": 0},
        )
    )
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["identity_conflict"] is True
    assert any(
        event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["security_state"]["auth_result"] == "FAIL"
        for event in runtime.events
    )
    assert json.dumps(runtime.events).find("actual_transmitter_id") == -1
