"""Cross-mechanism causality and policy audit for the frozen V6 baseline."""

from __future__ import annotations

from typing import Any

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION


def _attack(family: str, subtype: str, **updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 1.2,
        "attacker_node_id": -1,
        "target_node_ids": [1],
        "parameters": {},
        "intensity": {},
    }
    value.update(updates)
    return value


def _traffic(
    *, session: str = "business-a", source: int = 2, count: int = 1
) -> dict[str, Any]:
    return {
        "source_node_id": source,
        "target_node_id": 1,
        "packet_type": "TELEMETRY",
        "start_s": 0.2,
        "interval_s": 0.2,
        "count": count,
        "payload": {"altitude_m": 100.0, "flight_state": "CRUISE"},
        "session_id": session,
        "sequence_start": 100,
    }


class OneShotRffUnknown:
    accepted_event_types = frozenset({"RX_SUCCESS"})

    def __init__(self) -> None:
        self.used = False

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.used = False

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if self.used:
            return []
        self.used = True
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id="rff-observable-unknown",
                observer_node_id=event["observer_node_id"],
                decision_time_s=event["sim_time_s"],
                model_name="rff-observable-test",
                model_version="test-v1",
                status="OK",
                predicted_label="UNKNOWN",
                scores={"UNKNOWN": 0.99},
                confidence=0.99,
                quality=1.0,
                recommended_action=None,
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=None,
                error_code=None,
            )
        ]

    def health(self) -> dict[str, Any]:
        return {"model_name": "rff-observable-test", "status": "OK"}


class PreAuthIsolationModel:
    accepted_event_types = frozenset({"RX_SUCCESS"})

    def __init__(self) -> None:
        self.used = False

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.used = False

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if self.used:
            return []
        self.used = True
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id="pre-auth-isolation",
                observer_node_id=event["observer_node_id"],
                decision_time_s=event["sim_time_s"],
                model_name="bilstm-observable-test",
                model_version="test-v1",
                status="OK",
                predicted_label="SPOOFING",
                scores={"SPOOFING": 0.99},
                confidence=0.99,
                quality=1.0,
                recommended_action="RECOMMEND_DATA_ISOLATION",
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=None,
                error_code=None,
            )
        ]

    def health(self) -> dict[str, Any]:
        return {"model_name": "bilstm-observable-test", "status": "OK"}


def test_combination_a_fdi_plus_packet_loss_keeps_injection_and_delivery_separate():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.4,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "FDI",
                    "TELEMETRY_ABRUPT_CHANGE",
                    attacker_node_id=2,
                    parameters={"field": "altitude_m", "absolute_offset": 50.0},
                )
            ],
            normal_disturbance_specs=[
                {
                    "disturbance_type": "NORMAL_PACKET_LOSS",
                    "start_s": 0.2,
                    "end_s": 1.2,
                    "target_link_ids": ["link-2-1"],
                    "parameters": {"loss_probability": 1.0},
                }
            ],
            traffic_specs=[_traffic()],
        )
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["outcome"]["injected"] is True
    assert label["outcome"]["reached_target"] is False
    assert label["outcome"]["malicious_content_executed"] is False
    assert DatasetLeakageAudit.audit_events(runtime.events).passed


def test_combination_c_replay_and_legal_reorder_remain_distinguishable_by_protocol():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.8,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "REPLAY",
                    "IMMEDIATE_REPLAY",
                    impact_start_s=0.8,
                    end_s=1.6,
                    parameters={"max_capture_age_s": 1.0},
                )
            ],
            normal_disturbance_specs=[
                {
                    "disturbance_type": "NORMAL_OUT_OF_ORDER",
                    "start_s": 0.2,
                    "end_s": 1.0,
                    "target_node_ids": [1],
                    "parameters": {
                        "source_node_id": 2,
                        "sequence_numbers": [100, 102, 101],
                        "session_id": "legal-sequence-session",
                    },
                }
            ],
            traffic_specs=[_traffic(session="capture-session")],
            tx_service_per_step=32,
            rx_service_per_step=32,
        )
    )
    runtime.run_to_completion()
    legal_session = runtime.observable_session_id("legal-sequence-session")
    legal = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["packet"]["session_id"] == legal_session
    ]
    replay = runtime.attack_scheduler.labels()[0]
    replay_checks = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["message_id"] == replay["truth"].get("replayed_message_id")
    ]
    assert legal[:3] == ["PASS", "PASS", "PASS"]
    assert legal[-1] == "DUPLICATE"
    assert "DUPLICATE" in replay_checks
    assert replay["outcome"]["malicious_content_executed"] is False


def test_combination_d_spoof_rff_unknown_and_auth_fail_are_locally_consistent():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "SPOOFING",
                    "KNOWN_ID_CONFLICT",
                    end_s=0.8,
                    attacker_node_id=-1,
                    parameters={"claimed_src_id": 0},
                )
            ],
        ),
        model_adapters={"rff": OneShotRffUnknown()},
    )
    runtime.run_to_completion()
    spoof = runtime.attack_scheduler.labels()[0]
    assert spoof["outcome"]["reached_target"] is True
    assert spoof["outcome"]["malicious_content_executed"] is False
    later_auth = [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["observer_node_id"] == 1
        and event["online_features"]["security_state"]["auth_result"] == "FAIL"
    ]
    assert later_auth
    assert all(
        event["online_features"]["security_state"]["rff_identity_result"]
        == "UNKNOWN"
        for event in later_auth
    )
    assert runtime.rl_observation(1)["security"]["rff_anomaly_count"] > 0


def test_combination_e_flooding_and_legitimate_burst_share_observable_template():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.4,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "DOS",
                    "FLOODING",
                    attacker_node_id=2,
                    intensity={"value": 30.0, "unit": "pps"},
                    parameters={
                        "packet_type": "STATUS",
                        "target_packet_size_bytes": 192,
                    },
                )
            ],
            normal_disturbance_specs=[
                {
                    "disturbance_type": "NORMAL_TRAFFIC_BURST",
                    "start_s": 0.2,
                    "end_s": 1.2,
                    "target_node_ids": [1],
                    "parameters": {
                        "source_node_id": 2,
                        "packet_rate_pps": 20.0,
                        "packet_type": "STATUS",
                        "target_packet_size_bytes": 192,
                    },
                }
            ],
            tx_service_per_step=64,
            rx_service_per_step=64,
        )
    )
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["outcome"]["injected"] is True
    normal = next(iter(runtime.normal_disturbances.records.values()))
    assert normal.evidence["generated_count"] > 0
    observed_types = {
        event["online_features"]["packet"]["packet_type"]
        for event in runtime.events
        if event["event_type"] == "TX"
    }
    assert "STATUS" in observed_types
    assert not ({"FLOOD", "LEGITIMATE_BURST", "NORMAL_BURST"} & observed_types)
    assert DatasetLeakageAudit.audit_events(runtime.events).passed


def test_combination_g_pre_auth_model_is_deferred_and_later_rule_controls_action():
    model = PreAuthIsolationModel()
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "SPOOFING",
                    "KNOWN_ID_CONFLICT",
                    end_s=0.8,
                    attacker_node_id=-1,
                    parameters={"claimed_src_id": 0},
                )
            ],
        ),
        model_adapters={"bilstm": model},
    )
    runtime.run_to_completion()
    defenses = [
        event["extensions"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
    ]
    assert any(
        item.get("decision_audit", {}).get("model_result_id")
        == "pre-auth-isolation"
        and not item["defense_result"]["executed"]
        for item in defenses
    )
    assert any(
        item.get("decision_audit", {}).get("source") == "RULE"
        and item["defense_result"]["executed"]
        for item in defenses
    )
    assert 0 not in runtime.nodes[1].isolated_peer_ids
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(6800, {"duration_s": 0.6, "auto_traffic": False})
    _, outcome, _ = env.step(
        {"action": "RECOMMEND_DATA_ISOLATION", "peer_id": 0}
    )
    assert outcome["executed"] is False
