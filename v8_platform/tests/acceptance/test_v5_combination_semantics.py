from __future__ import annotations

from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION


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
        return {
            "model_name": self.name,
            "status": "OK",
            "model_version": "fake-observable-v1",
            "error_code": None,
        }


class RffStateAdapter(OneShotAdapter):
    def __init__(self, state: str) -> None:
        super().__init__(
            f"rff-{state.lower()}",
            {"RX_SUCCESS"},
            "RX_SUCCESS",
            state if state in {"KNOWN", "UNKNOWN"} else "UNKNOWN",
            None,
        )
        self.state = state

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        values = super().observe(event)
        if not values:
            return []
        result = values[0]
        if self.state in {"ERROR", "UNAVAILABLE"}:
            result.status = self.state
            result.predicted_label = None
            result.scores = None
            result.confidence = None
            result.error_code = f"RFF_{self.state}"
        return [result]


def _fdi_plan(**overrides):
    plan = {
        "attack_family": "FDI",
        "attack_subtype": "TELEMETRY_ABRUPT_CHANGE",
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.0,
        "end_s": 0.8,
        "attacker_node_id": 2,
        "target_node_ids": [1],
        "parameters": {"field": "altitude_m", "absolute_offset": 50.0},
    }
    plan.update(overrides)
    return plan


def test_spoofing_model_recommendation_waits_for_auth_and_never_isolates_claim():
    model = OneShotAdapter(
        "bilstm-combo-spoof",
        {"RX_SUCCESS"},
        "RX_SUCCESS",
        "SPOOFING",
        "RECOMMEND_DATA_ISOLATION",
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, rx_service_per_step=16),
        model_adapters={"bilstm": model},
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "KNOWN_ID_CONFLICT",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.0,
            "end_s": 0.8,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "parameters": {"claimed_src_id": 0},
        }
    )
    runtime.run_to_completion()
    fusion = [
        event["extensions"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("decision_audit", {}).get("source")
        == "FUSION"
    ]
    assert fusion[0]["decision_audit"]["decision_reason"] == "AUTHENTICATION_PENDING"
    assert all(not item["defense_result"]["executed"] for item in fusion)
    assert 0 not in runtime.nodes[1].isolated_peer_ids
    assert any(
        event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["security_state"]["auth_result"] == "FAIL"
        for event in runtime.events
    )


def test_fdi_injection_plus_phy_loss_keeps_target_side_outcome_false():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False), run_id="v5-combo-fdi-loss"
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
    runtime.schedule_attack(_fdi_plan())
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["injected"] is True
    assert outcome["reached_target"] is False
    assert outcome["malicious_content_executed"] is False
    assert outcome["attack_effective"] is False


def test_flood_rate_limit_blocks_attack_and_records_legitimate_harm():
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(
        5503,
        {
            "duration_s": 1.2,
            "decision_step_s": 0.8,
            "auto_traffic": False,
            "queue_capacity": 96,
            "tx_service_per_step": 64,
            "rx_service_per_step": 64,
            "attack_specs": [
                {
                    "attack_family": "DOS",
                    "attack_subtype": "FLOODING",
                    "scheduled_start_s": 0.0,
                    "impact_start_s": 0.0,
                    "end_s": 1.0,
                    "attacker_node_id": 2,
                    "target_node_ids": [1],
                    "intensity": {"value": 30.0, "unit": "pps"},
                    "parameters": {"packet_type": "STATUS", "packet_size_bytes": 192},
                }
            ],
        },
    )
    env.episode.runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0},
        session_id="combo-legitimate",
        sequence_no=1,
    )
    env.episode.runtime.debug_step()
    env.episode.runtime.debug_step()
    _, outcome, _ = env.step({"action": "RECOMMEND_RATE_LIMIT", "peer_id": 2})
    assert outcome["executed"] is True
    assert outcome["malicious_traffic_blocked"] > 0
    # The only legitimate packet was delivered before the action interval;
    # therefore the measured (rather than assumed) collateral harm is zero.
    assert outcome["legitimate_traffic_harmed"] is False
    assert outcome["legitimate_traffic_harm_score"] == 0.0


def test_replay_near_legal_reorder_preserves_pass_and_duplicate_distinction():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, rx_service_per_step=32)
    )
    runtime.schedule_normal_disturbance(
        {
            "disturbance_type": "NORMAL_OUT_OF_ORDER",
            "start_s": 0.0,
            "end_s": 0.4,
            "target_node_ids": [1],
            "parameters": {
                "source_node_id": 2,
                "sequence_numbers": [100, 102, 101],
                "session_id": "combo-order",
            },
        }
    )
    runtime.schedule_attack(
        {
            "attack_family": "REPLAY",
            "attack_subtype": "IMMEDIATE_REPLAY",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.8,
            "end_s": 1.2,
            "attacker_node_id": -1,
            "target_node_ids": [1],
        }
    )
    runtime.run_to_completion()
    checks = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT" and event["message_id"] is not None
    ]
    assert "PASS" in checks
    assert "DUPLICATE" in checks


def test_rff_unknown_remains_in_auth_snapshot_and_dueling_observation():
    rff = OneShotAdapter(
        "rff-combo", {"RX_SUCCESS"}, "RX_SUCCESS", "UNKNOWN", None
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=16),
        model_adapters={"rff": rff},
    )
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    auth = next(
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT" and event["message_id"] == message_id
    )
    assert auth["online_features"]["security_state"]["rff_identity_result"] == "UNKNOWN"
    assert runtime.rl_observation(1)["security"]["rff_anomaly_count"] > 0


@pytest.mark.parametrize(
    ("state", "expected_anomalies"),
    [("KNOWN", 0), ("UNKNOWN", 1), ("ERROR", 0), ("UNAVAILABLE", 0)],
)
def test_rff_final_state_matrix_is_consistent_across_local_snapshots(
    state: str, expected_anomalies: int
):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False, rx_service_per_step=16),
        model_adapters={"rff": RffStateAdapter(state)},
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    expected = state
    assert runtime.nodes[1].rff_identity_result == expected
    later = [
        event
        for event in runtime.events
        if event["observer_node_id"] == 1
        and event["sim_time_s"] >= (runtime.nodes[1].rff_last_update_s or 0.0)
        and event["event_type"] in {"AUTH_RESULT", "PHY_SAMPLE", "QUEUE_SAMPLE"}
    ]
    assert later
    assert all(
        event["online_features"]["security_state"]["rff_identity_result"] == expected
        for event in later
    )
    assert runtime.rl_observation(1)["security"]["rff_anomaly_count"] == expected_anomalies

