from __future__ import annotations

from typing import Any

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from .regression.test_v3_audit_regressions import OneShotAdapter


class AuthFailureAdapter(OneShotAdapter):
    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        security = event.get("online_features", {}).get("security_state", {})
        if event.get("message_id") is None or security.get("auth_result") != "FAIL":
            return []
        return super().observe(event)


def _fusion_results(runtime: PlatformRuntime) -> list[dict[str, Any]]:
    return [
        event["extensions"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("decision_audit", {}).get("source")
        == "FUSION"
    ]


def test_high_confidence_model_recommendation_is_authorized_by_b_and_executed():
    adapter = OneShotAdapter(
        "bilstm-decision",
        {"RX_SUCCESS"},
        "RX_SUCCESS",
        "FDI",
        "RECOMMEND_DATA_ISOLATION",
        confidence=0.99,
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False),
        model_adapters={"bilstm": adapter},
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    attempts = _fusion_results(runtime)
    assert attempts[0]["decision_audit"]["decision_reason"] == "AUTHENTICATION_PENDING"
    result = next(
        item for item in attempts if item["defense_result"]["executed"]
    )
    assert result["decision_audit"]["decision_reason"] == "MODEL_POLICY_ACCEPTED"
    assert result["defense_result"]["executed"] is True


def test_low_confidence_model_recommendation_is_audited_but_not_executed():
    adapter = OneShotAdapter(
        "bilstm-low",
        {"RX_SUCCESS"},
        "RX_SUCCESS",
        "FDI",
        "RECOMMEND_DATA_ISOLATION",
        confidence=0.4,
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False),
        model_adapters={"bilstm": adapter},
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    result = _fusion_results(runtime)[0]
    assert result["decision_audit"]["decision_reason"] == "MODEL_CONFIDENCE_BELOW_THRESHOLD"
    assert result["defense_result"]["executed"] is False


def test_high_certainty_auth_rule_has_priority_over_model_recommendation():
    adapter = AuthFailureAdapter(
        "bilstm-conflict",
        {"AUTH_RESULT"},
        "AUTH_RESULT",
        "SPOOFING",
        "RECOMMEND_INCREASE_MONITORING",
        confidence=0.99,
    )
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, auto_traffic=False),
        model_adapters={"bilstm": adapter},
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "UNKNOWN_ID",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.0,
            "end_s": 0.6,
            "attacker_node_id": -1,
            "target_node_ids": [1],
        }
    )
    runtime.run_to_completion()
    fused = _fusion_results(runtime)
    assert fused
    assert fused[0]["decision_audit"]["decision_reason"] == "RULE_HIGH_CERTAINTY_PRIORITY"
    assert fused[0]["defense_result"]["executed"] is False
    assert any(
        event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("defense_result", {}).get("request", {}).get("action")
        == "DROP_PACKET"
        for event in runtime.events
    )
