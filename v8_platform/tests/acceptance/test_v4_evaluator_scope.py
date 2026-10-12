from __future__ import annotations

from typing import Any

from swarm_sim.evaluation import ExperimentEvaluator
from ..regression.test_v3_audit_regressions import (
    _defense_event,
    _model_event,
    _phy_event,
)


def _label(
    family: str,
    subtype: str,
    *,
    target: int,
    attacker: int | None = None,
) -> dict[str, Any]:
    return {
        "attack_id": f"scope-{family}-{target}",
        "attack_family": family,
        "attack_subtype": subtype,
        "impact_start_s": 1.0,
        "end_s": 2.0,
        "attacker_node_id": attacker,
        "target_node_ids": [target],
        "target_link_ids": [],
        "truth": {},
        "outcome": {"attack_effective": True},
    }


def _rx(time_s: float, observer: int, success: bool) -> dict[str, Any]:
    return {
        "event_id": f"rx-{observer}-{time_s}",
        "sim_time_s": time_s,
        "event_type": "RX_SUCCESS" if success else "RX_FAILURE",
        "observer_node_id": observer,
        "message_id": f"m-{observer}-{time_s}",
        "online_features": {
            "packet": {},
            "phy": {
                "sinr_db": 10.0 if success else -8.0,
                "per_estimate": 0.05 if success else 0.99,
            },
            "traffic": {
                "throughput_mbps": 8.0 if success else 0.0,
                "latency_ms": 10.0 if success else 0.0,
                "drop_count": int(not success),
            },
        },
        "extensions": {},
    }


def test_e_scope_1_unrelated_node_alarm_is_not_target_tp():
    result = ExperimentEvaluator().evaluate(
        [_model_event(1.2, 3, "DOS", "unrelated")],
        [_label("DOS", "FLOODING", target=2)],
        run_record={"duration_s": 3.0},
    )["per_attack_family"]["DOS"]
    assert (result["TP"], result["FN"], result["FP"]) == (0, 1, 1)


def test_e_scope_2_target_node_correct_alarm_is_tp():
    result = ExperimentEvaluator().evaluate(
        [_model_event(1.2, 2, "DOS", "target")],
        [_label("DOS", "FLOODING", target=2)],
        run_record={"duration_s": 3.0},
    )["per_attack_family"]["DOS"]
    assert (result["TP"], result["FN"]) == (1, 0)


def test_e_scope_5_fdi_compromised_sender_and_target_receiver_match():
    episode = ExperimentEvaluator().evaluate(
        [_model_event(1.2, 1, "FDI", "leader-detection")],
        [_label("FDI", "TELEMETRY_ABRUPT_CHANGE", target=1, attacker=2)],
        run_record={"duration_s": 3.0},
    )["episodes"][0]
    assert episode["episode_detected"] is True
    assert episode["attack_scope"]["target_node_ids"] == [1]
    assert episode["attack_scope"]["relevant_observer_ids"] == [1]
