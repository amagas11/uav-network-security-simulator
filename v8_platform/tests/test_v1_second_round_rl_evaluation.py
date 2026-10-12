from __future__ import annotations

from copy import deepcopy

from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.rl import UavDefenseEnv


def _walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def _model_event(at_s: float, predicted: str, *, result_id: str, observer: int = 1):
    return {
        "sim_time_s": at_s,
        "event_type": "MODEL_RESULT",
        "observer_node_id": observer,
        "extensions": {
            "model_result": {
                "result_id": result_id,
                "predicted_label": predicted,
                "evidence_event_ids": [f"evidence-{result_id}"],
            }
        },
        "online_features": {"traffic": {}, "phy": {}},
    }


def _traffic_event(at_s: float, *, throughput: float, latency: float, event_type: str = "RX_SUCCESS"):
    return {
        "sim_time_s": at_s,
        "event_type": event_type,
        "observer_node_id": 1,
        "message_id": f"msg-{at_s}",
        "online_features": {
            "traffic": {
                "throughput_mbps": throughput,
                "latency_ms": latency,
                "drop_count": 0,
            },
            "phy": {"decode_success": event_type == "RX_SUCCESS"},
        },
        "extensions": {},
    }


def _label(start: float, end: float, *, attack_id: str, family: str = "DOS", outcome=None):
    return {
        "attack_id": attack_id,
        "label_id": f"label-{attack_id}",
        "attack_family": family,
        "attack_subtype": "FLOODING" if family == "DOS" else "UNKNOWN_ID",
        "impact_start_s": start,
        "end_s": end,
        "target_node_ids": [1],
        "truth": {},
        "outcome": dict(outcome or {}),
    }


def test_rl_state_has_required_windows_phy_security_model_node_and_defense_groups():
    env = UavDefenseEnv(observer_node_id=1)
    observation = env.reset(31, {"duration_s": 1.2, "auto_traffic": False})
    assert set(observation) >= {
        "schema_version",
        "run_id",
        "observer_node_id",
        "sim_time_s",
        "recent_2s",
        "recent_5s",
        "phy",
        "security",
        "model",
        "node",
        "defense_resource",
        "availability",
    }
    for window in (observation["recent_2s"], observation["recent_5s"]):
        assert set(window) >= {
            "packet_rate_pps",
            "error_rate",
            "queue_length",
            "latency_ms",
            "throughput_mbps",
        }
    assert observation["model"]["bilstm"]["status"] == "UNAVAILABLE"
    assert observation["model"]["bilstm"]["scores"] is None
    assert observation["model"]["bilstm"]["confidence"] is None
    assert not ({"attack_type", "attack_family", "attack_subtype", "labels", "attacker_node_id"} & set(_walk_keys(observation)))


def test_rl_reset_clears_previous_episode_statistics():
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(32, {"duration_s": 1.2, "auto_traffic": False, "tx_service_per_step": 16, "rx_service_per_step": 16})
    runtime = env.episode.runtime
    for _ in range(5):
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    env.step("NO_CHANGE")
    assert env.episode.runtime.rl_observation(1)["recent_2s"]["packet_rate_pps"] > 0

    observation = env.reset(33, {"duration_s": 1.2, "auto_traffic": False})
    assert observation["recent_2s"]["packet_rate_pps"] == 0.0
    assert observation["recent_5s"]["packet_rate_pps"] == 0.0


def test_flooding_changes_rl_local_state_without_truth_fields():
    flood_env = UavDefenseEnv(observer_node_id=1)
    flood_env.reset(34, {"duration_s": 1.6, "auto_traffic": False, "tx_service_per_step": 64, "rx_service_per_step": 64})
    flood_env.episode.runtime.schedule_attack(
        {
            "attack_family": "DOS",
            "attack_subtype": "FLOODING",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 1.4,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "intensity": {"value": 50.0, "unit": "pps"},
        }
    )
    flood_state, _, _ = flood_env.step("NO_CHANGE")
    assert flood_state["recent_2s"]["packet_rate_pps"] > 0
    assert "attack_family" not in set(_walk_keys(flood_state))


def test_rl_defense_action_changes_state_and_outcome_has_real_service_metrics():
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(36, {"duration_s": 1.2, "auto_traffic": False, "tx_service_per_step": 16, "rx_service_per_step": 16})
    runtime = env.episode.runtime
    for _ in range(4):
        runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    observation, outcome, terminated = env.step("INCREASE_MONITORING")
    assert not terminated
    assert outcome["allowed"] and outcome["executed"]
    assert outcome["execution_time_s"] is not None
    assert outcome["throughput_mbps"] is not None
    assert outcome["latency_ms"] is not None
    assert outcome["availability"]["throughput_mbps"] is True
    assert observation["defense_resource"]["monitoring_level"] == 1
    assert "reward" not in set(_walk_keys(outcome))
    assert "reward_weights" not in set(_walk_keys(observation))


def test_evaluator_counts_one_episode_once_with_duplicate_alarm_not_fp():
    events = [
        _model_event(1.2, "DOS", result_id="a"),
        _model_event(1.4, "DOS", result_id="b"),
    ]
    result = ExperimentEvaluator(evaluation_window_s=1.0).evaluate(
        events,
        [_label(1.0, 2.0, attack_id="dos-one")],
        run_record={"duration_s": 3.0},
    )
    metrics = result["per_attack_family"]["DOS"]
    assert metrics["TP"] == 1
    assert metrics["FP"] == 0
    assert metrics["duplicate_alarm_count"] == 1


def test_evaluator_fn_tn_and_normal_false_positive_use_defined_windows():
    evaluator = ExperimentEvaluator(evaluation_window_s=1.0)
    missed = evaluator.evaluate(
        [], [_label(1.0, 2.0, attack_id="missed")], run_record={"duration_s": 4.0}
    )["per_attack_family"]["DOS"]
    assert missed["FN"] == 1
    assert missed["TN"] > 0

    false_alarm = evaluator.evaluate(
        [_model_event(0.4, "DOS", result_id="fp")],
        [_label(2.0, 3.0, attack_id="later")],
        run_record={"duration_s": 4.0},
    )["per_attack_family"]["DOS"]
    assert false_alarm["FP"] == 1
    assert false_alarm["TN"] > 0
    assert false_alarm["pfa_fpr"] == false_alarm["FP"] / (false_alarm["FP"] + false_alarm["TN"])


def test_evaluator_counts_alarm_in_entirely_normal_run_as_false_positive():
    result = ExperimentEvaluator(evaluation_window_s=1.0).evaluate(
        [_model_event(0.4, "DOS", result_id="normal-fp")],
        [],
        run_record={"duration_s": 2.0},
    )
    assert result["per_attack_family"]["DOS"]["TP"] == 0
    assert result["per_attack_family"]["DOS"]["FP"] == 1
    assert result["per_attack_family"]["DOS"]["TN"] == 1


def test_wrong_family_alarm_during_attack_is_not_tp_and_is_family_false_positive():
    result = ExperimentEvaluator(evaluation_window_s=1.0).evaluate(
        [_model_event(1.2, "DOS", result_id="wrong-family")],
        [_label(1.0, 2.0, attack_id="spoof", family="SPOOFING")],
        run_record={"duration_s": 3.0},
    )
    assert result["per_attack_family"]["SPOOFING"]["TP"] == 0
    assert result["per_attack_family"]["SPOOFING"]["FN"] == 1
    assert result["per_attack_family"]["DOS"]["TP"] == 0
    assert result["per_attack_family"]["DOS"]["FP"] == 1


def test_evaluator_two_separate_episodes_are_two_true_positives_and_family_matches():
    events = [
        _model_event(1.1, "DOS", result_id="dos-a"),
        _model_event(3.1, "DOS", result_id="dos-b"),
        _model_event(5.1, "SPOOFING", result_id="wrong-family"),
    ]
    labels = [
        _label(1.0, 1.8, attack_id="one"),
        _label(3.0, 3.8, attack_id="two"),
        _label(5.0, 5.8, attack_id="spoof", family="SPOOFING"),
    ]
    result = ExperimentEvaluator(evaluation_window_s=1.0).evaluate(
        events, labels, run_record={"duration_s": 6.0}
    )
    assert result["per_attack_family"]["DOS"]["TP"] == 2
    assert result["per_attack_family"]["SPOOFING"]["TP"] == 1


def test_evaluator_separates_action_execution_from_actual_effectiveness():
    events = [
        _model_event(1.1, "DOS", result_id="detected"),
        {
            "sim_time_s": 1.2,
            "event_type": "DEFENSE_RESULT",
            "observer_node_id": 1,
            "extensions": {
                "defense_result": {
                    "executed": True,
                    "executed_time_s": 1.2,
                    "request": {"action": "RATE_LIMIT", "reason": "DOS"},
                    "outcome": {},
                }
            },
            "online_features": {"traffic": {}, "phy": {}},
        },
        _traffic_event(1.4, throughput=0.1, latency=200.0),
    ]
    label = _label(
        1.0,
        2.0,
        attack_id="continued",
        outcome={
            "attack_effective": True,
            "malicious_traffic_blocked": 0,
            "malicious_traffic_delivered_after_action": 4,
        },
    )
    result = ExperimentEvaluator(evaluation_window_s=0.5).evaluate(
        events, [label], run_record={"duration_s": 2.5}
    )
    episode = result["episodes"][0]
    assert episode["action_executed"] is True
    assert episode["defense_effective"] is False


def test_physically_ineffective_attack_is_not_automatic_defense_success():
    label = _label(
        1.0,
        2.0,
        attack_id="ineffective",
        outcome={"attack_effective": False},
    )
    result = ExperimentEvaluator().evaluate([], [label], run_record={"duration_s": 3.0})
    episode = result["episodes"][0]
    assert episode["attack_effective"] is False
    assert episode["action_executed"] is False
    assert episode["defense_effective"] is False


def test_report_delay_and_service_metrics_are_separate_and_explainable():
    events = [
        _traffic_event(0.2, throughput=10.0, latency=10.0),
        _model_event(1.1, "DOS", result_id="alarm"),
        _traffic_event(1.3, throughput=2.0, latency=40.0),
        _traffic_event(2.4, throughput=9.0, latency=11.0),
    ]
    reports = [
        {
            "report_id": "report-1",
            "source_node_id": 1,
            "category": "DOS",
            "event_time_s": 1.0,
            "detection_time_s": 1.1,
            "action_time_s": 1.2,
            "report_received_time_s": 1.9,
        }
    ]
    label = _label(1.0, 2.0, attack_id="service", outcome={"attack_effective": True})
    result = ExperimentEvaluator(evaluation_window_s=0.5).evaluate(
        events,
        [label],
        reports=reports,
        run_record={"duration_s": 3.0},
    )
    episode = result["episodes"][0]
    assert episode["detection_delay_s"] == 0.1
    assert episode["report_delay_s"] == 0.8
    assert episode["legitimate_service_damage"] > 0
    assert episode["service_recovery_time_s"] is not None
    assert result["metric_definitions"]["evaluation_unit"] == "ATTACK_EPISODE_AND_NORMAL_TIME_WINDOW"
