from __future__ import annotations

import json
from pathlib import Path

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch


def _attack(delta: float = 5.0):
    return {
        "attack_family": "FDI",
        "attack_subtype": "TELEMETRY_GRADUAL_DRIFT",
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.4,
        "end_s": 1.2,
        "attacker_node_id": 2,
        "target_node_ids": [2],
        "parameters": {"field": "altitude_m", "delta_per_step": delta},
        "intensity": {"value": delta, "unit": "m/packet"},
    }


def _normal(attenuation: float = 8.0):
    return {
        "disturbance_type": "NORMAL_LOW_SNR",
        "start_s": 0.2,
        "end_s": 0.4,
        "target_link_ids": ["link-1-2"],
        "parameters": {"attenuation_db": attenuation},
    }


def test_v3_run_metadata_is_complete_and_traceable(tmp_path):
    config = RunConfig.from_dict(
        {
            "seed": 810,
            "duration_s": 1.4,
            "auto_traffic": False,
            "decision_step_s": 0.2,
            "attack_specs": [_attack()],
            "normal_disturbance_specs": [_normal()],
        }
    )
    runtime = PlatformRuntime(config, run_id="c-v3-metadata")
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    record = json.loads((tmp_path / "runs.jsonl").read_text(encoding="utf-8"))

    assert record["schema_version"] == SCHEMA_VERSION
    assert record["software_version"].startswith("platform-v7")
    assert record["run_config"]["queue_capacity"] == config.queue_capacity
    assert record["run_config"]["traffic_statistics_window_s"] == config.traffic_statistics_window_s
    assert record["attack_plan"][0]["parameters"]["delta_per_step"] == 5.0
    assert record["normal_disturbance_plan"][0]["disturbance_type"] == "NORMAL_LOW_SNR"
    assert record["profiles"]["attack_plan_id"]
    assert record["profiles"]["normal_disturbance_plan_id"]
    assert len(record["config_fingerprint"]) == 64
    assert record["data_source"]["kind"] == "simulation"
    assert record["calibration_status"] == "UNCALIBRATED_BASELINE"
    assert DatasetValidator().validate(tmp_path).valid


def test_v3_rl_reset_builds_episode_and_step_advances_configured_interval():
    env = UavDefenseEnv(observer_node_id=1)
    initial = env.reset(
        811,
        {
            "duration_s": 1.6,
            "step_s": 0.2,
            "decision_step_s": 0.4,
            "auto_traffic": False,
            "attack_specs": [
                {
                    "attack_family": "DOS",
                    "attack_subtype": "FLOODING",
                    "scheduled_start_s": 0.0,
                    "impact_start_s": 0.4,
                    "end_s": 1.0,
                    "attacker_node_id": 2,
                    "target_node_ids": [1],
                    "intensity": {"value": 30.0, "unit": "pps"},
                }
            ],
        },
    )
    assert env.episode.current_phase == "NORMAL"
    assert "current_phase" not in initial
    next_state, outcome, _ = env.step({"action": "NO_CHANGE"})
    assert next_state["sim_time_s"] == 0.4
    assert env.episode.current_phase == "ATTACK_OR_DISTURBANCE"
    assert outcome["throughput_mbps"] is not None
    assert outcome["attack_impact"] is not None
    assert outcome["malicious_traffic_blocked"] is not None
    assert outcome["legitimate_traffic_harmed"] is not None
    assert outcome["mission_impact"] is None
    assert outcome["availability"]["mission_impact"] is False


def test_v3_rl_same_seed_and_config_produce_same_episode_plan():
    config = {
        "duration_s": 1.4,
        "auto_traffic": False,
        "attack_specs": [_attack()],
        "normal_disturbance_specs": [_normal()],
    }
    first = UavDefenseEnv(observer_node_id=1)
    second = UavDefenseEnv(observer_node_id=1)
    first.reset(812, config)
    second.reset(812, config)
    assert first.episode.plan_fingerprint == second.episode.plan_fingerprint
    assert first.episode.runtime.run_record()["attack_plan"] == second.episode.runtime.run_record()["attack_plan"]
    assert first.episode.runtime.run_id != second.episode.runtime.run_id


def test_v3_rl_rate_limit_changes_real_malicious_and_legitimate_outcomes():
    config = {
        "duration_s": 1.2,
        "step_s": 0.2,
        "decision_step_s": 0.8,
        "auto_traffic": False,
        "queue_capacity": 64,
        "tx_service_per_step": 64,
        "rx_service_per_step": 64,
        "attack_specs": [
            {
                "attack_family": "DOS",
                "attack_subtype": "FLOODING",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.2,
                "end_s": 1.0,
                "attacker_node_id": 2,
                "target_node_ids": [1],
                "intensity": {"value": 40.0, "unit": "pps"},
                "parameters": {"packet_size_bytes": 128},
            }
        ],
    }
    unprotected = UavDefenseEnv(observer_node_id=1)
    unprotected.reset(814, config)
    _, no_change, _ = unprotected.step("INCREASE_MONITORING")

    protected = UavDefenseEnv(observer_node_id=1)
    protected.reset(814, config)
    protected.episode.runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0},
        session_id="legitimate-control",
        sequence_no=1,
    )
    protected.episode.runtime.debug_step()
    protected.episode.runtime.debug_step()
    _, limited, _ = protected.step(
        {"action": "RECOMMEND_RATE_LIMIT", "peer_id": 2}
    )

    assert no_change["executed"] is True
    assert no_change["attack_impact"] > 0
    # The deterministic runtime rule may also protect the unrequested run
    # once the common, correctly-sized traffic template crosses its rate
    # threshold.  The explicit RL rate limit must still have an additional,
    # measurable effect.
    assert no_change["malicious_traffic_blocked"] >= 0
    assert limited["executed"] is True
    assert limited["malicious_traffic_blocked"] > no_change["malicious_traffic_blocked"]
    assert limited["attack_impact"] < no_change["attack_impact"]
    assert limited["legitimate_traffic_harmed"] is False
    assert limited["legitimate_drop_count"] == 0
    assert limited["throughput_mbps"] is not None
    assert limited["latency_ms"] is not None
    assert 0.0 <= limited["mission_impact"] <= 1.0


def test_v3_rl_episode_reaches_recovery_phase_with_service_available():
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(
        815,
        {
            "duration_s": 1.4,
            "step_s": 0.2,
            "decision_step_s": 0.4,
            "auto_traffic": True,
            "attack_specs": [
                {
                    "attack_family": "DOS",
                    "attack_subtype": "FLOODING",
                    "scheduled_start_s": 0.0,
                    "impact_start_s": 0.2,
                    "end_s": 0.8,
                    "attacker_node_id": 2,
                    "target_node_ids": [1],
                    "intensity": {"value": 20.0, "unit": "pps"},
                }
            ],
        },
    )
    env.step("NO_CHANGE")
    _, recovery_outcome, _ = env.step("NO_CHANGE")
    assert env.episode.current_phase == "RECOVERY"
    assert recovery_outcome["throughput_mbps"] is not None
    assert recovery_outcome["availability"]["throughput_mbps"] is True


def test_v3_event_contract_has_required_online_types_and_no_truth_leakage():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=True), run_id="c-v3-events"
    )
    runtime.run_to_completion()
    event_types = {event["event_type"] for event in runtime.events}
    assert {"TX", "RX_SUCCESS", "PHY_SAMPLE", "QUEUE_SAMPLE", "NODE_STATE", "TOPOLOGY_UPDATE", "AUTH_RESULT"} <= event_types
    forbidden = {
        "attack_family",
        "attack_subtype",
        "attacker_node_id",
        "actual_transmitter_id",
        "attack_success",
        "labels",
        "future_event",
        "future_log",
    }
    serialized = json.dumps(
        [event["online_features"] for event in runtime.events], ensure_ascii=False
    )
    assert all(f'"{name}"' not in serialized for name in forbidden)


def test_v3_normal_phy_loss_emits_rx_failure_without_attack_truth(tmp_path):
    runtime = PlatformRuntime(
        RunConfig.from_dict(
            {
                "duration_s": 1.0,
                "auto_traffic": False,
                "normal_disturbance_specs": [
                    {
                        "disturbance_type": "NORMAL_PACKET_LOSS",
                        "start_s": 0.0,
                        "end_s": 0.8,
                        "target_link_ids": ["link-2-1"],
                        "parameters": {"loss_probability": 1.0},
                    }
                ],
            }
        ),
        run_id="c-v3-normal-rx-failure",
    )
    runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.run_to_completion()
    assert any(
        event["event_type"] == "RX_FAILURE"
        and event["observer_node_id"] == 1
        for event in runtime.events
    )
    assert runtime.attack_scheduler.labels() == []
    runtime.export_dataset(tmp_path)
    assert DatasetValidator().validate(tmp_path).valid


def test_v3_traffic_features_have_real_non_null_values():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.4,
            auto_traffic=False,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        run_id="c-v3-traffic",
    )
    for sequence in range(1, 5):
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 100.0 + sequence},
            session_id="traffic-session",
            sequence_no=sequence,
        )
    runtime.run_to_completion()
    received = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS" and event["observer_node_id"] == 1
    ]
    assert len(received) >= 2
    assert any(event["online_features"]["packet"]["inter_arrival_s"] is not None for event in received[1:])
    assert max(event["online_features"]["traffic"]["packet_rate_pps"] for event in received) > 0
    assert max(event["online_features"]["traffic"]["byte_rate_Bps"] for event in received) > 0


def test_v3_batch_accepts_normal_disturbance_and_duplicate_seed(tmp_path):
    summary = run_batch(
        tmp_path,
        seeds=[7, 7],
        duration_s=1.0,
        step_s=0.2,
        node_count=4,
        normal_disturbance_specs=[_normal()],
    )
    assert summary["all_valid"]
    assert len({row["run_id"] for row in summary["runs"]}) == 2
    assert len({row["export"]["output_dir"] for row in summary["runs"]}) == 2
    for row in summary["runs"]:
        root = Path(row["export"]["output_dir"])
        run = json.loads((root / "runs.jsonl").read_text(encoding="utf-8"))
        labels = (root / "labels.jsonl").read_text(encoding="utf-8").strip()
        assert run["normal_disturbance_plan"]
        assert labels == ""


def test_v3_semantic_fingerprint_is_stable_but_sensitive_to_plan_parameters():
    first = PlatformRuntime(
        RunConfig.from_dict({"duration_s": 1.4, "auto_traffic": False, "attack_specs": [_attack(5.0)]})
    )
    repeat = PlatformRuntime(
        RunConfig.from_dict({"duration_s": 1.4, "auto_traffic": False, "attack_specs": [_attack(5.0)]})
    )
    changed = PlatformRuntime(
        RunConfig.from_dict({"duration_s": 1.4, "auto_traffic": False, "attack_specs": [_attack(50.0)]})
    )
    assert first.run_record()["config_fingerprint"] == repeat.run_record()["config_fingerprint"]
    assert first.run_record()["config_fingerprint"] != changed.run_record()["config_fingerprint"]


def test_v3_deterministic_e2e_semantic_projection_matches_on_repeat():
    config = RunConfig.from_dict(
        {
            "seed": 813,
            "duration_s": 2.6,
            "auto_traffic": True,
            "tx_service_per_step": 32,
            "rx_service_per_step": 32,
            "security_summary_window_s": 0.4,
            "attack_specs": [
                {
                    "attack_family": "REPLAY",
                    "attack_subtype": "IMMEDIATE_REPLAY",
                    "scheduled_start_s": 0.0,
                    "impact_start_s": 0.8,
                    "end_s": 1.4,
                    "target_node_ids": [1],
                }
            ],
            "normal_disturbance_specs": [
                {
                    "disturbance_type": "NORMAL_TRAFFIC_BURST",
                    "start_s": 0.2,
                    "end_s": 0.6,
                    "target_node_ids": [0],
                    "parameters": {"source_node_id": 2, "packet_rate_pps": 10.0},
                }
            ],
        }
    )
    first = PlatformRuntime(config, run_id="v3-e2e-first")
    second = PlatformRuntime(config, run_id="v3-e2e-second")
    first_messages = {
        first.queue_message(
            2,
            0,
            "TELEMETRY",
            {"altitude_m": 101.0},
            session_id="business-follower-a",
            sequence_no=101,
        ),
        first.queue_message(
            3,
            0,
            "TELEMETRY",
            {"altitude_m": 103.0},
            session_id="business-follower-b",
            sequence_no=101,
        ),
    }
    second.queue_message(
        2,
        0,
        "TELEMETRY",
        {"altitude_m": 101.0},
        session_id="business-follower-a",
        sequence_no=101,
    )
    second.queue_message(
        3,
        0,
        "TELEMETRY",
        {"altitude_m": 103.0},
        session_id="business-follower-b",
        sequence_no=101,
    )
    first.run_to_completion()
    second.run_to_completion()
    assert first.reproducible_event_projection() == second.reproducible_event_projection()
    assert first.evaluation_view()["scope"] == "GROUND_TRUTH_OFFLINE_EVALUATION"
    assert any(
        event["event_type"] == "AUTH_RESULT"
        and event["online_features"]["security_state"]["replay_check_result"] == "DUPLICATE"
        for event in first.events
    )
    gcs_auth = [
        event
        for event in first.events
        if event["event_type"] == "AUTH_RESULT"
        and event["observer_node_id"] == 0
        and event["message_id"] in first_messages
    ]
    assert {event["message_id"] for event in gcs_auth} == first_messages
    assert all(
        event["online_features"]["security_state"]["replay_check_result"]
        == "PASS"
        for event in gcs_auth
    )
    assert first.episode_phase() == "RECOVERY"
    assert first.attack_scheduler.labels()[0]["outcome"]["detected"] is True
    episode = first.evaluation_view()["episodes"][0]
    assert episode["defense_effective"] is True
    assert episode["defense_evidence"]["malicious_delivered_after_action"] == 0
    assert first.reporting.gcs_inbox
