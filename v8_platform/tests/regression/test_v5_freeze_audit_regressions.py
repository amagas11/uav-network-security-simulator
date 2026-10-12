from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.evaluation import ExperimentEvaluator
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch


def _attack(family: str, subtype: str, **values: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 1.2,
        "target_node_ids": [1],
        "parameters": {},
        "intensity": {},
    }
    plan.update(values)
    return plan


def _telemetry(count: int = 3, *, session_id: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            "source_node_id": 2,
            "target_node_id": 1,
            "packet_type": "TELEMETRY",
            "start_s": 0.2,
            "interval_s": 0.2,
            "count": count,
            "payload": {
                "altitude_m": 100.0,
                "battery_pct": 90.0,
                "flight_state": "FLYING",
            },
            "sensitive": True,
            **({"session_id": session_id} if session_id else {}),
        }
    ]


class RecordingAdapter:
    accepted_event_types = frozenset(
        {
            "TX",
            "RX_SUCCESS",
            "RX_FAILURE",
            "PHY_SAMPLE",
            "QUEUE_SAMPLE",
            "NODE_STATE",
            "TOPOLOGY_UPDATE",
            "AUTH_RESULT",
        }
    )

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.received.clear()

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        self.received.append(event)
        return []

    def health(self) -> dict[str, Any]:
        return {"model_name": "recording", "status": "OK"}


def _fdi_gradual_config() -> RunConfig:
    return RunConfig(
        seed=606,
        duration_s=1.4,
        step_s=0.2,
        auto_traffic=False,
        tx_service_per_step=32,
        rx_service_per_step=32,
        attack_specs=[
            _attack(
                "FDI",
                "TELEMETRY_GRADUAL_DRIFT",
                attacker_node_id=2,
                parameters={"field": "altitude_m", "delta_per_step": 5.0},
            )
        ],
        traffic_specs=_telemetry(3),
    )


def test_case_1_final_matrix_fdi_gradual_requires_real_accumulated_injection():
    runtime = PlatformRuntime(_fdi_gradual_config(), run_id="audit-fdi-gradual")
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    modifications = label["truth"].get("modifications", [])
    assert label["outcome"]["eligible_opportunity_seen"] is True
    assert label["outcome"]["attempted"] is True
    assert label["outcome"]["injected"] is True
    assert [row["modified_value"]["altitude_m"] for row in modifications] == [
        105.0,
        110.0,
        115.0,
    ]


def test_case_1b_fdi_attempt_requires_an_eligible_sender_target_and_field():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "FDI",
                    "TELEMETRY_ABRUPT_CHANGE",
                    end_s=0.8,
                    attacker_node_id=2,
                    target_node_ids=[1],
                    parameters={"field": "altitude_m", "absolute_offset": 50.0},
                )
            ],
            traffic_specs=[
                {
                    **_telemetry(1)[0],
                    "source_node_id": 3,
                },
                {
                    **_telemetry(1)[0],
                    "target_node_id": 0,
                },
                {
                    **_telemetry(1)[0],
                    "payload": {"battery_pct": 90.0},
                },
            ],
        )
    )
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["attack_active"] is True
    assert outcome["eligible_opportunity_seen"] is False
    assert outcome["attempted"] is False
    assert outcome["injected"] is False


def test_case_2_formal_run_batch_fdi_gradual_injects_without_test_queue_hook(
    tmp_path: Path,
):
    summary = run_batch(
        tmp_path,
        seeds=[606],
        duration_s=1.4,
        step_s=0.2,
        node_count=4,
        attack_specs=_fdi_gradual_config().attack_specs,
        traffic_specs=_telemetry(3),
    )
    row = summary["runs"][0]
    assert row["validation"]["valid"] is True
    label = row["mechanism_evidence"]["labels"][0]
    assert label["outcome"]["injected"] is True
    assert len(label["truth"]["modifications"]) == 3


def test_case_3_external_attacker_is_not_encoded_in_online_identifiers():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            step_s=0.2,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "SPOOFING",
                    "UNKNOWN_ID",
                    end_s=0.6,
                    attacker_node_id=-1,
                )
            ],
        ),
        run_id="spoof-external-private-minus-one",
    )
    runtime.run_to_completion()
    identifiers = DatasetLeakageAudit.collect_online_identifiers(runtime.events)
    assert identifiers
    assert all("-1" not in value for value in identifiers)
    assert DatasetLeakageAudit.audit_events(runtime.events).passed


def test_case_4_normal_reorder_session_id_is_opaque():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            step_s=0.2,
            auto_traffic=False,
            normal_disturbance_specs=[
                {
                    "disturbance_type": "NORMAL_OUT_OF_ORDER",
                    "start_s": 0.0,
                    "end_s": 0.6,
                    "target_node_ids": [1],
                    "parameters": {
                        "source_node_id": 2,
                        "sequence_numbers": [100, 102, 101],
                        "session_id": "normal-reorder-profile-answer",
                    },
                }
            ],
        )
    )
    runtime.run_to_completion()
    sessions = {
        event["online_features"]["packet"]["session_id"]
        for event in runtime.events
        if event["online_features"]["packet"]["session_id"]
    }
    assert sessions
    assert all(re.fullmatch(r"sess-[0-9a-f]{12}-\d{8}", value) for value in sessions)


def test_case_4b_leakage_audit_rejects_scenario_bearing_identifier():
    report = DatasetLeakageAudit.audit_events(
        [
            {
                "online_features": {
                    "packet": {"session_id": "session-replay-old-session"}
                },
                "availability": {},
                "extensions": {"sample_link_id": "link--1-1"},
            }
        ]
    )
    assert report.passed is False
    assert any("scenario-bearing identifier" in error for error in report.errors)
    assert any("endpoint-encoded identifier" in error for error in report.errors)


def test_case_4c_numeric_hash_prefix_stays_opaque_and_audit_safe(tmp_path: Path):
    """V6P-OPAQUE-ID-STABILITY-001: a numeric SHA prefix is not an endpoint."""

    # This real batch run id hashes to the all-decimal prefix 563586642103.
    # Before the closure patch, otherwise-valid lnk/sess IDs were therefore
    # rejected as if they encoded numeric simulator endpoints.
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, step_s=0.2),
        run_id="batch-c7e3ae46ace247e9ab55253f45364c53-run-0002-seed-7",
    )
    runtime.run_to_completion()

    identifiers = DatasetLeakageAudit.collect_online_identifiers(runtime.events)
    assert identifiers
    assert all(not re.search(r"(?:^|[-_:])-?\d+[-_:]-?\d+(?:$|[-_:])", value) for value in identifiers)
    assert DatasetLeakageAudit.audit_events(runtime.events).passed is True

    output_dir = tmp_path / "numeric-hash-scope"
    runtime.export_dataset(output_dir)
    assert DatasetValidator().validate(output_dir).valid is True


def test_case_5_external_observer_never_reaches_default_c_model_stream():
    recorder = RecordingAdapter()
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            step_s=0.2,
            auto_traffic=False,
            attack_specs=[
                _attack(
                    "SPOOFING", "UNKNOWN_ID", end_s=0.6, attacker_node_id=-1
                )
            ],
        ),
        model_adapters={"bilstm": recorder},
    )
    runtime.run_to_completion()
    assert recorder.received
    assert all(event["observer_role"] != "EXTERNAL" for event in recorder.received)
    assert not [
        event
        for event in runtime.events
        if event["observer_role"] == "EXTERNAL"
        and event["event_type"] in {"MODEL_RESULT", "DEFENSE_RESULT"}
    ]


def test_case_6_rl_agent_has_no_direct_isolation_privilege():
    env = UavDefenseEnv(observer_node_id=1)
    env.reset(
        606,
        {"duration_s": 0.8, "step_s": 0.2, "auto_traffic": False},
    )
    _observation, outcome, _terminated = env.step(
        {"action": "RECOMMEND_DATA_ISOLATION", "peer_id": 0}
    )
    assert outcome["executed"] is False
    assert outcome["decision_reason"] in {
        "AUTHENTICATION_PENDING",
        "DIRECT_PEER_EVIDENCE_REQUIRED",
        "MODEL_EVIDENCE_NOT_FOUND",
    }
    assert 0 not in env.episode.runtime.nodes[1].isolated_peer_ids


def test_case_7_rl_and_deployed_recommendations_share_b_policy():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.8, step_s=0.2, auto_traffic=False)
    )
    evidence = next(
        event
        for event in runtime.events
        if event["observer_node_id"] == 1 and event["event_type"] == "NODE_STATE"
    )
    deployed = runtime.process_action_recommendation(
        source="DUELING_Q_DEPLOYED",
        observer_node_id=1,
        recommended_action="RECOMMEND_DATA_ISOLATION",
        evidence_event_ids=[evidence["event_id"]],
        confidence=0.99,
        quality=1.0,
        target_hint={"peer_id": 0},
    )
    training = runtime.process_action_recommendation(
        source="RL_TRAINING_AGENT",
        observer_node_id=1,
        recommended_action="RECOMMEND_DATA_ISOLATION",
        evidence_event_ids=[evidence["event_id"]],
        confidence=0.99,
        quality=1.0,
        target_hint={"peer_id": 0},
    )
    assert (training["allowed"], training["executed"], training["failure_reason"]) == (
        deployed["allowed"],
        deployed["executed"],
        deployed["failure_reason"],
    )
    assert 0 not in runtime.nodes[1].isolated_peer_ids


def _phy_event(
    event_id: str,
    at_s: float,
    link_id: str,
    *,
    sinr: float,
    per: float,
    event_type: str = "PHY_SAMPLE",
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "sim_time_s": at_s,
        "event_type": event_type,
        "observer_node_id": 1,
        "message_id": None,
        "online_features": {
            "packet": {"link_id": link_id},
            "phy": {"sinr_db": sinr, "per_estimate": per},
            "traffic": {"throughput_mbps": 1.0, "latency_ms": 2.0},
        },
        "extensions": {"sample_link_id": link_id},
    }


def test_case_9_fdi_unsupported_command_is_rejected_before_execution():
    config = RunConfig(
        seed=609,
        duration_s=1.0,
        step_s=0.2,
        auto_traffic=False,
        tx_service_per_step=16,
        rx_service_per_step=16,
        attack_specs=[
            _attack(
                "FDI",
                "COMMAND_REPLACEMENT",
                end_s=0.8,
                attacker_node_id=0,
                target_node_ids=[2],
                parameters={"replacement": {"cmd": "LAND", "altitude_m": 0.0}},
            )
        ],
        traffic_specs=[
            {
                "source_node_id": 0,
                "target_node_id": 2,
                "packet_type": "MISSION_COMMAND",
                "start_s": 0.2,
                "count": 1,
                "payload": {
                    "cmd": "FLY_TO",
                    "position_x_m": 10.0,
                    "position_y_m": 0.0,
                    "altitude_m": 100.0,
                },
                "sensitive": True,
            }
        ],
    )
    runtime = PlatformRuntime(config)
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["injected"] is True
    assert outcome["reached_target"] is False
    assert outcome["application_hmac_rejected"] is True
    assert outcome["malicious_content_executed"] is False
    assert outcome["attack_effective"] is False


def test_case_9b_blocked_fdi_mission_impact_unavailability_is_shared():
    runtime = PlatformRuntime(_fdi_gradual_config())
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    outcome = label["outcome"]
    episode = ExperimentEvaluator().evaluate(
        runtime.events,
        [label],
        run_record=runtime.run_record(),
    )["episodes"][0]

    assert outcome["mission_impact_available"] is False
    assert outcome["mission_impact"] is None
    assert episode["mission_impact"] == outcome["mission_impact"]
    assert episode["mission_impact_available"] is False
    assert episode["mission_impact_components"] == outcome.get(
        "mission_impact_components", {}
    )


def _old_session_config() -> dict[str, Any]:
    return {
        "attack_specs": [
            _attack(
                "REPLAY",
                "OLD_SESSION_REPLAY",
                impact_start_s=0.8,
                end_s=1.2,
                attacker_node_id=-1,
                parameters={"stale_session_id": "business-session-a"},
            )
        ],
        "traffic_specs": [
            *_telemetry(1, session_id="business-session-a"),
            {
                **_telemetry(1, session_id="business-session-b")[0],
                "start_s": 0.6,
            },
        ],
        "session_lifecycle_specs": [
            {
                "sender_node_id": 2,
                "receiver_node_id": 1,
                "rotate_at_s": 0.6,
                "old_session_id": "business-session-a",
                "new_session_id": "business-session-b",
            }
        ],
    }


def test_case_10_batch_old_session_uses_configured_lifecycle(tmp_path: Path):
    plan = _old_session_config()
    summary = run_batch(
        tmp_path,
        seeds=[610],
        duration_s=1.4,
        step_s=0.2,
        node_count=4,
        attack_specs=plan["attack_specs"],
        traffic_specs=plan["traffic_specs"],
        session_lifecycle_specs=plan["session_lifecycle_specs"],
    )
    row = summary["runs"][0]
    assert row["validation"]["valid"] is True
    assert "WRONG_SESSION" in row["mechanism_evidence"]["replay_check_results"]


@pytest.mark.parametrize(
    ("subtype", "encrypt", "expected"),
    [
        ("CIPHERTEXT_ONLY", True, False),
        ("PLAINTEXT_EXPOSURE", False, True),
    ],
)
def test_case_11_12_eavesdrop_sensitive_protection_and_exposure(
    subtype: str, encrypt: bool, expected: bool
):
    runtime = PlatformRuntime(
        RunConfig(
            seed=611,
            duration_s=1.0,
            step_s=0.2,
            auto_traffic=False,
            tx_service_per_step=16,
            rx_service_per_step=16,
            attack_specs=[
                _attack(
                    "EAVESDROPPING",
                    subtype,
                    end_s=0.8,
                    attacker_node_id=-1,
                    target_link_ids=["link-2-1"],
                    parameters={"receiver_radius_m": 1000.0},
                )
            ],
            traffic_specs=[
                {
                    **_telemetry(2)[0],
                    "count": 2,
                    "encrypt": encrypt,
                }
            ],
        )
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert bool(label["outcome"].get("plaintext_exposure_count", 0)) is expected
    if encrypt:
        assert label["outcome"].get("ciphertext_count", 0) > 0


def test_case_13_normal_subtype_unknown_parameter_fails_fast():
    with pytest.raises(ValueError, match="UNKNOWN_NORMAL_PARAMETER"):
        PlatformRuntime(
            RunConfig(
                normal_disturbance_specs=[
                    {
                        "disturbance_type": "NORMAL_LOW_SNR",
                        "start_s": 0.0,
                        "end_s": 0.6,
                        "target_link_ids": ["link-2-1"],
                        "parameters": {"attenuatio_db": 20.0},
                    }
                ]
            )
        )


def test_case_14_attack_subtype_unknown_parameter_fails_fast():
    with pytest.raises(ValueError, match="UNKNOWN_ATTACK_PARAMETER"):
        PlatformRuntime(
            RunConfig(
                attack_specs=[
                    _attack(
                        "FDI",
                        "TELEMETRY_GRADUAL_DRIFT",
                        attacker_node_id=2,
                        parameters={"delta_per_stpe": 5.0},
                    )
                ]
            )
        )
