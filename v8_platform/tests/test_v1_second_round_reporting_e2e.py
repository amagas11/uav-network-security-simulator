from __future__ import annotations

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.normal import NormalDisturbancePlan
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator


def _batchable_reporting_runtime(
    run_id: str, *, duration_s: float = 2.4
) -> PlatformRuntime:
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=duration_s,
            auto_traffic=False,
            phy_sample_interval_s=0.2,
            tx_service_per_step=32,
            rx_service_per_step=32,
            security_summary_window_s=0.4,
        ),
        run_id=run_id,
    )
    for index in range(2):
        result = ModelResult(
            schema_version=SCHEMA_VERSION,
            run_id=runtime.context.run_id,
            result_id=f"reporting-model-{index}",
            observer_node_id=2,
            decision_time_s=0.0,
            model_name="reporting-fixture",
            model_version="1",
            status="OK",
            predicted_label="LINK_QUALITY_ALERT",
            scores={"LINK_QUALITY_ALERT": 0.85},
            confidence=0.85,
            quality=1.0,
            recommended_action=None,
            evidence_event_ids=[runtime.events[index]["event_id"]],
            inference_time_ms=0.0,
            error_code=None,
        )
        runtime._report_security_outcome(
            runtime.nodes[2],
            result=result,
            decision_source="MODEL",
            action_result=None,
            evidence={"link_quality_alert": True},
            event_time_s=0.0,
            source_event_ids=[runtime.events[index]["event_id"]],
            severity="MEDIUM",
        )
    return runtime


def test_leader_aggregates_similar_follower_reports_and_preserves_evidence_ids():
    runtime = _batchable_reporting_runtime("leader-aggregate")
    runtime.run_to_completion()
    summaries = [
        item for item in runtime.reporting.gcs_inbox if item.get("report_type") == "SECURITY_SUMMARY"
    ]
    assert summaries
    summary = max(summaries, key=lambda item: item["count"])
    assert summary["source_node_id"] == 2
    assert summary["category"] == "LINK_QUALITY_ALERT"
    assert summary["count"] >= 2
    assert summary["latest_detection_time_s"] >= summary["first_detection_time_s"]
    assert len(summary["source_event_ids"]) >= 2
    assert all(summary["source_event_ids"])
    assert len(runtime.nodes[2].local_security_cache) >= summary["count"]
    summary_tx = [
        event
        for event in runtime.events
        if event["event_type"] == "TX"
        and event["online_features"]["packet"]["packet_type"] == "SECURITY_SUMMARY"
    ]
    assert any(event["observer_node_id"] == runtime.leader_node_id for event in summary_tx)


def test_high_risk_report_bypasses_batching_but_still_traverses_leader_to_gcs():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.8, auto_traffic=False, tx_service_per_step=16, rx_service_per_step=16),
        run_id="leader-emergency",
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "UNKNOWN_ID",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 0.8,
            "attacker_node_id": -1,
            "target_node_ids": [2],
        }
    )
    runtime.run_to_completion()
    emergency = [
        item
        for item in runtime.reporting.gcs_inbox
        if item.get("delivery_mode") == "EMERGENCY_BYPASS"
    ]
    assert emergency
    report_id = emergency[0]["report_id"]
    tx_observers = [
        event["observer_node_id"]
        for event in runtime.events
        if event["event_type"] == "TX"
        and event.get("extensions", {}).get("report_id") == report_id
    ]
    assert 2 in tx_observers
    assert runtime.leader_node_id in tx_observers


def test_disconnected_leader_gcs_link_caches_summary_and_recovery_uploads_it():
    runtime = _batchable_reporting_runtime("leader-cache", duration_s=3.0)
    runtime.set_bidirectional_link_active(0, 1, False, reason="ACCEPTANCE_REPORT_LINK_DOWN")
    runtime.start()
    while runtime.context.clock.now_s < 1.8:
        runtime.step()
    assert runtime.reporting.pending_summary_count > 0
    assert not runtime.reporting.gcs_inbox

    runtime.set_bidirectional_link_active(0, 1, True, reason="ACCEPTANCE_REPORT_LINK_RECOVERY")
    while runtime.state.value == "RUNNING":
        runtime.step()
    assert runtime.reporting.pending_summary_count == 0
    assert any(item.get("report_type") == "SECURITY_SUMMARY" for item in runtime.reporting.gcs_inbox)
    assert any(item.get("report_delay_s", 0) > 0 for item in runtime.reporting.gcs_inbox)


def _build_e2e(run_id: str) -> PlatformRuntime:
    runtime = PlatformRuntime(
        RunConfig(
            seed=901,
            node_count=4,
            duration_s=2.6,
            auto_traffic=True,
            tx_service_per_step=32,
            rx_service_per_step=32,
            security_summary_window_s=0.4,
        ),
        run_id=run_id,
    )
    runtime.schedule_normal_disturbance(
        NormalDisturbancePlan(
            disturbance_type="NORMAL_TRAFFIC_BURST",
            start_s=0.2,
            end_s=0.6,
            target_node_ids=[1],
            parameters={"source_node_id": 3, "packet_rate_pps": 15.0},
        )
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "KNOWN_ID_CONFLICT",
            "scheduled_start_s": 0.6,
            "impact_start_s": 0.8,
            "end_s": 1.4,
            "attacker_node_id": -1,
            "target_node_ids": [2],
            "parameters": {"claimed_src_id": 0},
        }
    )
    return runtime


def test_deterministic_e2e_normal_attack_defense_reporting_evaluation_and_export(tmp_path):
    first = _build_e2e("e2e-first")
    second = _build_e2e("e2e-second")
    first.run_to_completion()
    second.run_to_completion()
    assert first.reproducible_event_projection() == second.reproducible_event_projection()

    assert first.attack_scheduler.labels()[0]["attack_family"] == "SPOOFING"
    assert any(event["event_type"] == "RX_SUCCESS" for event in first.events)
    assert any(
        event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("model_result", {}).get("predicted_label") == "AUTH_FAILURE"
        for event in first.events
    )
    assert any(event["event_type"] == "DEFENSE_RESULT" for event in first.events)
    assert first.reporting.gcs_inbox
    assert first.evaluation_view()["per_attack_family"]["SPOOFING"]["TP"] == 1
    assert all(
        "attack_family" not in event["online_features"]
        for event in first.events
    )
    assert first.normal_disturbances.records
    assert len(first.normal_disturbances.labels()) == 0

    first.export_dataset(tmp_path)
    validation = DatasetValidator().validate(tmp_path)
    assert validation.valid, validation.errors
