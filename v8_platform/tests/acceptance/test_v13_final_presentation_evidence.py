from __future__ import annotations

from swarm_sim import PlatformRuntime, RunConfig


def test_dos_target_summary_preserves_existing_detector_evidence_for_presentation():
    """Leader->GCS summary retains the target detector's already-made result.

    This is presentation-only provenance: the detector, threshold comparison and
    defense request all run before ReportingService builds the summary.
    """

    runtime = PlatformRuntime(
        RunConfig(
            seed=42,
            duration_s=3.2,
            step_s=0.2,
            auto_traffic=False,
            queue_capacity=128,
            tx_service_per_step=64,
            rx_service_per_step=64,
            flooding_packet_rate_threshold_pps=8.0,
            security_summary_window_s=0.4,
        ),
        run_id="v13-target-dos-presentation",
    )
    runtime.schedule_attack(
        {
            "attack_family": "DOS",
            "attack_subtype": "FLOODING",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.4,
            "end_s": 2.0,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "target_link_ids": [],
            "intensity": {"value": 80.0, "unit": "pps"},
            "parameters": {"packet_type": "STATUS"},
        }
    )
    runtime.run_to_completion()

    target_summaries = [
        item
        for item in runtime.reporting.gcs_inbox
        if item.get("report_type") == "SECURITY_SUMMARY"
        and item.get("category") == "DOS"
        and item.get("source_node_id") == 1
    ]
    assert target_summaries
    summary = target_summaries[-1]
    evidence = summary["evidence"]

    assert evidence["detector_node_id"] == 1
    assert evidence["observed_packet_rate_pps"] >= 8.0
    assert evidence["flooding_threshold_pps"] == 8.0
    assert evidence["statistics_window_s"] == 1.0
    assert evidence["detection_time_s"] == summary["latest_detection_time_s"]
    assert evidence["source_report_id"] in summary["source_report_ids"]
    assert summary["action_result"]["request"]["action"] == "INCREASE_MONITORING"
    assert summary["action_result"]["executed"] is True

    serialized = repr(summary).lower()
    assert "raw_key" not in serialized
    assert "private_key" not in serialized
    assert "key_material" not in serialized
