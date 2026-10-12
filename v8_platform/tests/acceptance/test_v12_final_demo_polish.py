from __future__ import annotations

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig


def test_replay_report_exposes_online_hmac_pass_and_sequence_without_truth_lookup():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.8,
            step_s=0.2,
            auto_traffic=False,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        run_id="v12-final-replay-presentation",
    )
    runtime.schedule_attack(
        AttackPlan(
            attack_family="REPLAY",
            attack_subtype="IMMEDIATE_REPLAY",
            scheduled_start_s=0.0,
            impact_start_s=0.4,
            end_s=1.4,
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"max_capture_age_s": 1.0},
        )
    )
    message_id = runtime.queue_message(
        2,
        1,
        "STATUS",
        {"status_code": 1, "value": 2},
        sequence_no=100,
        session_id="v12-final-replay-session",
        encrypt=False,
    )

    runtime.run_to_completion()

    online_auth = [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and event["message_id"] == message_id
        and event["online_features"]["security_state"]["replay_check_result"]
        == "DUPLICATE"
    ]
    assert online_auth
    state = online_auth[-1]["online_features"]["security_state"]
    assert state["application_hmac_result"] == "PASS"

    reports = [
        report
        for report in runtime.reporting.gcs_inbox
        if report.get("category") == "REPLAY"
    ]
    assert reports
    evidence = reports[-1]["evidence"]
    assert evidence == {
        "application_hmac_result": "PASS",
        "sequence_no": 100,
        "replay_check_result": "DUPLICATE",
    }
    assert reports[-1]["action_result"]["request"]["action"] == "DROP_PACKET"
    assert reports[-1]["action_result"]["executed"] is True
