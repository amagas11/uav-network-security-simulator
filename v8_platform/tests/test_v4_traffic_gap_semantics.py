from swarm_sim import PlatformRuntime, RunConfig


def test_sequence_gap_count_is_current_unresolved_and_late_arrival_clears_it():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.0,
            auto_traffic=False,
            tx_service_per_step=1,
            rx_service_per_step=1,
        ),
        run_id="v4-current-gap",
    )
    for sequence in (100, 102, 101):
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 100.0},
            session_id="gap-current",
            sequence_no=sequence,
        )
    runtime.run_to_completion()
    online_session = runtime.observable_session_id("gap-current")
    receives = [
        event
        for event in runtime.events
        if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
        and event["observer_node_id"] == 1
        and event["online_features"]["packet"]["session_id"] == online_session
    ]
    assert [
        event["online_features"]["traffic"]["sequence_gap_count"]
        for event in receives
    ] == [0, 1, 0]
