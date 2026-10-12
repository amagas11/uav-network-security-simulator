from __future__ import annotations

import time

import pytest

from swarm_sim import PlatformRuntime, RunConfig, SimulationClock, SimulationScheduler
from swarm_sim.domain import NodeRole


def test_simulation_clock_is_explicit_and_monotonic():
    clock = SimulationClock()
    before = time.monotonic()
    assert clock.advance_by(0.2) == 0.2
    assert clock.now_s == 0.2
    assert time.monotonic() >= before
    with pytest.raises(ValueError):
        clock.advance_to(0.1)


def test_scheduler_orders_by_time_priority_and_insertion():
    scheduler = SimulationScheduler()
    scheduler.schedule(1.0, "last")
    scheduler.schedule(0.5, "second", priority=20)
    scheduler.schedule(0.5, "first", priority=10)
    assert [item.kind for item in scheduler.pop_due(0.5)] == ["first", "second"]
    assert [item.kind for item in scheduler.pop_due(1.0)] == ["last"]


def test_same_seed_has_same_semantic_projection():
    config = RunConfig(seed=81, duration_s=1.2, step_s=0.2, node_count=5)
    first = PlatformRuntime(config, run_id="first")
    second = PlatformRuntime(config, run_id="second")
    first.run_to_completion()
    second.run_to_completion()
    assert first.reproducible_event_projection() == second.reproducible_event_projection()


def test_reset_creates_new_run_identity_and_clears_state():
    runtime = PlatformRuntime(RunConfig(seed=81, duration_s=0.4), run_id="before-reset")
    runtime.run_to_completion()
    assert runtime.events
    runtime.reset()
    assert runtime.run_id != "before-reset"
    assert runtime.context.clock.now_s == 0.0
    assert runtime.state.value == "INITIALIZED"


def test_different_seed_changes_phy_projection():
    first = PlatformRuntime(RunConfig(seed=1, duration_s=0.4), run_id="a")
    second = PlatformRuntime(RunConfig(seed=2, duration_s=0.4), run_id="b")
    first.run_to_completion()
    second.run_to_completion()
    assert first.reproducible_event_projection() != second.reproducible_event_projection()


def test_role_assignment_and_default_formation_are_not_random():
    runtime = PlatformRuntime(RunConfig(node_count=6, auto_traffic=False))
    assert runtime.nodes[0].role == NodeRole.GCS
    assert runtime.nodes[1].role == NodeRole.LEADER
    assert all(runtime.nodes[index].role == NodeRole.FOLLOWER for index in range(2, 6))
    assert runtime.topology.route(2, 0) == [2, 1, 0]
    assert runtime.topology.route(0, 4) == [0, 1, 4]


def test_unauthorized_external_business_flow_is_rejected():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    runtime._external_node(-1)
    runtime.topology.ensure_external_ingress(-1, [1])
    assert runtime.queue_message(-1, 1, "COMMAND", {"cmd": "LAND"}) is None


def test_multihop_traffic_uses_two_link_transmissions_and_forward_queue():
    runtime = PlatformRuntime(RunConfig(seed=42, duration_s=2, auto_traffic=False))
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 90.0})
    assert message_id
    runtime.start()
    runtime.step()
    assert len(runtime.nodes[1].rx_queue) == 1
    runtime.step()
    assert len(runtime.nodes[1].forward_queue) == 1
    runtime.step()
    runtime.step()
    assert [
        runtime.internal_link_id(event["online_features"]["packet"]["link_id"])
        for event in runtime.events
        if event["event_type"] == "TX" and event["message_id"] == message_id
    ] == ["link-2-1", "link-1-0"]
    assert runtime.nodes[0].delivered_messages[-1].message_id == message_id


def test_each_node_exposes_only_local_neighbors():
    runtime = PlatformRuntime(RunConfig(node_count=5, auto_traffic=False))
    assert runtime.observation(0)["known_topology"]["neighbor_ids"] == [1]
    assert runtime.observation(2)["known_topology"]["neighbor_ids"] == [1]
    assert set(runtime.observation(1)["known_topology"]["neighbor_ids"]) == {0, 2, 3, 4}


def test_persistent_phy_state_is_reused_and_periodically_sampled():
    runtime = PlatformRuntime(RunConfig(duration_s=0.6, auto_traffic=False))
    state = runtime.phy.states["link-1-2"]
    runtime.run_to_completion()
    assert runtime.phy.states["link-1-2"] is state
    samples = [event for event in runtime.events if event["event_type"] == "PHY_SAMPLE"]
    assert samples
    assert all(event["availability"]["payload_available"] is False for event in samples)


def test_probe_pair_has_shared_ids_but_independent_measurements():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="probe")
    first, second = runtime.probes.probe(1, 2, sample_count=32)
    assert first.probe_id == second.probe_id
    assert first.session_id == second.session_id
    assert first.sim_time_s == second.sim_time_s
    assert first.measurement is not None and second.measurement is not None
    assert first.measurement != second.measurement
    correlation_direction = sum(
        (a - sum(first.measurement) / 32) * (b - sum(second.measurement) / 32)
        for a, b in zip(first.measurement, second.measurement)
    )
    assert correlation_direction > 0


def test_missing_probe_uses_null_not_zero_samples():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    runtime.topology.set_bidirectional_active(1, 2, False)
    first, second = runtime.probes.probe(1, 2)
    assert first.missing and second.missing
    assert first.measurement is None and second.measurement is None
    assert first.snr_db is None and second.snr_db is None
