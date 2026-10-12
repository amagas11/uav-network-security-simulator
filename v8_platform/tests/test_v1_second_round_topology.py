from __future__ import annotations

from swarm_sim import PlatformRuntime, RunConfig


def _topology_events(runtime: PlatformRuntime, node_id: int) -> list[dict]:
    return [
        event
        for event in runtime.events
        if event["event_type"] == "TOPOLOGY_UPDATE"
        and event["observer_node_id"] == node_id
    ]


def test_link_failure_and_recovery_emit_only_relevant_local_updates():
    runtime = PlatformRuntime(RunConfig(node_count=5, auto_traffic=False), run_id="topology-events")
    initial_versions = {
        node_id: runtime.nodes[node_id].known_topology_version for node_id in runtime.roles
    }
    initial_counts = {node_id: len(_topology_events(runtime, node_id)) for node_id in runtime.roles}

    runtime.set_bidirectional_link_active(1, 2, False, reason="ACCEPTANCE_LINK_FAILURE")
    assert runtime.nodes[1].known_topology_version > initial_versions[1]
    assert runtime.nodes[2].known_topology_version > initial_versions[2]
    assert runtime.nodes[0].known_topology_version == initial_versions[0]
    assert runtime.nodes[4].known_topology_version == initial_versions[4]
    assert len(_topology_events(runtime, 1)) == initial_counts[1] + 1
    assert len(_topology_events(runtime, 2)) == initial_counts[2] + 1
    assert len(_topology_events(runtime, 0)) == initial_counts[0]
    assert "link-1-2" in runtime.nodes[1].known_bad_link_ids
    assert "link-2-1" in runtime.nodes[2].known_bad_link_ids

    failed_versions = {
        node_id: runtime.nodes[node_id].known_topology_version for node_id in runtime.roles
    }
    runtime.set_bidirectional_link_active(1, 2, True, reason="ACCEPTANCE_LINK_RECOVERY")
    assert runtime.nodes[1].known_topology_version > failed_versions[1]
    assert runtime.nodes[2].known_topology_version > failed_versions[2]
    assert runtime.nodes[0].known_topology_version == failed_versions[0]
    assert len(_topology_events(runtime, 1)) == initial_counts[1] + 2
    assert len(_topology_events(runtime, 2)) == initial_counts[2] + 2
    assert "link-1-2" not in runtime.nodes[1].known_bad_link_ids
    assert "link-2-1" not in runtime.nodes[2].known_bad_link_ids


def test_reroute_changes_usable_path_without_exposing_global_graph():
    runtime = PlatformRuntime(RunConfig(node_count=4, auto_traffic=False), run_id="topology-reroute")
    runtime.add_bidirectional_link(2, 3, reason="ACCEPTANCE_ALTERNATE_PATH")
    assert runtime.topology.route(2, 0) == [2, 1, 0]

    runtime.set_bidirectional_link_active(1, 2, False, reason="ACCEPTANCE_REROUTE")
    assert runtime.topology.route(2, 0) == [2, 3, 1, 0]
    follower_view = runtime.observation(2)["known_topology"]
    assert set(follower_view) >= {"neighbor_ids", "known_bad_link_ids", "topology_version"}
    assert "links" not in follower_view
    assert "global_topology" not in follower_view
    assert set(follower_view["neighbor_ids"]) == {3}


def test_reroute_defense_triggers_runtime_topology_refresh():
    runtime = PlatformRuntime(RunConfig(node_count=4, auto_traffic=False), run_id="topology-defense")
    before = len(_topology_events(runtime, 1))
    result = runtime.request_defense(
        node_id=1,
        action="REROUTE",
        target_link_id="link-1-2",
        reason="LOCAL_BAD_LINK",
    )
    assert result["executed"]
    assert not runtime.topology.links["link-1-2"].active
    assert len(_topology_events(runtime, 1)) == before + 1
    assert any(
        event["event_type"] in {"TOPOLOGY_UPDATE", "DEFENSE_RESULT"}
        for event in runtime.events[-12:]
    )
