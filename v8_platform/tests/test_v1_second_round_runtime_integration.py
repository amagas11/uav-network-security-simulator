from __future__ import annotations

import json

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import MockKeyProvider
from swarm_sim.terminal import TerminalAuthorizer, TerminalProfile


def _profile(node_id: int, *, board: str = "board-a") -> TerminalProfile:
    return TerminalProfile(
        terminal_id=f"uav-{node_id}",
        hardware_fingerprint_attributes={"board": board, "radio": f"radio-{node_id}"},
        software_environment={"app": "platform-v1"},
        os_environment={"os": "sim-os-v1"},
    )


def _terminal_events(runtime: PlatformRuntime, node_id: int, action: str) -> list[dict]:
    return [
        event
        for event in runtime.events
        if event["observer_node_id"] == node_id
        and event.get("extensions", {}).get("terminal_authorization", {}).get("event") == action
    ]


def test_runtime_authorizes_program_start_and_network_join_for_default_terminals():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="terminal-default")
    runtime.start()
    for node_id in runtime.roles:
        node = runtime.nodes[node_id]
        assert node.program_authorized is True
        assert node.network_authorized is True
        assert node.lifecycle_state == "ACTIVE"
        assert _terminal_events(runtime, node_id, "PROGRAM_START")[-1]["online_features"]["security_state"]["auth_result"] == "PASS"
        assert _terminal_events(runtime, node_id, "NETWORK_JOIN")[-1]["online_features"]["security_state"]["auth_result"] == "PASS"


def test_runtime_copy_attack_denies_program_start_and_network_join():
    authorizer = TerminalAuthorizer()
    genuine = _profile(2, board="genuine-board")
    copied = _profile(2, board="copied-board")
    credential = "opaque-copy-test-handle"
    authorizer.enroll(genuine, credential)
    runtime = PlatformRuntime(
        RunConfig(auto_traffic=False),
        run_id="terminal-copy",
        terminal_authorizer=authorizer,
        terminal_profiles={2: copied},
        terminal_credentials={2: credential},
    )
    runtime.start()
    assert runtime.nodes[2].program_authorized is False
    assert runtime.nodes[2].network_authorized is False
    assert runtime.nodes[2].lifecycle_state == "AUTHORIZATION_DENIED"
    assert runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0}) is None
    assert _terminal_events(runtime, 2, "PROGRAM_START")[-1]["online_features"]["security_state"]["auth_result"] == "FAIL"
    serialized = json.dumps(runtime.events, ensure_ascii=False)
    assert credential not in serialized


def test_sensitive_command_is_denied_when_presented_profile_changes_after_join():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="terminal-sensitive",
    )
    runtime.start()
    runtime.set_presented_terminal_identity(
        2,
        _profile(2, board="copied-after-join"),
        runtime.terminal_credentials[2],
    )
    message_id = runtime.queue_message(
        0,
        2,
        "MISSION_COMMAND",
        {"cmd": "FLY_TO", "position_x_m": 200.0, "altitude_m": 120.0},
        sensitive=True,
    )
    assert message_id is not None
    while runtime.state.value == "RUNNING":
        runtime.step()
    assert runtime.nodes[2].flight_state != "FLYING"
    sensitive = _terminal_events(runtime, 2, "SENSITIVE_COMMAND")
    assert sensitive
    assert sensitive[-1]["online_features"]["security_state"]["auth_result"] == "FAIL"
    assert all(message.message_id != message_id for message in runtime.nodes[2].delivered_messages)


def test_rekey_success_uses_key_provider_and_records_state_transitions():
    provider = MockKeyProvider(71)
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), key_provider=provider, run_id="rekey-success")
    previous = runtime.nodes[1].key_epoch
    result = runtime.request_defense(
        node_id=1,
        action="REAUTH_REKEY_REQUEST",
        target_node_id=1,
        peer_id=2,
        session_id="session-1-2-1",
        reason="ACCEPTANCE_REKEY",
    )
    assert result["allowed"] is True
    assert result["executed"] is True
    assert runtime.nodes[1].key_epoch == previous + 1
    assert result["outcome"]["key_state_transitions"] == ["AVAILABLE", "UPDATING", "AVAILABLE"]
    assert result["outcome"]["new_key_epoch"] == previous + 1
    serialized = json.dumps(runtime.events, ensure_ascii=False)
    assert "_key_material" not in serialized
    assert provider._root.hex() not in serialized


def test_failed_rekey_does_not_advance_epoch_or_pretend_execution():
    provider = MockKeyProvider(72)
    provider.fail_next_rekey("TEST_PROVIDER_FAILURE")
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), key_provider=provider, run_id="rekey-failure")
    previous = runtime.nodes[1].key_epoch
    result = runtime.request_defense(
        node_id=1,
        action="REAUTH_REKEY_REQUEST",
        target_node_id=1,
        peer_id=2,
        session_id="session-1-2-1",
    )
    assert result["allowed"] is True
    assert result["executed"] is False
    assert runtime.nodes[1].key_epoch == previous
    assert result["failure_reason"] == "TEST_PROVIDER_FAILURE"
    assert result["outcome"]["key_state_transitions"] == ["AVAILABLE", "UPDATING", "FAILED"]
    assert result["outcome"]["new_key_epoch"] is None


def test_runtime_security_decision_uses_three_replicas_and_adjudicates_one_fault():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="redundancy-runtime",
    )
    runtime.inject_redundancy_fault("security-replica-3", mode="INCONSISTENT_ONCE")
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "UNKNOWN_ID",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 1.0,
            "attacker_node_id": -1,
            "target_node_ids": [1],
        }
    )
    runtime.run_to_completion()
    redundancy_events = [
        event["extensions"]["redundancy_event"]
        for event in runtime.events
        if "redundancy_event" in event.get("extensions", {})
    ]
    adjudications = [item for item in redundancy_events if item["event"] == "SECURITY_DECISION_ADJUDICATED"]
    assert adjudications
    first = adjudications[0]
    assert len(first["replica_results"]) == 3
    assert first["adjudication"]["status"] == "CONSENSUS"
    assert first["adjudication"]["output"]["label"] == "AUTH_FAILURE"
    assert any(item["event"] == "REPLICA_DEGRADED" for item in redundancy_events)
    assert any(item["event"] == "REPLICA_RECOVERED" for item in redundancy_events)
    assert any(
        event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("model_result", {}).get("predicted_label") == "AUTH_FAILURE"
        for event in runtime.events
    )


def test_runtime_redundancy_survives_one_raising_replica():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="redundancy-failure",
    )
    runtime.inject_redundancy_fault("security-replica-2", mode="FAIL_ONCE")
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "KNOWN_ID_CONFLICT",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 0.8,
            "attacker_node_id": -1,
            "target_node_ids": [1],
        }
    )
    runtime.run_to_completion()
    results = [
        event["extensions"]["redundancy_event"]
        for event in runtime.events
        if event.get("extensions", {}).get("redundancy_event", {}).get("event")
        == "SECURITY_DECISION_ADJUDICATED"
    ]
    assert results
    assert any(replica["status"] == "FAILED" for replica in results[0]["replica_results"])
    assert results[0]["adjudication"]["output"]["label"] == "AUTH_FAILURE"
