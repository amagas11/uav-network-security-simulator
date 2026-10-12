from __future__ import annotations

from copy import deepcopy

import pytest

from swarm_sim import AttackPlan, PlatformRuntimeFactory, RunConfig, RuntimeDependencies
from swarm_sim.domain import ReceivedFrame
from swarm_sim.integrations.person_a import PersonASecurityBundleFactory

from .test_aead_and_skg import SESSION, _events, _runtime


def _plan(family: str, subtype: str, **overrides) -> AttackPlan:
    values = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.1,
        "end_s": 1.6,
        "target_node_ids": [1],
    }
    values.update(overrides)
    return AttackPlan(**values)


def test_a14_rekey_is_networked_skg_and_preserves_prior_epoch_decrypt(person_a_root):
    runtime = _runtime(person_a_root, preload=True, duration_s=4.0)
    runtime.queue_message(
        1, 2, "STATUS", {"value": 1}, sensitive=True, encrypt=True,
        session_id=SESSION
    )
    intent = runtime.nodes[1].tx_queue.popleft()
    link = runtime.topology.get_link(1, 2)
    prior_frame = runtime.crypto.protect(intent.message, 1, 2, link.link_id, 0)
    assert prior_frame.key_epoch == 1

    result = runtime.request_defense(
        node_id=1,
        action="REAUTH_REKEY_REQUEST",
        target_node_id=1,
        peer_id=2,
        session_id=SESSION,
        reason="PERSON_A_REKEY_ACCEPTANCE",
    )
    assert result["executed"] is True
    assert result["outcome"]["new_key_epoch"] is None
    assert result["outcome"]["key_state_transitions"][-1] == "UPDATING"
    assert runtime.nodes[1].key_epoch == 1
    runtime.run_to_completion()
    assert runtime.nodes[1].key_epoch == 2
    assert runtime.nodes[2].key_epoch == 2
    assert runtime.security_coordinator.key_reference(1, 2, SESSION, 2).state == "AVAILABLE"
    assert runtime.crypto.open(prior_frame, 2).auth_result == "PASS"

    message = deepcopy(intent.message)
    message.message_id = runtime.context.ids.next("msg")
    message.sequence_no += 1
    message.key_epoch = runtime.nodes[1].key_epoch
    current_frame = runtime.crypto.protect(message, 1, 2, link.link_id, 0)
    assert current_frame.key_epoch == 2
    assert {event["extensions"]["security_control"]["phase"] for event in _events(runtime, "TX", "SKG_CONTROL")} == {"RECONCILE", "CONFIRM"}


def test_a15_fdi_mutates_after_hmac_and_is_rejected(person_a_root):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    runtime.schedule_attack(
        _plan(
            "FDI",
            "TELEMETRY_GRADUAL_DRIFT",
            attacker_node_id=2,
            parameters={"field": "altitude_m", "delta_per_step": 5.0},
        )
    )
    runtime.start()
    runtime.step()
    message_ids = [
        runtime.queue_message(
            2,
            1,
            "TELEMETRY",
            {"altitude_m": 100.0, "flight_state": "FLYING"},
            sensitive=True,
            session_id=SESSION,
        )
        for _ in range(3)
    ]
    while not runtime.is_terminated:
        runtime.step()
    label = runtime.attack_scheduler.labels()[0]
    assert label["outcome"]["injected"] is True
    modifications = label["truth"]["modifications"]
    assert [item["modified_value"]["altitude_m"] for item in modifications] == [105.0, 110.0, 115.0]
    auth = [event for event in _events(runtime, "AUTH_RESULT", "TELEMETRY") if event["message_id"] in message_ids]
    assert auth and all(
        event["online_features"]["security_state"]["application_hmac_result"]
        == "FAIL"
        for event in auth
    )
    assert all(
        event["online_features"]["packet"]["encrypted"] is False
        for event in _events(runtime, "TX", "TELEMETRY")
    )
    assert label["outcome"]["malicious_content_executed"] is False


def test_a15_fdi_is_detected_by_hmac_not_business_bounds(person_a_root):
    runtime = _runtime(person_a_root, preload=True, duration_s=1.8)
    runtime.schedule_attack(
        _plan(
            "FDI",
            "OUT_OF_RANGE_VALUE",
            attacker_node_id=2,
            parameters={"field": "altitude_m", "value": 5000.0},
        )
    )
    runtime.start()
    runtime.step()
    message_id = runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True,
        session_id=SESSION,
    )
    while not runtime.is_terminated:
        runtime.step()
    auth = [
        event for event in _events(runtime, "AUTH_RESULT", "TELEMETRY")
        if event["message_id"] == message_id
    ]
    state = auth[-1]["online_features"]["security_state"]
    assert state["auth_result"] == "FAIL"
    assert state["application_hmac_result"] == "FAIL"
    assert state["application_hmac_failure_reason"] == "HMAC_MISMATCH"
    assert auth[-1]["online_features"]["packet"]["payload_numeric"] is None
    detections = [
        event["extensions"]["model_result"]
        for event in _events(runtime, "MODEL_RESULT", "TELEMETRY")
        if event["message_id"] == message_id
    ]
    assert any(
        item["model_name"] == "deterministic-rule"
        and item["predicted_label"] == "AUTH_FAILURE"
        for item in detections
    )


def test_a16_ciphertext_tamper_is_not_executed_by_business_handler(person_a_root):
    runtime = _runtime(person_a_root, preload=True)
    runtime.queue_message(
        1,
        2,
        "MISSION_COMMAND",
        {"cmd": "FLY_TO", "altitude_m": 130.0},
        sensitive=True,
        encrypt=True,
        session_id=SESSION,
    )
    intent = runtime.nodes[1].tx_queue.popleft()
    link = runtime.topology.get_link(1, 2)
    frame = runtime.crypto.protect(intent.message, 1, 2, link.link_id, 0)
    frame.protected_payload["ciphertext_b64"] = "AA=="
    runtime.nodes[2].enqueue_rx(ReceivedFrame(frame, {}, 0.0))
    before = runtime.nodes[2].flight_state
    runtime._service_rx(runtime.nodes[2], 1)
    assert runtime.nodes[2].flight_state == before
    assert not runtime.nodes[2].delivered_messages
    auth = _events(runtime, "AUTH_RESULT", "MISSION_COMMAND")[-1]
    assert auth["online_features"]["security_state"]["auth_result"] == "FAIL"


@pytest.mark.parametrize(
    ("subtype", "parameters", "expected"),
    [
        ("IMMEDIATE_REPLAY", {"max_capture_age_s": 0.6}, "DUPLICATE"),
        ("DELAYED_REPLAY", {"delay_s": 0.5}, "DUPLICATE"),
    ],
)
def test_a19_replay_hmac_passes_then_replay_window_rejects(
    person_a_root, subtype, parameters, expected
):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.2)
    runtime.schedule_attack(
        _plan(
            "REPLAY",
            subtype,
            impact_start_s=0.4,
            end_s=2.0,
            attacker_node_id=-1,
            parameters=parameters,
        )
    )
    message_id = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0},
        sensitive=True,
        session_id=SESSION,
        sequence_no=1,
    )
    runtime.run_to_completion()
    checks = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in _events(runtime, "AUTH_RESULT", "TELEMETRY")
        if event["message_id"] == message_id
    ]
    assert "PASS" in checks
    assert expected in checks
    hmac_results = [
        event["online_features"]["security_state"]["application_hmac_result"]
        for event in _events(runtime, "AUTH_RESULT", "TELEMETRY")
        if event["message_id"] == message_id
    ]
    assert hmac_results and set(hmac_results) == {"PASS"}
    assert all(
        event["online_features"]["packet"]["encrypted"] is False
        for event in _events(runtime, "TX", "TELEMETRY")
        if event["message_id"] == message_id
    )
    assert len([event for event in _events(runtime, "TX", "TELEMETRY") if event["message_id"] == message_id]) >= 2


def test_a19_old_session_replay_hmac_passes_but_session_lifecycle_rejects(person_a_root):
    old_session = "old-person-a-session"
    new_session = "new-person-a-session"
    bundle = PersonASecurityBundleFactory(
        person_a_root,
        test_only_preloaded_keys=[
            {
                "first_id": 1,
                "second_id": 2,
                "session_id": old_session,
                "key": bytes(range(32)),
                "key_epoch": 1,
            },
            {
                "first_id": 1,
                "second_id": 2,
                "session_id": new_session,
                "key": bytes(reversed(range(32))),
                "key_epoch": 1,
            },
        ],
    )
    runtime = PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=bundle)
    ).create(
        RunConfig(seed=51, duration_s=2.0, step_s=0.1, auto_traffic=False)
    )
    runtime.schedule_attack(
        _plan(
            "REPLAY",
            "OLD_SESSION_REPLAY",
            impact_start_s=0.8,
            end_s=1.8,
            attacker_node_id=-1,
            parameters={"stale_session_id": old_session},
        )
    )
    old_message = runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 100.0}, sensitive=True,
        session_id=old_session, sequence_no=1,
    )
    runtime.start()
    for _ in range(4):
        runtime.step()
    runtime.rotate_security_session(
        2,
        1,
        old_session_id=old_session,
        new_session_id=new_session,
        key_epoch=1,
    )
    runtime.queue_message(
        2, 1, "TELEMETRY", {"altitude_m": 101.0}, sensitive=True,
        session_id=new_session, sequence_no=1,
    )
    while not runtime.is_terminated:
        runtime.step()
    results = [
        event["online_features"]["security_state"]["replay_check_result"]
        for event in _events(runtime, "AUTH_RESULT", "TELEMETRY")
        if event["message_id"] == old_message
    ]
    assert "PASS" in results
    assert "WRONG_SESSION" in results
    assert runtime.attack_scheduler.labels()[0]["truth"]["replay_mode"] == "OLD_SESSION_REPLAY"


def test_a20_spoofing_external_has_no_authenticated_legitimate_packet(person_a_root):
    runtime = _runtime(person_a_root, duration_s=1.8)
    runtime.schedule_attack(
        _plan(
            "SPOOFING",
            "KNOWN_ID_CONFLICT",
            attacker_node_id=-1,
            parameters={"claimed_src_id": 0},
        )
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["outcome"]["injected"] is True
    spoof_auth = [
        event for event in _events(runtime, "AUTH_RESULT", "MISSION_COMMAND")
        if event["online_features"]["packet"]["claimed_src_id"] == 0
    ]
    assert spoof_auth
    assert all(event["online_features"]["security_state"]["auth_result"] == "FAIL" for event in spoof_auth)
    assert 0 not in runtime.nodes[1].isolated_peer_ids


def test_a17_sensitive_aead_is_ciphertext_only_to_eavesdropper(person_a_root):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    runtime.schedule_attack(
        _plan(
            "EAVESDROPPING",
            "CIPHERTEXT_ONLY",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"receiver_radius_m": 10000.0},
        )
    )
    for index in range(16):
        runtime.queue_message(
            2, 1, "TELEMETRY", {"altitude_m": 100 + index},
            sensitive=True, session_id=SESSION,
        )
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["captured_count"] > 0
    assert outcome["ciphertext_count"] > 0
    assert outcome.get("plaintext_exposure_count", 0) == 0


def test_a17_nonsensitive_plaintext_control_is_not_an_exposure(person_a_root):
    runtime = _runtime(person_a_root, duration_s=2.0)
    runtime.schedule_attack(
        _plan(
            "EAVESDROPPING",
            "PASSIVE_CAPTURE",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"receiver_radius_m": 10000.0},
        )
    )
    for index in range(16):
        runtime.queue_message(
            2, 1, "STATUS", {"value": index}, sensitive=False,
            encrypt=False, session_id=SESSION,
        )
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["captured_count"] > 0
    assert outcome["ordinary_plaintext_count"] > 0
    assert outcome.get("plaintext_exposure_count", 0) == 0


def test_a18_explicit_unprotected_sensitive_control_remains_positive(person_a_root):
    runtime = _runtime(person_a_root, duration_s=2.0)
    runtime.schedule_attack(
        _plan(
            "EAVESDROPPING",
            "PLAINTEXT_EXPOSURE",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"receiver_radius_m": 10000.0},
        )
    )
    for index in range(16):
        runtime.queue_message(
            2, 1, "TELEMETRY", {"altitude_m": 100 + index},
            sensitive=True, encrypt=False, session_id=SESSION,
        )
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["captured_count"] > 0
    assert outcome["plaintext_exposure_count"] > 0


def test_a21_flooding_mechanism_and_hmac_gate_still_occur(person_a_root):
    flood = _runtime(person_a_root, duration_s=1.8)
    flood.schedule_attack(
        _plan(
            "DOS",
            "FLOODING",
            attacker_node_id=-1,
            intensity={"value": 100.0, "unit": "pps"},
            parameters={"packet_type": "STATUS", "target_packet_size_bytes": 256},
        )
    )
    flood.run_to_completion()
    flood_label = flood.attack_scheduler.labels()[0]
    flood_outcome = flood_label["outcome"]
    assert flood_label["truth"]["generated_packets"] > 0
    assert flood_outcome["injected"] is True
    assert flood_outcome["receiver_total_rate_exceeded"] is True
    assert flood_outcome["malicious_traffic_blocked"] > 0


def test_a22_broken_link_prevents_skg_success(person_a_root):
    runtime = _runtime(person_a_root, duration_s=1.2)
    runtime.security_coordinator.timeout_s = 0.4
    started = runtime.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    assert started["accepted"]
    runtime.set_link_active(runtime.topology.get_link(1, 2).link_id, False)
    runtime.set_link_active(runtime.topology.get_link(2, 1).link_id, False)
    runtime.run_to_completion()
    handshake = runtime.security_coordinator.handshakes[started["probe_id"]]
    assert handshake.status == "FAILED"
    assert handshake.failure_reason == "SKG_NETWORK_TIMEOUT"
    assert runtime.security_coordinator.key_reference(1, 2, SESSION, 1).state == "MISSING"
