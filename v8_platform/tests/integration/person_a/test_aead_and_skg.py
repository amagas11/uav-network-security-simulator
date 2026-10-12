from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from swarm_sim import PlatformRuntimeFactory, RunConfig, RuntimeDependencies
from swarm_sim.adapters import KeyProvider, TestKeyMaterialProvider
from swarm_sim.integrations.person_a import (
    PersonASecretLeakageAudit,
    PersonASecurityBundleFactory,
)
from swarm_sim.probe import PERSON_A_V01_COMPAT_PROBE_PROFILE


SESSION = "integration-business-session"
TEST_KEY = bytes(range(32))


def _factory(root: Path, *, preload: bool = False, timeout_s: float = 3.0):
    keys = (
        [
            {
                "first_id": 1,
                "second_id": 2,
                "session_id": SESSION,
                "key": TEST_KEY,
                "key_epoch": 1,
            }
        ]
        if preload
        else []
    )
    bundle = PersonASecurityBundleFactory(
        root,
        test_only_preloaded_keys=keys,
        skg_timeout_s=timeout_s,
        probe_profile=PERSON_A_V01_COMPAT_PROBE_PROFILE,
    )
    return PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=bundle)
    )


def _runtime(root: Path, *, preload: bool = False, seed: int = 31, duration_s: float = 3.0):
    return _factory(root, preload=preload).create(
        RunConfig(
            seed=seed,
            duration_s=duration_s,
            step_s=0.1,
            node_count=4,
            auto_traffic=False,
            phy_sample_interval_s=10.0,
        )
    )


def _events(runtime, event_type: str, packet_type: str | None = None):
    values = [item for item in runtime.events if item["event_type"] == event_type]
    if packet_type is not None:
        values = [
            item
            for item in values
            if item["online_features"]["packet"]["packet_type"] == packet_type
        ]
    return values


def test_a03_production_adapter_has_no_raw_key_api(person_a_root):
    runtime = _runtime(person_a_root)
    coordinator = runtime.security_coordinator
    crypto = runtime.crypto
    assert not hasattr(coordinator, "_key_material")
    assert not hasattr(crypto, "_key_material")
    assert "_key_material" not in KeyProvider.__dict__
    assert "_key_material" in TestKeyMaterialProvider.__dict__


def test_a04_preloaded_key_aead_uses_v8_frame_path(person_a_root):
    runtime = _runtime(person_a_root, preload=True)
    message_id = runtime.queue_message(
        1,
        2,
        "STATUS",
        {"status_code": 7, "value": 42.5},
        sensitive=True,
        encrypt=True,
        session_id=SESSION,
    )
    assert message_id
    runtime.run_to_completion()
    assert any(item.message_id == message_id for item in runtime.nodes[2].delivered_messages)
    assert _events(runtime, "TX", "STATUS")
    assert _events(runtime, "RX_SUCCESS", "STATUS")
    auth = _events(runtime, "AUTH_RESULT", "STATUS")
    passed = [
        item
        for item in auth
        if item["online_features"]["security_state"]["auth_result"] == "PASS"
    ]
    assert passed
    assert passed[-1]["extensions"]["crypto_result"]["algorithm"] == "AES-256-GCM"
    assert passed[-1]["extensions"]["crypto_result"]["key_id"]


def test_a05_ciphertext_tamper_returns_no_plaintext(person_a_root):
    runtime = _runtime(person_a_root, preload=True)
    assert runtime.queue_message(
        1, 2, "STATUS", {"value": 9}, sensitive=True, encrypt=True,
        session_id=SESSION
    )
    sender = runtime.nodes[1]
    intent = sender.tx_queue.popleft()
    link = runtime.topology.get_link(1, 2)
    frame = runtime.crypto.protect(intent.message, 1, 2, link.link_id, 0)
    frame.protected_payload["ciphertext_b64"] = "AA=="
    opened = runtime.crypto.open(frame, 2)
    assert opened.auth_result == "FAIL"
    assert opened.payload is None
    assert opened.error_code == "AUTH_FAIL"


def test_a06_wrong_receiver_and_direction_fail_closed(person_a_root):
    runtime = _runtime(person_a_root, preload=True)
    runtime.queue_message(
        1, 2, "STATUS", {"value": 1}, sensitive=True, encrypt=True,
        session_id=SESSION
    )
    intent = runtime.nodes[1].tx_queue[0]
    link = runtime.topology.get_link(1, 2)
    frame = runtime.crypto.protect(intent.message, 1, 2, link.link_id, 0)
    wrong_receiver = runtime.crypto.open(frame, 3)
    assert wrong_receiver.auth_result == "FAIL"
    assert wrong_receiver.payload is None
    reversed_frame = deepcopy(frame)
    reversed_frame.link_sender_id, reversed_frame.link_receiver_id = 2, 1
    wrong_direction = runtime.crypto.open(reversed_frame, 1)
    assert wrong_direction.auth_result != "PASS"
    assert wrong_direction.payload is None

    runtime.security_coordinator.providers[2].put(
        1, SESSION, b"x" * 32, key_epoch=1
    )
    wrong_key = runtime.crypto.open(frame, 2)
    assert wrong_key.auth_result == "FAIL"
    assert wrong_key.payload is None


def test_a07_missing_key_does_not_send_plaintext_or_crash(person_a_root):
    runtime = _runtime(person_a_root, preload=False, duration_s=0.3)
    message_id = runtime.queue_message(
        1, 2, "STATUS", {"secret_value": 77}, sensitive=True, encrypt=True,
        session_id=SESSION
    )
    runtime.run_to_completion()
    assert message_id
    assert not [event for event in _events(runtime, "TX", "STATUS") if event["message_id"] == message_id]
    failures = [
        event for event in _events(runtime, "AUTH_RESULT")
        if event.get("extensions", {}).get("crypto_send_failure", {}).get(
            "withheld_message_ref"
        ) == message_id
    ]
    assert failures
    assert failures[-1]["online_features"]["security_state"]["auth_result"] == "UNAVAILABLE"
    assert failures[-1]["extensions"]["crypto_send_failure"]["skg_required"] is True


def test_a08_to_a10_real_probe_and_network_skg_then_business_aead(person_a_root):
    runtime = _runtime(person_a_root, duration_s=4.0)
    started = runtime.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    assert started["accepted"] is True
    probe_id = started["probe_id"]
    handshake = runtime.security_coordinator.handshakes[probe_id]
    assert handshake.session_id == SESSION
    # The V8 probe creates the paired observations, but each upstream A engine
    # owns only its endpoint-local record; neither receives the peer record.
    first_state = handshake.engines[1]._probes[probe_id]
    second_state = handshake.engines[2]._probes[probe_id]
    assert (first_state.local_id, first_state.peer_id) == (1, 2)
    assert (second_state.local_id, second_state.peer_id) == (2, 1)
    runtime.run_to_completion()
    assert handshake.status == "AVAILABLE"
    assert handshake.state_history == [
        "NEGOTIATING",
        "CONFIRM_PENDING",
        "COMMIT_READY",
        "AVAILABLE",
    ]
    control_tx = _events(runtime, "TX", "SKG_CONTROL")
    control_rx = _events(runtime, "RX_SUCCESS", "SKG_CONTROL")
    phases_tx = {event["extensions"]["security_control"]["phase"] for event in control_tx}
    phases_rx = {event["extensions"]["security_control"]["phase"] for event in control_rx}
    assert phases_tx == {"RECONCILE", "CONFIRM"}
    assert phases_rx == {"RECONCILE", "CONFIRM"}
    assert len(handshake.control_message_ids) == 4
    assert all(
        message.packet_type != "SKG_CONTROL"
        for node in runtime.nodes.values()
        for message in node.delivered_messages
    )
    assert runtime.security_coordinator.key_reference(1, 2, SESSION, 1).state == "AVAILABLE"
    # Continue with a fresh runtime duration boundary by directly starting a
    # second business send before completion in a sufficiently long run.


def test_a10_skg_key_directly_drives_subsequent_business_aead(person_a_root):
    runtime = _runtime(person_a_root, duration_s=5.0)
    started = runtime.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    runtime.start()
    while runtime.security_coordinator.handshakes[started["probe_id"]].status not in {"AVAILABLE", "FAILED"}:
        runtime.step()
    assert runtime.security_coordinator.handshakes[started["probe_id"]].status == "AVAILABLE"
    message_id = runtime.queue_message(
        1, 2, "STATUS", {"status_code": 2, "value": 88}, sensitive=True, session_id=SESSION
    )
    while not runtime.is_terminated:
        runtime.step()
    delivered = [item for item in runtime.nodes[2].delivered_messages if item.message_id == message_id]
    assert delivered and delivered[0].payload["value"] == 88
    assert any(event["message_id"] == message_id for event in _events(runtime, "TX", "STATUS"))


def test_a11_non_neighbor_probe_fails_without_key(person_a_root):
    runtime = _runtime(person_a_root)
    # GCS 0 and follower 2 are not direct peers in the default topology.
    result = runtime.security_coordinator.initiate_session(0, 2, SESSION, key_epoch=1)
    assert result["accepted"] is False
    assert runtime.security_coordinator.key_reference(0, 2, SESSION, 1).state == "MISSING"


def test_a12_missing_probe_observation_never_commits_key(person_a_root):
    runtime = _runtime(person_a_root)
    runtime.set_link_active(runtime.topology.get_link(1, 2).link_id, False)
    result = runtime.security_coordinator.initiate_session(
        1, 2, SESSION, key_epoch=1
    )
    assert result["accepted"] is False
    handshake = runtime.security_coordinator.handshakes[result["probe_id"]]
    assert handshake.status == "FAILED"
    assert runtime.security_coordinator.key_reference(1, 2, SESSION, 1).state == "MISSING"
    assert runtime.security_coordinator.key_reference(2, 1, SESSION, 1).state == "MISSING"


def test_a13_tampered_identity_signature_prevents_key_commit(person_a_root):
    runtime = _runtime(person_a_root, duration_s=1.5)
    started = runtime.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    assert started["accepted"]
    intent = runtime.nodes[1].tx_queue[0]
    intent.message.payload["signature_b64"] = "AA=="
    runtime.run_to_completion()
    handshake = runtime.security_coordinator.handshakes[started["probe_id"]]
    assert handshake.status != "AVAILABLE"
    assert runtime.security_coordinator.key_reference(1, 2, SESSION, 1).state == "MISSING"


def test_a23_terminal_credential_binds_simulated_fingerprint(person_a_root):
    runtime = _runtime(person_a_root, preload=True)
    assert all(node.program_authorized and node.network_authorized for node in runtime.nodes.values())
    original = runtime.terminal_profiles[2]
    copied = deepcopy(original)
    copied.hardware_fingerprint_attributes["cpu_id"] = "copied-device"
    runtime.set_presented_terminal_identity(2, copied, "ignored-opaque-handle")
    assert runtime._authorize_terminal_event(2, "SENSITIVE_COMMAND") is False


def test_a24_exported_surfaces_do_not_contain_known_secrets(person_a_root, tmp_path):
    runtime = _runtime(person_a_root, preload=True)
    runtime.queue_message(
        1, 2, "STATUS", {"value": 4}, sensitive=True, session_id=SESSION
    )
    runtime.run_to_completion()
    exported = runtime.export_dataset(tmp_path / "dataset")
    values = {
        "run": runtime.run_record(),
        "events": runtime.events,
        "labels": runtime.attack_scheduler.labels(),
        "runtime_view": runtime.runtime_view(0),
        "export": exported,
    }
    assert PersonASecretLeakageAudit.scan(values, known_secrets=[TEST_KEY]) == []


def test_a25_factory_creates_fresh_nonce_and_key_state(person_a_root):
    factory = _factory(person_a_root, preload=True)
    config = RunConfig(seed=2, duration_s=1.0, step_s=0.1, auto_traffic=False)
    first = factory.create(config)
    second = factory.create(config)
    assert first.security_coordinator is not second.security_coordinator
    assert first.security_coordinator.providers[1] is not second.security_coordinator.providers[1]
    assert first.crypto is not second.crypto
