from __future__ import annotations

import base64

from swarm_sim import (
    PlatformRuntime,
    PlatformRuntimeFactory,
    RunConfig,
    RuntimeDependencies,
)
from swarm_sim.integrations.person_a import PersonASecurityBundleFactory

from .test_aead_and_skg import SESSION, _runtime


def _advance_to_confirm_pending(runtime, probe_id: str):
    runtime.start()
    for _ in range(8):
        runtime.step()
        handshake = runtime.security_coordinator.handshakes[probe_id]
        if (
            handshake.status == "CONFIRM_PENDING"
            and handshake.received_reconcile == {1, 2}
        ):
            return handshake
    raise AssertionError("SKG handshake did not reach CONFIRM_PENDING")


def _confirm_intent(runtime, sender_id: int):
    return next(
        intent
        for intent in runtime.nodes[sender_id].tx_queue
        if intent.message.packet_type == "SKG_CONTROL"
        and intent.message.payload["phase"] == "CONFIRM"
    )


def test_a28_one_side_confirm_loss_never_commits_half_key_and_old_epoch_works(
    person_a_root,
):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    coordinator = runtime.security_coordinator
    coordinator.timeout_s = 0.8

    # Prove the previous epoch remains usable after the failed rekey.
    assert runtime.queue_message(
        1, 2, "STATUS", {"value": 1}, sensitive=True, session_id=SESSION
    )
    intent = runtime.nodes[1].tx_queue.popleft()
    link = runtime.topology.get_link(1, 2)
    old_frame = runtime.crypto.protect(intent.message, 1, 2, link.link_id, 0)

    started = coordinator.initiate_session(1, 2, SESSION, key_epoch=2)
    assert started["accepted"] is True
    handshake = _advance_to_confirm_pending(runtime, started["probe_id"])

    # Simulate one directional network loss after both reconciles traversed V8.
    lost = _confirm_intent(runtime, 1)
    runtime.nodes[1].tx_queue.remove(lost)
    for _ in range(4):
        runtime.step()
        if len(handshake.received_confirm) == 1:
            break
    assert len(handshake.received_confirm) == 1
    assert coordinator.key_reference(1, 2, SESSION, 2).state != "AVAILABLE"
    assert coordinator.key_reference(2, 1, SESSION, 2).state != "AVAILABLE"
    while not runtime.is_terminated:
        runtime.step()

    assert handshake.status == "FAILED"
    assert handshake.failure_reason == "SKG_NETWORK_TIMEOUT"
    assert "COMMIT_READY" not in handshake.state_history
    assert handshake.state_history[-1] == "FAILED"
    assert coordinator.key_reference(1, 2, SESSION, 2).state != "AVAILABLE"
    assert coordinator.key_reference(2, 1, SESSION, 2).state != "AVAILABLE"
    assert coordinator.key_reference(1, 2, SESSION, 1).state == "AVAILABLE"
    assert coordinator.key_reference(2, 1, SESSION, 1).state == "AVAILABLE"
    assert runtime.crypto.open(old_frame, 2).auth_result == "PASS"


def test_a29_duplicate_rekey_reuses_one_active_pair_session_epoch(person_a_root):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    coordinator = runtime.security_coordinator

    first = coordinator.request_rekey(1, 2, SESSION, 1)
    first_probe_id = next(iter(coordinator.handshakes))
    second = coordinator.request_rekey(2, 1, SESSION, 1)

    assert first.success is True
    assert second.success is False
    assert second.failure_reason == "existing_rekey_in_progress"
    assert list(coordinator.handshakes) == [first_probe_id]
    assert coordinator.active_rekey_count == 1
    runtime.run_to_completion()
    assert coordinator.handshakes[first_probe_id].status == "AVAILABLE"
    first_ref = coordinator.key_reference(1, 2, SESSION, 2)
    second_ref = coordinator.key_reference(2, 1, SESSION, 2)
    assert first_ref.state == second_ref.state == "AVAILABLE"
    assert first_ref.key_handle == second_ref.key_handle
    assert len(coordinator.handshakes) == 1


def test_a30_cross_confirm_conflict_fails_before_either_key_commit(person_a_root):
    runtime = _runtime(person_a_root, duration_s=2.0)
    coordinator = runtime.security_coordinator
    started = coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    assert started["accepted"] is True
    handshake = _advance_to_confirm_pending(runtime, started["probe_id"])

    # The altered public confirm is re-signed, so identity is valid while the
    # cryptographic cross-confirm is inconsistent.
    intent = _confirm_intent(runtime, 1)
    payload = intent.message.payload
    conflicting = bytearray(base64.b64decode(payload["blob_b64"], validate=True))
    conflicting[-1] ^= 0x01
    conflicting_blob = bytes(conflicting)
    signed = coordinator.identities[1].sign_handshake(
        1, 2, SESSION, handshake.probe_id, conflicting_blob
    )
    payload["blob_b64"] = base64.b64encode(conflicting_blob).decode("ascii")
    payload["signature_b64"] = base64.b64encode(signed.signature).decode("ascii")
    payload["identity_id"] = signed.identity_id
    payload["public_key_pem"] = signed.public_key_pem

    while not runtime.is_terminated and handshake.status != "FAILED":
        runtime.step()

    assert handshake.status == "FAILED"
    assert handshake.failure_reason == "SKG_CROSS_CONFIRM_CONFLICT"
    assert "COMMIT_READY" not in handshake.state_history
    assert coordinator.key_reference(1, 2, SESSION, 1).state != "AVAILABLE"
    assert coordinator.key_reference(2, 1, SESSION, 1).state != "AVAILABLE"


def test_a31_default_probe_restores_original_v8_distribution():
    runtime = PlatformRuntime(
        RunConfig(seed=31, duration_s=1.0, step_s=0.1, auto_traffic=False),
        run_id="run-probe-v8-reference",
    )
    first, second = runtime.probes.probe(1, 2, sample_count=8)

    assert runtime.probes.profile == "V8_DEFAULT"
    assert first.measurement == [
        -53.083799,
        -54.395447,
        -52.31569,
        -53.29813,
        -51.960791,
        -51.772565,
        -53.779476,
        -52.161498,
    ]
    assert second.measurement == [
        -52.78842,
        -53.918962,
        -51.756357,
        -52.881369,
        -51.446903,
        -51.150364,
        -54.320869,
        -52.267171,
    ]
    assert runtime.run_record()["probe_profile"] == "V8_DEFAULT"


def test_a31_person_a_compat_probe_is_explicit_test_only_metadata(person_a_root):
    bundle = PersonASecurityBundleFactory(
        person_a_root,
        probe_profile="PERSON_A_V01_COMPAT_TEST",
    )
    runtime = PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=bundle)
    ).create(
        RunConfig(seed=31, duration_s=1.0, step_s=0.1, auto_traffic=False)
    )
    # Existing integration fixture opts in explicitly.
    assert runtime.probes.profile == "PERSON_A_V01_COMPAT_TEST"
    record = runtime.run_record()
    assert record["probe_profile"] == "PERSON_A_V01_COMPAT_TEST"
    assert "PERSON_A_COMPAT_PROBE_TEST_ONLY" in record["readiness_blockers"]

    # A newly constructed Person-A bundle remains on the real V8 default.
    default_bundle = PersonASecurityBundleFactory(person_a_root)
    assert default_bundle.probe_profile == "V8_DEFAULT"
    default_runtime = PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=default_bundle)
    ).create(RunConfig(seed=31, duration_s=1.0, step_s=0.1, auto_traffic=False))
    default_record = default_runtime.run_record()
    assert default_record["probe_profile"] == "V8_DEFAULT"
    assert "PERSON_A_COMPAT_PROBE_TEST_ONLY" not in default_record["readiness_blockers"]
    assert default_record["config_fingerprint"] != record["config_fingerprint"]
