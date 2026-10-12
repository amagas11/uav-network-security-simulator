from __future__ import annotations

from copy import deepcopy

from .test_aead_and_skg import SESSION, _events, _runtime
from .test_skg_closure import _advance_to_confirm_pending


def _fail_second_commit(runtime, monkeypatch):
    coordinator = runtime.security_coordinator
    started = coordinator.initiate_session(1, 2, SESSION, key_epoch=2)
    assert started["accepted"] is True
    handshake = _advance_to_confirm_pending(runtime, started["probe_id"])

    def fail_commit(_probe_id, _message):
        raise RuntimeError("deterministic second-endpoint commit failure")

    # Commit order is deterministic (node 1 then node 2), so node 1 has
    # installed epoch 2 before this injected node-2 failure is raised.
    monkeypatch.setattr(handshake.engines[2], "apply_confirm_blob", fail_commit)
    while not runtime.is_terminated and handshake.status != "FAILED":
        runtime.step()
    assert handshake.status == "FAILED"
    assert handshake.failure_reason == "SKG_CONFIRM_COMMIT_FAILED"
    assert "COMMIT_READY" in handshake.state_history
    return handshake


def test_a32_commit_failure_restores_previous_epoch_for_new_bidirectional_traffic(
    person_a_root, monkeypatch
):
    runtime = _runtime(person_a_root, preload=True, duration_s=3.0)
    coordinator = runtime.security_coordinator
    handshake = _fail_second_commit(runtime, monkeypatch)

    assert handshake.status == "FAILED"
    assert coordinator.current_epoch(1, 2, SESSION) == 1
    assert coordinator.current_epoch(2, 1, SESSION) == 1
    assert coordinator.key_reference(1, 2, SESSION, 2).state != "AVAILABLE"
    assert coordinator.key_reference(2, 1, SESSION, 2).state != "AVAILABLE"

    first_message = runtime.queue_message(
        1,
        2,
        "STATUS",
        {"status_code": 7, "value": 101},
        sensitive=True,
        session_id=SESSION,
    )
    second_message = runtime.queue_message(
        2,
        1,
        "STATUS",
        {"status_code": 7, "value": 202},
        sensitive=True,
        session_id=SESSION,
    )
    assert first_message and second_message
    while not runtime.is_terminated:
        runtime.step()

    delivered_to_two = {
        item.message_id for item in runtime.nodes[2].delivered_messages
    }
    delivered_to_one = {
        item.message_id for item in runtime.nodes[1].delivered_messages
    }
    assert first_message in delivered_to_two
    assert second_message in delivered_to_one

    business_tx = [
        event
        for event in _events(runtime, "TX", "STATUS")
        if event["message_id"] in {first_message, second_message}
    ]
    assert len(business_tx) == 2
    assert {
        event["online_features"]["packet"]["key_epoch"] for event in business_tx
    } == {1}


def test_a33_commit_failure_leaves_all_three_epoch_views_consistent(
    person_a_root, monkeypatch
):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    coordinator = runtime.security_coordinator
    handshake = _fail_second_commit(runtime, monkeypatch)

    assert handshake.previous_epochs == {1: 1, 2: 1}
    assert set(handshake.rollback_results) == {1, 2}
    assert all(
        result["restored"] is True
        and result["previous_epoch"] == 1
        and result["target_epoch"] == 2
        and result["target_state"] in {"KEY_REVOKED", "KEY_UNAVAILABLE"}
        for result in handshake.rollback_results.values()
    )
    assert runtime.nodes[1].key_epoch == runtime.nodes[2].key_epoch == 1
    assert coordinator.current_epoch(1, 2, SESSION) == 1
    assert coordinator.current_epoch(2, 1, SESSION) == 1

    aad = b"fresh-post-rollback-directional-check"
    from_one = coordinator.providers[1].encrypt(
        1, 2, SESSION, b"one-to-two", aad
    )
    from_two = coordinator.providers[2].encrypt(
        2, 1, SESSION, b"two-to-one", aad
    )
    assert from_one.status == from_two.status == "ok"
    assert from_one.key_epoch == from_two.key_epoch == 1
    assert (
        coordinator.providers[2].decrypt(
            2,
            1,
            SESSION,
            from_one.ciphertext,
            aad,
            nonce=from_one.nonce,
            key_id=from_one.key_id,
            key_epoch=from_one.key_epoch,
        ).plaintext
        == b"one-to-two"
    )
    assert (
        coordinator.providers[1].decrypt(
            1,
            2,
            SESSION,
            from_two.ciphertext,
            aad,
            nonce=from_two.nonce,
            key_id=from_two.key_id,
            key_epoch=from_two.key_epoch,
        ).plaintext
        == b"two-to-one"
    )


def test_a34_rollback_does_not_resurrect_invalid_previous_key(
    person_a_root, monkeypatch
):
    runtime = _runtime(person_a_root, preload=True, duration_s=2.0)
    coordinator = runtime.security_coordinator
    for local_id, peer_id in ((1, 2), (2, 1)):
        coordinator.providers[local_id].revoke(
            peer_id, SESSION, key_epoch=1, sim_time_s=0.0
        )
    assert coordinator.current_epoch(1, 2, SESSION) is None
    assert coordinator.current_epoch(2, 1, SESSION) is None

    handshake = _fail_second_commit(runtime, monkeypatch)
    assert handshake.previous_epochs == {1: None, 2: None}
    assert all(
        result["restored"] is False
        for result in handshake.rollback_results.values()
    )
    assert coordinator.current_epoch(1, 2, SESSION) is None
    assert coordinator.current_epoch(2, 1, SESSION) is None
    assert coordinator.providers[1].encrypt(
        1, 2, SESSION, b"must-not-send", b"aad"
    ).status == "key_unavailable"
    assert coordinator.providers[2].encrypt(
        2, 1, SESSION, b"must-not-send", b"aad"
    ).status == "key_unavailable"
    while not runtime.is_terminated:
        runtime.step()


def test_a35_normal_rekey_still_commits_epoch_two_and_preserves_epoch_one(
    person_a_root,
):
    runtime = _runtime(person_a_root, preload=True, duration_s=3.0)
    coordinator = runtime.security_coordinator
    assert runtime.queue_message(
        1, 2, "STATUS", {"value": 1}, sensitive=True, session_id=SESSION
    )
    old_intent = runtime.nodes[1].tx_queue.popleft()
    link = runtime.topology.get_link(1, 2)
    old_frame = runtime.crypto.protect(old_intent.message, 1, 2, link.link_id, 0)
    assert old_frame.key_epoch == 1

    started = coordinator.initiate_session(1, 2, SESSION, key_epoch=2)
    assert started["accepted"] is True
    runtime.start()
    handshake = coordinator.handshakes[started["probe_id"]]
    while not runtime.is_terminated and handshake.status != "AVAILABLE":
        runtime.step()
    assert handshake.status == "AVAILABLE"
    assert runtime.nodes[1].key_epoch == runtime.nodes[2].key_epoch == 2
    assert coordinator.current_epoch(1, 2, SESSION) == 2
    assert coordinator.current_epoch(2, 1, SESSION) == 2

    fresh = deepcopy(old_intent.message)
    fresh.message_id = runtime.context.ids.next("msg")
    fresh.sequence_no += 1
    fresh.key_epoch = runtime.nodes[1].key_epoch
    new_frame = runtime.crypto.protect(fresh, 1, 2, link.link_id, 0)
    assert new_frame.key_epoch == 2
    assert runtime.crypto.open(new_frame, 2).auth_result == "PASS"
    assert runtime.crypto.open(old_frame, 2).auth_result == "PASS"
