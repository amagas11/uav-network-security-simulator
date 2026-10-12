from __future__ import annotations

import inspect
import sys
from dataclasses import fields, is_dataclass
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.key_provider import (
    EVENT_KEY_READY,
    EVENT_KEY_REVOKED,
    EVENT_REKEY_OK,
    EVENT_REKEY_ROLLBACK_OK,
    KeyProvider,
    STATUS_KEY_REVOKED,
)
from crypto.types import (
    STATUS_KEY_EXPIRED,
    STATUS_KEY_UNAVAILABLE,
    STATUS_OK,
)

SESSION = "link-3-7-s1"
AAD = b"src=3,dst=7,seq=18,msg_type=data,key_epoch=0,direction=3->7"
PLAINTEXT = b"mission-cmd-42"
KEY_V1 = bytes(range(32))
KEY_V2 = bytes(range(32, 64))


@pytest.fixture
def node3() -> KeyProvider:
    return KeyProvider(3)


@pytest.fixture
def node7() -> KeyProvider:
    return KeyProvider(7)


def _collect_bytes(obj: object) -> list[bytes]:
    found: list[bytes] = []
    if isinstance(obj, (bytes, bytearray)):
        found.append(bytes(obj))
        return found
    if is_dataclass(obj) and not isinstance(obj, type):
        for item in fields(obj):
            found.extend(_collect_bytes(getattr(obj, item.name)))
    return found


def _assert_no_raw_key(result: object, *raw_keys: bytes) -> None:
    assert not hasattr(result, "key")
    names = {item.name for item in fields(result)} if is_dataclass(result) and not isinstance(result, type) else set()
    assert "key" not in names
    blobs = _collect_bytes(result)
    dumped = repr(result)
    for raw_key in raw_keys:
        for blob in blobs:
            assert blob != raw_key
        assert raw_key.hex() not in dumped


def test_put_then_encrypt_decrypt_roundtrip(node3: KeyProvider, node7: KeyProvider) -> None:
    ready = node3.put(7, SESSION, KEY_V1, key_epoch=0)
    assert ready.event == EVENT_KEY_READY
    assert ready.status == STATUS_OK
    assert ready.key_id is not None
    node7.put(3, SESSION, KEY_V1, key_epoch=0)
    assert node3.get_status(7, SESSION) == STATUS_OK

    enc = node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert enc.status == STATUS_OK
    assert enc.auth is not None and enc.auth.status == STATUS_OK
    assert enc.plaintext is None
    assert enc.ciphertext is not None and enc.nonce is not None
    assert enc.key_epoch == 0

    dec = node7.decrypt(
        7, 3, SESSION, enc.ciphertext, AAD,
        nonce=enc.nonce, key_id=enc.key_id, key_epoch=enc.key_epoch,
    )
    assert dec.status == STATUS_OK
    assert dec.plaintext == PLAINTEXT
    assert dec.ciphertext is None


def test_encrypt_without_put_is_key_unavailable(node3: KeyProvider) -> None:
    assert node3.get_status(7, SESSION) == STATUS_KEY_UNAVAILABLE
    enc = node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert enc.status == STATUS_KEY_UNAVAILABLE
    assert enc.plaintext is None
    assert enc.ciphertext is None


def test_revoke_and_expiry_block_encrypt_without_plaintext(node3: KeyProvider) -> None:
    node3.put(7, SESSION, KEY_V1, key_epoch=0, expires_at_s=10.0)
    revoked = node3.revoke(7, SESSION)
    assert revoked.event == EVENT_KEY_REVOKED
    assert node3.get_status(7, SESSION) == STATUS_KEY_REVOKED
    after_revoke = node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert after_revoke.status == STATUS_KEY_UNAVAILABLE
    assert after_revoke.plaintext is None
    assert after_revoke.ciphertext is None

    fresh = KeyProvider(3)
    fresh.put(7, SESSION, KEY_V1, key_epoch=1, expires_at_s=10.0)
    assert fresh.get_status(7, SESSION, sim_time_s=9.9) == STATUS_OK
    still_ok = fresh.encrypt(3, 7, SESSION, PLAINTEXT, AAD, sim_time_s=9.9)
    assert still_ok.status == STATUS_OK

    assert fresh.get_status(7, SESSION, sim_time_s=10.0) == STATUS_KEY_EXPIRED
    after_expiry = fresh.encrypt(3, 7, SESSION, PLAINTEXT, AAD, sim_time_s=10.0)
    assert after_expiry.status == STATUS_KEY_EXPIRED
    assert after_expiry.plaintext is None
    assert after_expiry.ciphertext is None


def test_new_epoch_encrypts_while_old_ciphertext_still_decrypts(
    node3: KeyProvider, node7: KeyProvider
) -> None:
    node3.put(7, SESSION, KEY_V1, key_epoch=1)
    node7.put(3, SESSION, KEY_V1, key_epoch=1)
    old = node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert old.status == STATUS_OK
    assert old.key_epoch == 1

    rekey3 = node3.put(7, SESSION, KEY_V2, key_epoch=2)
    rekey7 = node7.put(3, SESSION, KEY_V2, key_epoch=2)
    assert rekey3.event == EVENT_REKEY_OK
    assert rekey7.event == EVENT_REKEY_OK

    new_plain = b"new-payload"
    new = node3.encrypt(3, 7, SESSION, new_plain, AAD)
    assert new.status == STATUS_OK
    assert new.key_epoch == 2
    assert new.key_id != old.key_id

    dec_new = node7.decrypt(7, 3, SESSION, new.ciphertext, AAD, nonce=new.nonce)
    assert dec_new.status == STATUS_OK
    assert dec_new.plaintext == new_plain

    dec_old = node7.decrypt(
        7, 3, SESSION, old.ciphertext, AAD,
        nonce=old.nonce, key_id=old.key_id, key_epoch=old.key_epoch,
    )
    assert dec_old.status == STATUS_OK
    assert dec_old.plaintext == PLAINTEXT

    dec_old_default = node7.decrypt(7, 3, SESSION, old.ciphertext, AAD, nonce=old.nonce)
    assert dec_old_default.status == STATUS_OK
    assert dec_old_default.plaintext == PLAINTEXT


def test_results_do_not_contain_raw_key(node3: KeyProvider, node7: KeyProvider) -> None:
    event = node3.put(7, SESSION, KEY_V1, key_epoch=0)
    node7.put(3, SESSION, KEY_V1, key_epoch=0)
    enc = node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    dec = node7.decrypt(7, 3, SESSION, enc.ciphertext, AAD, nonce=enc.nonce, key_id=enc.key_id)
    revoked = node3.revoke(7, SESSION)

    for obj in (event, enc, dec, revoked, enc.auth, dec.auth):
        _assert_no_raw_key(obj, KEY_V1, KEY_V2)
    _assert_no_raw_key(event, KEY_V1)
    assert "key" not in inspect.signature(node3.encrypt).parameters
    assert "key" not in inspect.signature(node3.decrypt).parameters
    assert "key" not in repr(node3)


def test_failed_rekey_rollback_restores_previous_outbound_epoch(
    node3: KeyProvider, node7: KeyProvider
) -> None:
    node3.put(7, SESSION, KEY_V1, key_epoch=1)
    node7.put(3, SESSION, KEY_V1, key_epoch=1)
    node3.put(7, SESSION, KEY_V2, key_epoch=2)

    rolled_back = node3.rollback_epoch(
        7, SESSION, failed_epoch=2, restore_epoch=1
    )
    assert rolled_back.event == EVENT_REKEY_ROLLBACK_OK
    assert rolled_back.status == STATUS_OK
    assert rolled_back.key_epoch == 1
    assert node3.get_status(7, SESSION, key_epoch=2) == STATUS_KEY_REVOKED

    new = node3.encrypt(3, 7, SESSION, b"post-rollback", AAD)
    assert new.status == STATUS_OK
    assert new.key_epoch == 1
    opened = node7.decrypt(
        7,
        3,
        SESSION,
        new.ciphertext,
        AAD,
        nonce=new.nonce,
        key_id=new.key_id,
        key_epoch=new.key_epoch,
    )
    assert opened.status == STATUS_OK
    assert opened.plaintext == b"post-rollback"
    _assert_no_raw_key(rolled_back, KEY_V1, KEY_V2)


def test_rollback_is_idempotent_when_peer_never_committed_target(
    node3: KeyProvider,
) -> None:
    node3.put(7, SESSION, KEY_V1, key_epoch=1)

    rolled_back = node3.rollback_epoch(
        7, SESSION, failed_epoch=2, restore_epoch=1
    )
    assert rolled_back.event == EVENT_REKEY_ROLLBACK_OK
    assert rolled_back.key_epoch == 1
    assert node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD).key_epoch == 1


def test_rollback_never_resurrects_revoked_previous_epoch(
    node3: KeyProvider,
) -> None:
    node3.put(7, SESSION, KEY_V1, key_epoch=1)
    node3.revoke(7, SESSION, key_epoch=1)
    node3.put(7, SESSION, KEY_V2, key_epoch=2)

    failed = node3.rollback_epoch(7, SESSION, failed_epoch=2, restore_epoch=1)
    assert failed.status == STATUS_KEY_UNAVAILABLE
    assert node3.get_status(7, SESSION, key_epoch=1) == STATUS_KEY_UNAVAILABLE
    assert node3.get_status(7, SESSION, key_epoch=2) == STATUS_KEY_REVOKED
    assert node3.encrypt(3, 7, SESSION, PLAINTEXT, AAD).status == STATUS_KEY_UNAVAILABLE
