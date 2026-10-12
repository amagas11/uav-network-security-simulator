from __future__ import annotations

import sys
from dataclasses import fields, is_dataclass
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.aead import AeadService, encrypt
from crypto.types import (
    STATUS_AUTH_FAIL,
    STATUS_KEY_UNAVAILABLE,
    STATUS_OK,
)

SESSION = "link-3-7-s1"
AAD = b"src=3,dst=7,seq=18,msg_type=data,key_epoch=0,direction=3->7"
PLAINTEXT = b"mission-cmd-42"


@pytest.fixture
def key() -> bytes:
    return bytes(range(32))


@pytest.fixture
def aead() -> AeadService:
    return AeadService()


def _collect_bytes(obj: object) -> list[bytes]:
    found: list[bytes] = []
    if isinstance(obj, (bytes, bytearray)):
        found.append(bytes(obj))
        return found
    if is_dataclass(obj) and not isinstance(obj, type):
        for item in fields(obj):
            found.extend(_collect_bytes(getattr(obj, item.name)))
    return found


def _assert_no_raw_key(result: object, raw_key: bytes) -> None:
    assert not hasattr(result, "key")
    names = {item.name for item in fields(result)} if is_dataclass(result) and not isinstance(result, type) else set()
    assert "key" not in names
    for blob in _collect_bytes(result):
        assert blob != raw_key
    dumped = repr(result)
    assert "key=" not in dumped or "key_id=" in dumped
    assert raw_key.hex() not in dumped


def test_roundtrip_plaintext_matches_and_status_ok(aead: AeadService, key: bytes) -> None:
    enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=key, key_id="k-3-7-s1-e00", key_epoch=0)
    assert enc.status == STATUS_OK
    assert enc.auth is not None and enc.auth.status == STATUS_OK
    assert enc.ciphertext is not None and enc.nonce is not None
    assert enc.plaintext is None
    assert enc.ciphertext != PLAINTEXT
    assert PLAINTEXT not in enc.ciphertext

    dec = aead.decrypt(
        7, 3, SESSION, enc.ciphertext, AAD,
        key=key, nonce=enc.nonce, key_id=enc.key_id, key_epoch=enc.key_epoch,
    )
    assert dec.status == STATUS_OK
    assert dec.auth is not None and dec.auth.status == STATUS_OK
    assert dec.plaintext == PLAINTEXT
    assert dec.ciphertext is None
    assert dec.key_id == "k-3-7-s1-e00"


def test_tampered_ciphertext_is_auth_fail_without_plaintext(aead: AeadService, key: bytes) -> None:
    enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=key)
    assert enc.ciphertext is not None
    tampered = bytearray(enc.ciphertext)
    tampered[0] ^= 0x01

    dec = aead.decrypt(
        7, 3, SESSION, bytes(tampered), AAD,
        key=key, nonce=enc.nonce, key_id=enc.key_id, key_epoch=enc.key_epoch,
    )
    assert dec.status == STATUS_AUTH_FAIL
    assert dec.auth is not None and dec.auth.status == STATUS_AUTH_FAIL
    assert dec.plaintext is None


def test_missing_or_empty_key_is_key_unavailable(aead: AeadService) -> None:
    missing_enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=None)
    assert missing_enc.status == STATUS_KEY_UNAVAILABLE
    assert missing_enc.plaintext is None
    assert missing_enc.ciphertext is None

    empty_enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=b"")
    assert empty_enc.status == STATUS_KEY_UNAVAILABLE
    assert empty_enc.plaintext is None

    enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=bytes(range(32)))
    missing_dec = aead.decrypt(
        7, 3, SESSION, enc.ciphertext, AAD,
        key=None, nonce=enc.nonce,
    )
    assert missing_dec.status == STATUS_KEY_UNAVAILABLE
    assert missing_dec.plaintext is None

    empty_dec = aead.decrypt(
        7, 3, SESSION, enc.ciphertext, AAD,
        key=b"", nonce=enc.nonce,
    )
    assert empty_dec.status == STATUS_KEY_UNAVAILABLE
    assert empty_dec.plaintext is None


def test_result_does_not_contain_raw_key(aead: AeadService, key: bytes) -> None:
    enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=key, key_id="k-3-7-s1-e00")
    _assert_no_raw_key(enc, key)
    if enc.auth is not None:
        _assert_no_raw_key(enc.auth, key)

    dec = aead.decrypt(
        7, 3, SESSION, enc.ciphertext, AAD,
        key=key, nonce=enc.nonce, key_id=enc.key_id,
    )
    _assert_no_raw_key(dec, key)
    if dec.auth is not None:
        _assert_no_raw_key(dec.auth, key)

    module_enc = encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=key)
    _assert_no_raw_key(module_enc, key)


def test_wrong_direction_is_auth_fail(aead: AeadService, key: bytes) -> None:
    enc = aead.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=key)
    swapped = aead.decrypt(
        3, 7, SESSION, enc.ciphertext, AAD,
        key=key, nonce=enc.nonce,
    )
    assert swapped.status == STATUS_AUTH_FAIL
    assert swapped.plaintext is None
