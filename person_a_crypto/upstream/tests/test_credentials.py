from __future__ import annotations

import sys
from dataclasses import fields, is_dataclass
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.credentials import CredentialResult, CredentialService
from crypto.types import STATUS_BAD_ARGUMENT, STATUS_CREDENTIAL_FAIL, STATUS_OK

FINGERPRINT = b"hw-fp-terminal-alpha-001"
OTHER_FINGERPRINT = b"hw-fp-terminal-bravo-002"


@pytest.fixture
def master_key() -> bytes:
    return bytes(range(32))


@pytest.fixture
def other_master_key() -> bytes:
    return bytes(range(32, 64))


@pytest.fixture
def svc(master_key: bytes) -> CredentialService:
    return CredentialService(master_key)


def _collect_bytes(obj: object) -> list[bytes]:
    found: list[bytes] = []
    if isinstance(obj, (bytes, bytearray)):
        found.append(bytes(obj))
        return found
    if isinstance(obj, str):
        found.append(obj.encode("utf-8"))
        return found
    if is_dataclass(obj) and not isinstance(obj, type):
        for item in fields(obj):
            found.extend(_collect_bytes(getattr(obj, item.name)))
    return found


def _assert_no_secrets(obj: object, master_key: bytes, fingerprint: bytes) -> None:
    assert not hasattr(obj, "master_key")
    assert not hasattr(obj, "fingerprint")
    names = {item.name for item in fields(obj)} if is_dataclass(obj) and not isinstance(obj, type) else set()
    assert "master_key" not in names
    assert "fingerprint" not in names
    blobs = _collect_bytes(obj)
    assert master_key not in blobs
    assert fingerprint not in blobs
    dumped = repr(obj)
    assert "key=" not in dumped
    assert master_key.hex() not in dumped
    assert fingerprint.hex() not in dumped
    try:
        text = fingerprint.decode("ascii")
    except UnicodeDecodeError:
        text = None
    if text:
        assert text not in dumped


def test_same_fingerprint_and_master_key_yield_same_serial_and_verify_ok(
    svc: CredentialService,
) -> None:
    first = svc.derive(FINGERPRINT, terminal_id="gcs-1")
    second = svc.derive(FINGERPRINT, terminal_id="gcs-1")
    assert first.status == STATUS_OK
    assert second.status == STATUS_OK
    assert first.serial is not None and len(first.serial) == 32
    assert first.serial == second.serial
    assert first.credential_id == second.credential_id
    assert first.credential_id is not None and first.credential_id.startswith("cred-")

    checked = svc.verify(FINGERPRINT, first.serial, terminal_id="gcs-1")
    assert checked.status == STATUS_OK
    assert checked.serial is None
    assert checked.credential_id == first.credential_id


def test_different_fingerprint_or_master_key_is_credential_fail_without_serial_leak(
    svc: CredentialService,
    other_master_key: bytes,
) -> None:
    enrolled = svc.derive(FINGERPRINT)
    assert enrolled.status == STATUS_OK
    assert enrolled.serial is not None

    wrong_fp = svc.verify(OTHER_FINGERPRINT, enrolled.serial)
    assert wrong_fp.status == STATUS_CREDENTIAL_FAIL
    assert wrong_fp.serial is None
    assert enrolled.serial not in _collect_bytes(wrong_fp)
    assert enrolled.serial.hex() not in repr(wrong_fp)

    other = CredentialService(other_master_key)
    other_enrolled = other.derive(FINGERPRINT)
    assert other_enrolled.status == STATUS_OK
    assert other_enrolled.serial != enrolled.serial

    wrong_key = other.verify(FINGERPRINT, enrolled.serial)
    assert wrong_key.status == STATUS_CREDENTIAL_FAIL
    assert wrong_key.serial is None
    assert enrolled.serial not in _collect_bytes(wrong_key)
    assert other_enrolled.serial not in _collect_bytes(wrong_key)
    assert enrolled.serial.hex() not in repr(wrong_key)
    assert other_enrolled.serial.hex() not in repr(wrong_key)


def test_empty_fingerprint_is_bad_argument(svc: CredentialService) -> None:
    derived = svc.derive(b"")
    assert derived.status == STATUS_BAD_ARGUMENT
    assert derived.serial is None

    verified = svc.verify(b"", bytes(32))
    assert verified.status == STATUS_BAD_ARGUMENT
    assert verified.serial is None

    not_bytes = svc.derive("not-bytes")  # type: ignore[arg-type]
    assert not_bytes.status == STATUS_BAD_ARGUMENT


def test_results_and_repr_do_not_contain_master_key_or_fingerprint(
    svc: CredentialService,
    master_key: bytes,
) -> None:
    enrolled = svc.derive(FINGERPRINT, terminal_id="uav-3")
    checked = svc.verify(FINGERPRINT, enrolled.serial, terminal_id="uav-3")
    failed = svc.verify(OTHER_FINGERPRINT, enrolled.serial, terminal_id="uav-3")
    for obj in (svc, enrolled, checked, failed):
        _assert_no_secrets(obj, master_key, FINGERPRINT)
        _assert_no_secrets(obj, master_key, OTHER_FINGERPRINT)


def test_bad_master_key_raises_value_error() -> None:
    with pytest.raises(ValueError):
        CredentialService(b"short")
    with pytest.raises(ValueError):
        CredentialService("not-bytes")  # type: ignore[arg-type]


def test_credential_result_has_no_secret_fields() -> None:
    names = {item.name for item in fields(CredentialResult)}
    assert "master_key" not in names
    assert "fingerprint" not in names
    assert "key" not in names
