"""终端凭据：指纹字节 + 内部主密钥 → 序列号，以及恒定时间校验（A7）。"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .types import STATUS_BAD_ARGUMENT, STATUS_CREDENTIAL_FAIL, STATUS_OK

MASTER_KEY_LEN = 32
SERIAL_LEN = 32
_HKDF_INFO_PREFIX = b"uav-cred-v1"
_HANDLE_PREFIX = b"uav-cred-id|"


@dataclass(frozen=True, slots=True)
class CredentialResult:
    status: str
    serial: bytes | None = None
    credential_id: str | None = None


def _hkdf_info(terminal_id: str | None) -> bytes:
    if terminal_id is None:
        return _HKDF_INFO_PREFIX
    return _HKDF_INFO_PREFIX + b"|" + terminal_id.encode("utf-8")


def _credential_id(serial: bytes) -> str:
    digest = hashlib.sha256(_HANDLE_PREFIX + serial).digest()
    return "cred-" + digest[:8].hex()


def _fingerprint_status(fingerprint: object) -> str | None:
    if not isinstance(fingerprint, (bytes, bytearray)):
        return STATUS_BAD_ARGUMENT
    if len(fingerprint) == 0:
        return STATUS_BAD_ARGUMENT
    return None


def _terminal_id_status(terminal_id: object) -> str | None:
    if terminal_id is None:
        return None
    if not isinstance(terminal_id, str) or terminal_id == "":
        return STATUS_BAD_ARGUMENT
    return None


def _serial_arg_status(serial: object) -> str | None:
    if not isinstance(serial, (bytes, bytearray)):
        return STATUS_BAD_ARGUMENT
    if len(serial) == 0:
        return STATUS_BAD_ARGUMENT
    return None


class CredentialService:
    """内部主密钥只留在此对象；返回值只有 serial / credential_id 句柄。"""

    def __init__(self, master_key: bytes) -> None:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != MASTER_KEY_LEN:
            raise ValueError("master_key must be 32 bytes")
        self._master_key = bytes(master_key)

    def __repr__(self) -> str:
        return "CredentialService()"

    def _derive_serial(self, fingerprint: bytes, terminal_id: str | None) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SERIAL_LEN,
            salt=self._master_key,
            info=_hkdf_info(terminal_id),
        )
        return hkdf.derive(fingerprint)

    def derive(self, fingerprint: bytes, *, terminal_id: str | None = None) -> CredentialResult:
        arg_status = _fingerprint_status(fingerprint) or _terminal_id_status(terminal_id)
        if arg_status is not None:
            return CredentialResult(status=arg_status)
        serial = self._derive_serial(bytes(fingerprint), terminal_id)
        return CredentialResult(
            status=STATUS_OK,
            serial=serial,
            credential_id=_credential_id(serial),
        )

    def verify(
        self,
        fingerprint: bytes,
        serial: bytes,
        *,
        terminal_id: str | None = None,
    ) -> CredentialResult:
        arg_status = (
            _fingerprint_status(fingerprint)
            or _serial_arg_status(serial)
            or _terminal_id_status(terminal_id)
        )
        if arg_status is not None:
            return CredentialResult(status=arg_status)
        expected = self._derive_serial(bytes(fingerprint), terminal_id)
        presented = bytes(serial)
        if len(presented) != len(expected) or not hmac.compare_digest(presented, expected):
            return CredentialResult(status=STATUS_CREDENTIAL_FAIL)
        return CredentialResult(status=STATUS_OK, credential_id=_credential_id(expected))
