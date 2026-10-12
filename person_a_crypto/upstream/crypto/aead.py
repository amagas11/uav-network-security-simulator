"""AES-256-GCM 加解密（A2）。调用方直接传入 32 字节密钥；KeyProvider 留给 A3。"""

from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .types import (
    ALG_AES_256_GCM,
    AuthResult,
    CryptoResult,
    STATUS_AUTH_FAIL,
    STATUS_BAD_ARGUMENT,
    STATUS_KEY_UNAVAILABLE,
    STATUS_NONCE_REUSE,
    STATUS_OK,
)

KEY_LEN = 32
NONCE_LEN = 12
_COUNTER_MAX = (1 << 64) - 1
_TAG_LEN = 4


def _direction_label(src_id: int, dst_id: int) -> str:
    return f"{src_id}->{dst_id}"


def _direction_tag(src_id: int, dst_id: int) -> bytes:
    digest = hashlib.sha256(_direction_label(src_id, dst_id).encode("ascii")).digest()
    return digest[:_TAG_LEN]


def _make_nonce(src_id: int, dst_id: int, counter: int) -> bytes:
    return _direction_tag(src_id, dst_id) + struct.pack(">Q", counter)


def _bound_aad(src_id: int, dst_id: int, session_id: str, aad: bytes) -> bytes:
    header = f"{_direction_label(src_id, dst_id)}|{session_id}|".encode("utf-8")
    return header + aad


def _default_key_id(local_id: int, peer_id: int, session_id: str, key_epoch: int) -> str:
    lo, hi = (local_id, peer_id) if local_id <= peer_id else (peer_id, local_id)
    return f"k-{lo}-{hi}-{session_id}-e{key_epoch:02d}"


def _key_status(key: object) -> str | None:
    if key is None:
        return STATUS_KEY_UNAVAILABLE
    if isinstance(key, (bytes, bytearray)):
        if len(key) == 0:
            return STATUS_KEY_UNAVAILABLE
        if len(key) != KEY_LEN:
            return STATUS_BAD_ARGUMENT
        return None
    return STATUS_BAD_ARGUMENT


def _is_node_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class AeadService:
    """每发送方向独立计数 nonce，`3->7` 与 `7->3` 不共用空间。"""

    def __init__(self) -> None:
        self._counters: dict[tuple[int, int, str], int] = {}

    def encrypt(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        plaintext: bytes,
        aad: bytes,
        *,
        key: bytes | None = None,
        key_id: str | None = None,
        key_epoch: int | None = None,
    ) -> CryptoResult:
        ids_status = self._ids_status(local_id, peer_id, session_id)
        if ids_status is not None:
            return self._fail(ids_status, local_id=local_id)

        if not isinstance(plaintext, (bytes, bytearray)) or not isinstance(aad, (bytes, bytearray)):
            return self._fail(STATUS_BAD_ARGUMENT, local_id=local_id, claimed_src=local_id)

        key_status = _key_status(key)
        if key_status is not None:
            return self._fail(key_status, local_id=local_id, claimed_src=local_id)

        epoch = 0 if key_epoch is None else key_epoch
        handle = key_id or _default_key_id(local_id, peer_id, session_id, epoch)
        counter_key = (local_id, peer_id, session_id)
        next_counter = self._counters.get(counter_key, 0) + 1
        if next_counter > _COUNTER_MAX:
            return self._fail(
                STATUS_NONCE_REUSE,
                key_id=handle,
                key_epoch=epoch,
                local_id=local_id,
                claimed_src=local_id,
            )

        nonce = _make_nonce(local_id, peer_id, next_counter)
        bound = _bound_aad(local_id, peer_id, session_id, bytes(aad))
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), bound)
        self._counters[counter_key] = next_counter
        return CryptoResult(
            status=STATUS_OK,
            key_id=handle,
            key_epoch=epoch,
            ciphertext=ciphertext,
            plaintext=None,
            nonce=nonce,
            auth=AuthResult(
                status=STATUS_OK,
                key_id=handle,
                key_epoch=epoch,
                alg=ALG_AES_256_GCM,
                local_id=local_id,
                claimed_src=local_id,
            ),
        )

    def decrypt(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        ciphertext: bytes,
        aad: bytes,
        *,
        key: bytes | None = None,
        nonce: bytes | None = None,
        key_id: str | None = None,
        key_epoch: int | None = None,
    ) -> CryptoResult:
        ids_status = self._ids_status(local_id, peer_id, session_id)
        if ids_status is not None:
            return self._fail(ids_status, local_id=local_id, claimed_src=peer_id)

        if not isinstance(ciphertext, (bytes, bytearray)) or not isinstance(aad, (bytes, bytearray)):
            return self._fail(STATUS_BAD_ARGUMENT, local_id=local_id, claimed_src=peer_id)

        key_status = _key_status(key)
        if key_status is not None:
            return self._fail(key_status, local_id=local_id, claimed_src=peer_id)

        epoch = 0 if key_epoch is None else key_epoch
        handle = key_id or _default_key_id(local_id, peer_id, session_id, epoch)

        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
            return self._fail(
                STATUS_BAD_ARGUMENT,
                key_id=handle,
                key_epoch=epoch,
                local_id=local_id,
                claimed_src=peer_id,
            )

        nonce_b = bytes(nonce)
        if nonce_b[:_TAG_LEN] != _direction_tag(peer_id, local_id):
            return self._fail(
                STATUS_AUTH_FAIL,
                key_id=handle,
                key_epoch=epoch,
                local_id=local_id,
                claimed_src=peer_id,
            )

        bound = _bound_aad(peer_id, local_id, session_id, bytes(aad))
        try:
            plaintext = AESGCM(bytes(key)).decrypt(nonce_b, bytes(ciphertext), bound)
        except InvalidTag:
            return self._fail(
                STATUS_AUTH_FAIL,
                key_id=handle,
                key_epoch=epoch,
                local_id=local_id,
                claimed_src=peer_id,
            )

        return CryptoResult(
            status=STATUS_OK,
            key_id=handle,
            key_epoch=epoch,
            ciphertext=None,
            plaintext=plaintext,
            nonce=nonce_b,
            auth=AuthResult(
                status=STATUS_OK,
                key_id=handle,
                key_epoch=epoch,
                alg=ALG_AES_256_GCM,
                local_id=local_id,
                claimed_src=peer_id,
            ),
        )

    @staticmethod
    def _ids_status(local_id: object, peer_id: object, session_id: object) -> str | None:
        if not _is_node_id(local_id) or not _is_node_id(peer_id):
            return STATUS_BAD_ARGUMENT
        if not isinstance(session_id, str) or session_id == "":
            return STATUS_BAD_ARGUMENT
        if local_id == peer_id:
            return STATUS_BAD_ARGUMENT
        return None

    @staticmethod
    def _fail(
        status: str,
        *,
        key_id: str | None = None,
        key_epoch: int | None = None,
        local_id: int | None = None,
        claimed_src: int | None = None,
    ) -> CryptoResult:
        return CryptoResult(
            status=status,
            key_id=key_id,
            key_epoch=key_epoch,
            ciphertext=None,
            plaintext=None,
            nonce=None,
            auth=AuthResult(
                status=status,
                key_id=key_id,
                key_epoch=key_epoch,
                alg=ALG_AES_256_GCM,
                local_id=local_id,
                claimed_src=claimed_src,
            ),
        )


_default_service = AeadService()
encrypt = _default_service.encrypt
decrypt = _default_service.decrypt
