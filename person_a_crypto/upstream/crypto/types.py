"""A1 稳定失败码与返回类型。对象里只有 key_id 句柄，不含密钥字节。"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_OK = "ok"
STATUS_KEY_UNAVAILABLE = "key_unavailable"
STATUS_KEY_EXPIRED = "key_expired"
STATUS_AUTH_FAIL = "auth_fail"
STATUS_NONCE_REUSE = "nonce_reuse"
STATUS_IDENTITY_FAIL = "identity_fail"
STATUS_SKG_FAIL = "skg_fail"
STATUS_CREDENTIAL_FAIL = "credential_fail"
STATUS_BAD_ARGUMENT = "bad_argument"
STATUS_UNENCRYPTED = "unencrypted"

ALG_AES_256_GCM = "AES-256-GCM"

FAILURE_CODES = (
    STATUS_OK,
    STATUS_KEY_UNAVAILABLE,
    STATUS_KEY_EXPIRED,
    STATUS_AUTH_FAIL,
    STATUS_NONCE_REUSE,
    STATUS_IDENTITY_FAIL,
    STATUS_SKG_FAIL,
    STATUS_CREDENTIAL_FAIL,
    STATUS_BAD_ARGUMENT,
    STATUS_UNENCRYPTED,
)


@dataclass(frozen=True, slots=True)
class AuthResult:
    status: str
    key_id: str | None = None
    key_epoch: int | None = None
    alg: str = ALG_AES_256_GCM
    local_id: int | None = None
    claimed_src: int | None = None


@dataclass(frozen=True, slots=True)
class CryptoResult:
    status: str
    key_id: str | None = None
    key_epoch: int | None = None
    ciphertext: bytes | None = None
    plaintext: bytes | None = None
    nonce: bytes | None = None
    auth: AuthResult | None = None
