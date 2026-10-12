"""邻接链路密码服务。A2–A6 可 import；A8 见 README 与 test_vectors.json。未接入仿真。"""

from .aead import AeadService, decrypt, encrypt
from .credentials import CredentialResult, CredentialService
from .identity import HandshakeSignResult, HandshakeVerifyResult, IdentityStore, NodeIdentity
from .key_provider import KeyEvent, KeyProvider
from .observations import (
    LocalPhyObservation,
    synthesize_eve_rssi,
    synthesize_reciprocal_rssi,
    synthesize_reciprocal_rssi_with_eve,
)
from .skg import SkgEngine, SkgResult
from .types import (
    ALG_AES_256_GCM,
    AuthResult,
    CryptoResult,
    STATUS_AUTH_FAIL,
    STATUS_BAD_ARGUMENT,
    STATUS_CREDENTIAL_FAIL,
    STATUS_IDENTITY_FAIL,
    STATUS_KEY_EXPIRED,
    STATUS_KEY_UNAVAILABLE,
    STATUS_NONCE_REUSE,
    STATUS_OK,
    STATUS_SKG_FAIL,
    STATUS_UNENCRYPTED,
)

__all__ = [
    "ALG_AES_256_GCM",
    "AeadService",
    "AuthResult",
    "CredentialResult",
    "CredentialService",
    "CryptoResult",
    "HandshakeSignResult",
    "HandshakeVerifyResult",
    "IdentityStore",
    "KeyEvent",
    "KeyProvider",
    "LocalPhyObservation",
    "NodeIdentity",
    "SkgEngine",
    "SkgResult",
    "STATUS_AUTH_FAIL",
    "STATUS_BAD_ARGUMENT",
    "STATUS_CREDENTIAL_FAIL",
    "STATUS_IDENTITY_FAIL",
    "STATUS_KEY_EXPIRED",
    "STATUS_KEY_UNAVAILABLE",
    "STATUS_NONCE_REUSE",
    "STATUS_OK",
    "STATUS_SKG_FAIL",
    "STATUS_UNENCRYPTED",
    "decrypt",
    "encrypt",
    "synthesize_eve_rssi",
    "synthesize_reciprocal_rssi",
    "synthesize_reciprocal_rssi_with_eve",
]
