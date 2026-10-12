from __future__ import annotations

import sys
from dataclasses import fields, is_dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.identity import IdentityStore, NodeIdentity
from crypto.types import STATUS_IDENTITY_FAIL, STATUS_OK

SESSION = "link-3-7-s1"
PROBE = "prb-00042"
BLOB = b"skg-reconcile-blob"


def _keypair_pems() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


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


def _assert_no_private_key(result: object, private_pem: bytes) -> None:
    assert not hasattr(result, "private_key")
    assert not hasattr(result, "private_key_pem")
    names = {item.name for item in fields(result)} if is_dataclass(result) and not isinstance(result, type) else set()
    assert "private_key" not in names
    assert "private_key_pem" not in names
    dumped = repr(result)
    assert private_pem not in _collect_bytes(result)
    assert private_pem.decode("ascii") not in dumped
    assert private_pem.hex() not in dumped


def test_node3_sign_node7_verifies_with_node3_public_key() -> None:
    node3 = IdentityStore.generate(3, "uav-3")
    node7 = IdentityStore.generate(7, "uav-7")
    node7.trust_public(node3.public_material())

    signed = node3.sign_handshake(3, 7, SESSION, PROBE, BLOB)
    assert signed.status == STATUS_OK
    assert signed.identity_id == "uav-3"
    assert signed.signature
    assert signed.public_key_pem == node3.public_material()["public_key_pem"]

    verified = node7.verify_handshake(
        7, 3, SESSION, PROBE, BLOB,
        signature=signed.signature,
        identity_id=signed.identity_id,
        public_key_pem=signed.public_key_pem,
    )
    assert verified.status == STATUS_OK
    assert verified.node_id == 3
    assert verified.identity_id == "uav-3"


def test_tampered_blob_or_wrong_public_key_is_identity_fail() -> None:
    node3 = IdentityStore.generate(3, "uav-3")
    node5 = IdentityStore.generate(5, "uav-5")
    node7 = IdentityStore.generate(7, "uav-7")
    node7.trust_public(node3.public_material())
    node7.trust_public(node5.public_material())
    signed = node3.sign_handshake(3, 7, SESSION, PROBE, BLOB)

    tampered = node7.verify_handshake(
        7, 3, SESSION, PROBE, BLOB + b"x",
        signature=signed.signature,
        identity_id=signed.identity_id,
        public_key_pem=signed.public_key_pem,
    )
    assert tampered.status == STATUS_IDENTITY_FAIL

    wrong_key = node7.verify_handshake(
        7, 3, SESSION, PROBE, BLOB,
        signature=signed.signature,
        identity_id=signed.identity_id,
        public_key_pem=node5.public_material()["public_key_pem"],
    )
    assert wrong_key.status == STATUS_IDENTITY_FAIL


def test_node5_impersonating_node3_is_identity_fail() -> None:
    node3 = IdentityStore.generate(3, "uav-3")
    node5 = IdentityStore.generate(5, "uav-5")
    node7 = IdentityStore.generate(7, "uav-7")
    node7.trust_public(node3.public_material())
    node7.trust_public(node5.public_material())

    signed_as_3 = node5.sign_handshake(3, 7, SESSION, PROBE, BLOB)
    assert signed_as_3.status == STATUS_IDENTITY_FAIL
    assert signed_as_3.signature is None

    signed_5 = node5.sign_handshake(5, 7, SESSION, PROBE, BLOB)
    assert signed_5.status == STATUS_OK
    impersonated = node7.verify_handshake(
        7, 3, SESSION, PROBE, BLOB,
        signature=signed_5.signature,
        identity_id="uav-3",
        public_key_pem=signed_5.public_key_pem,
    )
    assert impersonated.status == STATUS_IDENTITY_FAIL


def test_results_do_not_contain_private_key() -> None:
    private_pem, public_pem = _keypair_pems()
    material = {
        "node_id": 3,
        "identity_id": "uav-3",
        "private_key_pem": private_pem.decode("ascii"),
        "public_key_pem": public_pem.decode("ascii"),
    }
    node3 = IdentityStore.load(material)
    node7 = IdentityStore.generate(7, "uav-7")
    node7.trust_public(node3.public_material())
    signed = node3.sign_handshake(3, 7, SESSION, PROBE, BLOB)
    verified = node7.verify_handshake(
        7, 3, SESSION, PROBE, BLOB,
        signature=signed.signature,
        identity_id=signed.identity_id,
        public_key_pem=signed.public_key_pem,
    )
    public = node3.public_material()
    assert "private_key_pem" not in public
    identity = NodeIdentity.load(material)
    for obj in (signed, verified, node3, identity):
        _assert_no_private_key(obj, private_pem)
    assert "private" not in repr(node3)
    assert "private" not in repr(identity)
