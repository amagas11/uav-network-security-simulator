"""预置身份：首次协商用 Ed25519 证明节点身份，不依赖 SKG 会话密钥。"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from .types import STATUS_BAD_ARGUMENT, STATUS_IDENTITY_FAIL, STATUS_OK

ALG_ED25519 = "Ed25519"
_MSG_PREFIX = b"UAV-HS-v1"


def _is_node_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pem_bytes(value: str | bytes) -> bytes:
    if isinstance(value, str):
        return value.encode("ascii")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError("PEM must be str or bytes")


def _pem_text(value: str | bytes) -> str:
    raw = _pem_bytes(value)
    return raw.decode("ascii")


def _encode_field(value: str | bytes) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return len(raw).to_bytes(4, "big") + raw


def canonical_handshake_message(
    signer_id: int,
    recipient_id: int,
    session_id: str,
    probe_id: str,
    identity_id: str,
    blob: bytes,
) -> bytes:
    return (
        _MSG_PREFIX
        + _encode_field(str(signer_id))
        + _encode_field(str(recipient_id))
        + _encode_field(session_id)
        + _encode_field(probe_id)
        + _encode_field(identity_id)
        + _encode_field(blob)
    )


def _load_private(pem: str | bytes) -> Ed25519PrivateKey:
    loaded = load_pem_private_key(_pem_bytes(pem), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("private_key_pem must be Ed25519")
    return loaded


def _load_public(pem: str | bytes) -> Ed25519PublicKey:
    loaded = load_pem_public_key(_pem_bytes(pem))
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("public_key_pem must be Ed25519")
    return loaded


def _public_pem_of(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


@dataclass(frozen=True, slots=True)
class HandshakeSignResult:
    status: str
    identity_id: str | None = None
    public_key_pem: str | None = None
    signature: bytes | None = None
    node_id: int | None = None
    alg: str = ALG_ED25519


@dataclass(frozen=True, slots=True)
class HandshakeVerifyResult:
    status: str
    identity_id: str | None = None
    node_id: int | None = None
    alg: str = ALG_ED25519


@dataclass(frozen=True, slots=True)
class TrustedPeer:
    node_id: int
    identity_id: str
    public_key_pem: str


class NodeIdentity:
    """本节点预置身份。私钥只留在此对象内部。"""

    def __init__(
        self,
        node_id: int,
        identity_id: str,
        private_key: Ed25519PrivateKey,
        public_key_pem: str,
    ) -> None:
        self.node_id = node_id
        self.identity_id = identity_id
        self._private_key = private_key
        self.public_key_pem = public_key_pem

    def __repr__(self) -> str:
        return f"NodeIdentity(node_id={self.node_id}, identity_id={self.identity_id!r})"

    @classmethod
    def generate(cls, node_id: int, identity_id: str | None = None) -> NodeIdentity:
        if not _is_node_id(node_id):
            raise TypeError("node_id must be an int")
        private_key = Ed25519PrivateKey.generate()
        handle = identity_id or f"uav-{node_id}"
        return cls(
            node_id=node_id,
            identity_id=handle,
            private_key=private_key,
            public_key_pem=_pem_text(_public_pem_of(private_key.public_key())),
        )

    @classmethod
    def load(cls, material: dict) -> NodeIdentity:
        node_id = material["node_id"]
        identity_id = material["identity_id"]
        if not _is_node_id(node_id) or not isinstance(identity_id, str) or identity_id == "":
            raise ValueError("invalid identity material")
        private_key = _load_private(material["private_key_pem"])
        public_pem = _pem_text(material["public_key_pem"])
        derived = _pem_text(_public_pem_of(private_key.public_key()))
        if derived != public_pem:
            raise ValueError("public_key_pem does not match private_key_pem")
        return cls(
            node_id=node_id,
            identity_id=identity_id,
            private_key=private_key,
            public_key_pem=public_pem,
        )

    def public_material(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "identity_id": self.identity_id,
            "public_key_pem": self.public_key_pem,
        }

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class IdentityStore:
    """一节点一份私钥，外加已信任对端公钥。不加解密、不读 KeyProvider。"""

    def __init__(self, local: NodeIdentity) -> None:
        self._local = local
        self._peers: dict[int, TrustedPeer] = {}
        self.trust_public(local.public_material())

    def __repr__(self) -> str:
        return (
            f"IdentityStore(node_id={self._local.node_id}, "
            f"identity_id={self._local.identity_id!r}, peers={len(self._peers)})"
        )

    @classmethod
    def generate(cls, node_id: int, identity_id: str | None = None) -> IdentityStore:
        return cls(NodeIdentity.generate(node_id, identity_id))

    @classmethod
    def load(cls, material: dict) -> IdentityStore:
        return cls(NodeIdentity.load(material))

    @property
    def node_id(self) -> int:
        return self._local.node_id

    @property
    def identity_id(self) -> str:
        return self._local.identity_id

    def public_material(self) -> dict[str, object]:
        return self._local.public_material()

    def trust_public(self, material: dict) -> None:
        node_id = material["node_id"]
        identity_id = material["identity_id"]
        public_key_pem = material["public_key_pem"]
        if not _is_node_id(node_id) or not isinstance(identity_id, str) or identity_id == "":
            raise ValueError("invalid peer identity material")
        _load_public(public_key_pem)
        self._peers[node_id] = TrustedPeer(
            node_id=node_id,
            identity_id=identity_id,
            public_key_pem=_pem_text(public_key_pem),
        )

    def sign_handshake(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        probe_id: str,
        blob: bytes,
    ) -> HandshakeSignResult:
        if local_id != self._local.node_id:
            return HandshakeSignResult(status=STATUS_IDENTITY_FAIL, node_id=local_id)
        arg_status = _handshake_args_status(local_id, peer_id, session_id, probe_id, blob)
        if arg_status is not None:
            return HandshakeSignResult(status=arg_status, identity_id=self._local.identity_id, node_id=local_id)

        message = canonical_handshake_message(
            local_id, peer_id, session_id, probe_id, self._local.identity_id, bytes(blob)
        )
        signature = self._local.sign(message)
        return HandshakeSignResult(
            status=STATUS_OK,
            identity_id=self._local.identity_id,
            public_key_pem=self._local.public_key_pem,
            signature=signature,
            node_id=local_id,
        )

    def verify_handshake(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        probe_id: str,
        blob: bytes,
        *,
        signature: bytes | None,
        identity_id: str | None = None,
        public_key_pem: str | bytes | None = None,
    ) -> HandshakeVerifyResult:
        if local_id != self._local.node_id:
            return HandshakeVerifyResult(status=STATUS_IDENTITY_FAIL, node_id=peer_id)
        arg_status = _handshake_args_status(local_id, peer_id, session_id, probe_id, blob)
        if arg_status is not None:
            return HandshakeVerifyResult(status=arg_status, identity_id=identity_id, node_id=peer_id)
        if not isinstance(signature, (bytes, bytearray)) or len(signature) == 0:
            return HandshakeVerifyResult(
                status=STATUS_IDENTITY_FAIL, identity_id=identity_id, node_id=peer_id
            )

        trusted = self._peers.get(peer_id)
        if trusted is None:
            return HandshakeVerifyResult(status=STATUS_IDENTITY_FAIL, identity_id=identity_id, node_id=peer_id)
        if identity_id is not None and identity_id != trusted.identity_id:
            return HandshakeVerifyResult(
                status=STATUS_IDENTITY_FAIL, identity_id=identity_id, node_id=peer_id
            )
        if public_key_pem is not None and _pem_text(public_key_pem) != trusted.public_key_pem:
            return HandshakeVerifyResult(
                status=STATUS_IDENTITY_FAIL, identity_id=trusted.identity_id, node_id=peer_id
            )

        message = canonical_handshake_message(
            peer_id, local_id, session_id, probe_id, trusted.identity_id, bytes(blob)
        )
        try:
            _load_public(trusted.public_key_pem).verify(bytes(signature), message)
        except (InvalidSignature, ValueError):
            return HandshakeVerifyResult(
                status=STATUS_IDENTITY_FAIL, identity_id=trusted.identity_id, node_id=peer_id
            )
        return HandshakeVerifyResult(
            status=STATUS_OK, identity_id=trusted.identity_id, node_id=peer_id
        )


def _handshake_args_status(
    local_id: object,
    peer_id: object,
    session_id: object,
    probe_id: object,
    blob: object,
) -> str | None:
    if not _is_node_id(local_id) or not _is_node_id(peer_id):
        return STATUS_BAD_ARGUMENT
    if local_id == peer_id:
        return STATUS_BAD_ARGUMENT
    if not isinstance(session_id, str) or session_id == "":
        return STATUS_BAD_ARGUMENT
    if not isinstance(probe_id, str) or probe_id == "":
        return STATUS_BAD_ARGUMENT
    if not isinstance(blob, (bytes, bytearray)):
        return STATUS_BAD_ARGUMENT
    return None
