"""Explicit A/C integration interfaces and clearly marked test/null adapters."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import base64
import hashlib
import hmac
import json
from typing import Any, Protocol, runtime_checkable

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - exercised only in dependency failure environments
    AESGCM = None

from .domain import Frame, Message
from .simulation import RunContext, SCHEMA_VERSION


@dataclass(slots=True)
class KeyReference:
    key_handle: str | None
    key_epoch: int | str
    state: str
    error_code: str | None = None


@dataclass(slots=True)
class RekeyResult:
    success: bool
    previous_key_epoch: int | str
    new_key_epoch: int | str | None
    state_transitions: list[str]
    failure_reason: str | None
    implementation_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KeyProvider(Protocol):
    """Production key-control boundary.

    Raw key bytes are deliberately absent.  A production provider exposes
    opaque references, lifecycle control and non-secret provenance only.
    Cryptographic operations belong to ``CryptoProvider``.
    """

    implementation_status: str

    def reset(self, run_info: dict[str, Any]) -> None: ...

    def key_reference(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> KeyReference: ...

    def request_rekey(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        current_key_epoch: int | str,
    ) -> RekeyResult: ...


@runtime_checkable
class TestKeyMaterialProvider(Protocol):
    """Private compatibility protocol used only by B's test AEAD adapter."""

    __test__ = False

    def _key_material(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> bytes | None: ...


class NullKeyProvider:
    implementation_status = "INTERFACE_READY"

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info

    def key_reference(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> KeyReference:
        del local_id, peer_id, session_id
        return KeyReference(None, key_epoch, "MISSING", "A_KEY_PROVIDER_NOT_CONFIGURED")

    def _key_material(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> bytes | None:
        del local_id, peer_id, session_id, key_epoch
        return None

    def request_rekey(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        current_key_epoch: int | str,
    ) -> RekeyResult:
        del local_id, peer_id, session_id
        return RekeyResult(
            success=False,
            previous_key_epoch=current_key_epoch,
            new_key_epoch=None,
            state_transitions=["MISSING", "UPDATING", "MISSING"],
            failure_reason="A_KEY_PROVIDER_NOT_CONFIGURED",
            implementation_status=self.implementation_status,
        )


class MockKeyProvider:
    """TEST ONLY deterministic keys.  This is NOT an SKG implementation."""

    implementation_status = "TEST_ONLY_NOT_SKG"

    def __init__(self, seed: int) -> None:
        self._root = hashlib.sha256(f"mock-key-root:{seed}".encode("utf-8")).digest()
        self._next_rekey_failure: str | None = None

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info

    @staticmethod
    def _context(
        local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> bytes:
        first, second = sorted((int(local_id), int(peer_id)))
        return f"{first}:{second}:{session_id}:{key_epoch}".encode("utf-8")

    def _key_material(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> bytes:
        return hmac.new(
            self._root,
            self._context(local_id, peer_id, session_id, key_epoch),
            hashlib.sha256,
        ).digest()

    def key_reference(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> KeyReference:
        digest = hashlib.sha256(
            self._context(local_id, peer_id, session_id, key_epoch)
        ).hexdigest()[:16]
        return KeyReference(f"mock-key-{digest}", key_epoch, "AVAILABLE")

    def fail_next_rekey(self, reason: str = "MOCK_REKEY_FAILURE") -> None:
        self._next_rekey_failure = str(reason)

    def request_rekey(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        current_key_epoch: int | str,
    ) -> RekeyResult:
        # Resolve the current reference as an adapter-level availability check;
        # only opaque handles and state transitions leave this provider.
        current = self.key_reference(
            local_id, peer_id, session_id, current_key_epoch
        )
        if self._next_rekey_failure is not None:
            reason = self._next_rekey_failure
            self._next_rekey_failure = None
            return RekeyResult(
                success=False,
                previous_key_epoch=current_key_epoch,
                new_key_epoch=None,
                state_transitions=[current.state, "UPDATING", "FAILED"],
                failure_reason=reason,
                implementation_status=self.implementation_status,
            )
        new_epoch: int | str
        if isinstance(current_key_epoch, int):
            new_epoch = current_key_epoch + 1
        else:
            new_epoch = f"{current_key_epoch}-next"
        return RekeyResult(
            success=True,
            previous_key_epoch=current_key_epoch,
            new_key_epoch=new_epoch,
            state_transitions=[current.state, "UPDATING", "AVAILABLE"],
            failure_reason=None,
            implementation_status=self.implementation_status,
        )


@dataclass(slots=True)
class CryptoOpenResult:
    status: str
    auth_result: str
    payload: dict[str, Any] | None
    key_state: str
    key_epoch: int | str
    error_code: str | None = None
    key_id: str | None = None
    algorithm: str | None = None


class CryptoProvider(Protocol):
    implementation_status: str

    def protect(
        self,
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> Frame: ...

    def open(self, frame: Frame, receiver_id: int) -> CryptoOpenResult: ...


class CryptoProtectionError(RuntimeError):
    """Recoverable send-side crypto failure; never authorizes plaintext fallback."""

    def __init__(
        self,
        error_code: str,
        *,
        key_state: str = "MISSING",
        key_epoch: int | str | None = None,
        status: str = "UNAVAILABLE",
    ) -> None:
        super().__init__(error_code)
        self.error_code = str(error_code)
        self.key_state = str(key_state)
        self.key_epoch = key_epoch
        self.status = str(status)


class TestOnlyAeadCryptoProvider:
    """Mature AES-GCM integration with mock/test keys, never represented as SKG."""

    implementation_status = "TEST_ONLY_AEAD_NOT_SKG"
    __test__ = False

    def __init__(self, key_provider: TestKeyMaterialProvider) -> None:
        self.key_provider = key_provider

    @staticmethod
    def _payload_bytes(payload: dict[str, Any]) -> bytes:
        return json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @staticmethod
    def _aad(
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> bytes:
        value = {
            "message_id": message.message_id,
            "claimed_src_id": message.claimed_src_id,
            "claimed_dst_id": message.claimed_dst_id,
            "packet_type": message.packet_type,
            "sequence_no": message.sequence_no,
            "session_id": message.session_id,
            "key_epoch": message.key_epoch,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "link_id": link_id,
            "hop_index": hop_index,
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def protect(
        self,
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> Frame:
        key_ref = self.key_provider.key_reference(
            sender_id, receiver_id, message.session_id, message.key_epoch
        )
        key = self.key_provider._key_material(
            sender_id, receiver_id, message.session_id, message.key_epoch
        )
        payload_bytes = self._payload_bytes(message.payload)
        aad = self._aad(message, sender_id, receiver_id, link_id, hop_index)
        auth_tag: str | None = None
        nonce_b64: str | None = None
        protected_payload: dict[str, Any]

        if key is None and message.encrypt_requested:
            raise CryptoProtectionError(
                "KEY_UNAVAILABLE_FOR_ENCRYPTION",
                key_state=key_ref.state,
                key_epoch=message.key_epoch,
            )
        if key is None:
            protected_payload = deepcopy(message.payload)
        elif message.encrypt_requested:
            if AESGCM is None:
                raise RuntimeError("cryptography is required for AES-GCM")
            nonce = hmac.new(
                key,
                f"nonce:{message.message_id}:{hop_index}:{message.sequence_no}".encode("utf-8"),
                hashlib.sha256,
            ).digest()[:12]
            ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, aad)
            protected_payload = {
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
                "algorithm": "AES-256-GCM",
                "key_handle": key_ref.key_handle,
            }
            nonce_b64 = base64.b64encode(nonce).decode("ascii")
        else:
            protected_payload = deepcopy(message.payload)
            auth_tag = hmac.new(key, aad + payload_bytes, hashlib.sha256).hexdigest()

        return Frame(
            message_id=message.message_id,
            claimed_src_id=message.claimed_src_id,
            claimed_dst_id=message.claimed_dst_id,
            packet_type=message.packet_type,
            sequence_no=message.sequence_no,
            session_id=message.session_id,
            key_epoch=message.key_epoch,
            hop_index=hop_index,
            link_id=link_id,
            link_sender_id=sender_id,
            link_receiver_id=receiver_id,
            protected_payload=protected_payload,
            encrypted=message.encrypt_requested,
            auth_tag=auth_tag,
            nonce_b64=nonce_b64,
            sensitive=message.sensitive,
            created_time_s=message.created_time_s,
            route=list(message.route),
            application_size_bytes=message.application_size_bytes,
            extensions=deepcopy(message.extensions),
            runtime_attack_id=message.runtime_attack_id,
            observable_session_id=message.observable_session_id,
            application_direction=message.application_direction,
            app_hmac_tag=message.app_hmac_tag,
            app_hmac_key_id=message.app_hmac_key_id,
        )

    def open(self, frame: Frame, receiver_id: int) -> CryptoOpenResult:
        if receiver_id != frame.link_receiver_id:
            return CryptoOpenResult(
                "ERROR", "FAIL", None, "UNAVAILABLE", frame.key_epoch, "WRONG_RECEIVER"
            )
        key_ref = self.key_provider.key_reference(
            frame.link_sender_id, receiver_id, frame.session_id, frame.key_epoch
        )
        key = self.key_provider._key_material(
            frame.link_sender_id, receiver_id, frame.session_id, frame.key_epoch
        )
        if key is None:
            return CryptoOpenResult(
                "UNAVAILABLE",
                "UNAVAILABLE",
                None,
                key_ref.state,
                frame.key_epoch,
                key_ref.error_code,
            )
        message_stub = Message(
            message_id=frame.message_id,
            origin_node_id=frame.claimed_src_id if frame.claimed_src_id is not None else -1,
            final_dst_node_id=frame.claimed_dst_id if frame.claimed_dst_id is not None else receiver_id,
            claimed_src_id=frame.claimed_src_id,
            claimed_dst_id=frame.claimed_dst_id,
            packet_type=frame.packet_type,
            payload={},
            sequence_no=frame.sequence_no,
            session_id=frame.session_id,
            key_epoch=frame.key_epoch,
            created_time_s=frame.created_time_s,
            route=list(frame.route),
        )
        aad = self._aad(
            message_stub,
            frame.link_sender_id,
            receiver_id,
            frame.link_id,
            frame.hop_index,
        )
        try:
            if frame.encrypted:
                if AESGCM is None:
                    raise RuntimeError("cryptography unavailable")
                nonce = base64.b64decode(frame.nonce_b64 or "")
                ciphertext = base64.b64decode(
                    frame.protected_payload.get("ciphertext_b64", "")
                )
                plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
                payload = json.loads(plaintext.decode("utf-8"))
            else:
                payload = deepcopy(frame.protected_payload)
                expected = hmac.new(
                    key, aad + self._payload_bytes(payload), hashlib.sha256
                ).hexdigest()
                if not frame.auth_tag or not hmac.compare_digest(expected, frame.auth_tag):
                    raise ValueError("authentication tag mismatch")
        except Exception:
            return CryptoOpenResult(
                "ERROR", "FAIL", None, key_ref.state, frame.key_epoch, "AUTHENTICATION_FAILED"
            )
        return CryptoOpenResult(
            "OK", "PASS", payload, key_ref.state, frame.key_epoch, None
        )


@dataclass(slots=True)
class ModelResult:
    schema_version: str
    run_id: str
    result_id: str
    observer_node_id: int
    decision_time_s: float
    model_name: str
    model_version: str | None
    status: str
    predicted_label: str | None
    scores: dict[str, float] | None
    confidence: float | None
    quality: float | None
    recommended_action: str | None
    evidence_event_ids: list[str]
    inference_time_ms: float | None
    error_code: str | None
    error_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelAdapter(Protocol):
    accepted_event_types: frozenset[str]

    def reset(self, run_info: dict[str, Any]) -> None: ...

    def observe(self, event: dict[str, Any]) -> list[ModelResult]: ...

    def health(self) -> dict[str, Any]: ...


class NullModelAdapter:
    """Interface-ready adapter; unavailable is never converted to NORMAL."""

    def __init__(
        self,
        name: str,
        context: RunContext,
        accepted_event_types: frozenset[str],
    ) -> None:
        self.name = name
        self.context = context
        self.accepted_event_types = accepted_event_types

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        del event
        # Availability is exposed through health(); an absent model must not
        # manufacture one high-frequency MODEL_RESULT for every radio sample.
        return []

    def health(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "status": "UNAVAILABLE",
            "model_version": None,
            "error_code": "MODEL_NOT_CONFIGURED",
            "implementation_status": "INTERFACE_READY",
        }


def default_model_adapters(context: RunContext) -> dict[str, NullModelAdapter]:
    return {
        "bilstm": NullModelAdapter(
            "bilstm-threat-classifier",
            context,
            frozenset(
                {
                    "TX",
                    "RX_SUCCESS",
                    "RX_FAILURE",
                    "PHY_SAMPLE",
                    "QUEUE_SAMPLE",
                    "NODE_STATE",
                    "TOPOLOGY_UPDATE",
                    "AUTH_RESULT",
                }
            ),
        ),
        "dueling_q": NullModelAdapter(
            "dueling-q-policy",
            context,
            frozenset(
                {
                    "PHY_SAMPLE",
                    "QUEUE_SAMPLE",
                    "NODE_STATE",
                    "TOPOLOGY_UPDATE",
                    "AUTH_RESULT",
                    "MODEL_RESULT",
                    "DEFENSE_RESULT",
                }
            ),
        ),
        "rff": NullModelAdapter(
            "rff-identity",
            context,
            frozenset({"RX_SUCCESS", "RX_FAILURE", "PHY_SAMPLE"}),
        ),
    }
