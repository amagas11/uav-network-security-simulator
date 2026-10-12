"""End-to-end application authentication independent from link crypto.

The simulator keeps one private HMAC key per legitimate device.  Keys never
leave this service; frames carry only a public key identifier and a truncated
authentication tag.  Person-A session keys, AES-GCM tags, and SKG control
authentication remain separate mechanisms.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Any, Iterable

from .domain import Frame, Message


APPLICATION_HMAC_ALGORITHM = "HMAC-SHA-256-128"
APPLICATION_HMAC_TAG_BYTES = 16
APPLICATION_HMAC_EXCLUDED_PACKET_TYPES = frozenset({"SKG_CONTROL"})


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Return the one canonical UTF-8 representation used by both peers."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_mac_data(
    item: Message | Frame,
    payload: dict[str, Any],
) -> bytes:
    """Serialize the frozen application-MAC fields exactly once.

    Hop sender/receiver/link information is intentionally absent.  A Leader
    may therefore relay a valid end-to-end application message without
    changing its UPLINK/DOWNLINK direction or tag.
    """

    payload_bytes = canonical_payload_bytes(payload)
    value = {
        "direction": item.application_direction,
        "device_id": item.claimed_src_id,
        "message_type": item.packet_type,
        "sequence_no": item.sequence_no,
        "timestamp_ms": int(round(float(item.created_time_s) * 1000.0)),
        "payload_length": len(payload_bytes),
        "business_payload": payload,
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ApplicationHmacVerification:
    result: str
    failure_reason: str | None
    key_id: str | None

    @property
    def passed(self) -> bool:
        return self.result in {"PASS", "NOT_APPLICABLE"}


class ApplicationHmacService:
    """Run-local, deterministic per-device HMAC key store and verifier."""

    implementation_status = "SIMULATED_PER_DEVICE_APPLICATION_HMAC"
    algorithm = APPLICATION_HMAC_ALGORITHM

    def __init__(self, seed: int, legitimate_device_ids: Iterable[int]) -> None:
        master = hashlib.sha256(
            f"application-hmac-master:{int(seed)}".encode("utf-8")
        ).digest()
        self._keys = {
            int(device_id): hmac.new(
                master,
                f"device:{int(device_id)}".encode("utf-8"),
                hashlib.sha256,
            ).digest()
            for device_id in legitimate_device_ids
        }
        # This separate simulator-private value lets an unregistered sender
        # make a deterministic *guess*.  It is never a trusted device key and
        # cannot validate as any legitimate claimed identity.
        self._untrusted_master = hashlib.sha256(
            f"application-hmac-untrusted:{int(seed)}".encode("utf-8")
        ).digest()

    @staticmethod
    def key_id(device_id: int) -> str:
        return f"app-hmac-device-{int(device_id)}"

    @staticmethod
    def applies_to(packet_type: str) -> bool:
        """Return whether the business-layer HMAC covers this packet type.

        Person-A RECONCILE/CONFIRM messages already use their frozen Ed25519
        handshake authentication. Mixing that control signature with the
        application HMAC would conflate two independent trust domains.
        """

        return str(packet_type) not in APPLICATION_HMAC_EXCLUDED_PACKET_TYPES

    @staticmethod
    def _tag(key: bytes, data: bytes) -> str:
        return hmac.new(key, data, hashlib.sha256).digest()[
            :APPLICATION_HMAC_TAG_BYTES
        ].hex()

    def sign(self, message: Message) -> None:
        """Sign a legitimate message, or create an untrusted sender's guess."""

        if not self.applies_to(message.packet_type):
            message.app_hmac_tag = None
            message.app_hmac_key_id = None
            return

        key = self._keys.get(int(message.origin_node_id))
        if key is not None:
            message.app_hmac_key_id = self.key_id(message.origin_node_id)
        else:
            key = hmac.new(
                self._untrusted_master,
                f"untrusted-device:{int(message.origin_node_id)}".encode("utf-8"),
                hashlib.sha256,
            ).digest()
            message.app_hmac_key_id = None
        message.app_hmac_tag = self._tag(
            key, canonical_mac_data(message, message.payload)
        )

    def verify(
        self,
        frame: Frame,
        payload: dict[str, Any] | None,
    ) -> ApplicationHmacVerification:
        if not self.applies_to(frame.packet_type):
            return ApplicationHmacVerification("NOT_APPLICABLE", None, None)
        claimed = frame.claimed_src_id
        if claimed is None or int(claimed) not in self._keys:
            return ApplicationHmacVerification(
                "UNKNOWN_DEVICE", "UNKNOWN_DEVICE_KEY", None
            )
        key_id = self.key_id(int(claimed))
        if not frame.app_hmac_tag:
            return ApplicationHmacVerification("MISSING", "HMAC_MISSING", key_id)
        if payload is None:
            return ApplicationHmacVerification("FAIL", "PAYLOAD_UNAVAILABLE", key_id)
        expected = self._tag(
            self._keys[int(claimed)], canonical_mac_data(frame, payload)
        )
        if not hmac.compare_digest(expected, str(frame.app_hmac_tag)):
            return ApplicationHmacVerification("FAIL", "HMAC_MISMATCH", key_id)
        return ApplicationHmacVerification("PASS", None, key_id)

    def provenance(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "algorithm": self.algorithm,
            "tag_length_bytes": APPLICATION_HMAC_TAG_BYTES,
            "key_scope": "PER_LEGITIMATE_DEVICE",
            "covered_fields": [
                "direction",
                "device_id",
                "message_type",
                "sequence_no",
                "timestamp_ms",
                "payload_length",
                "business_payload",
            ],
            "implementation_status": self.implementation_status,
            "excluded_control_packet_types": sorted(
                APPLICATION_HMAC_EXCLUDED_PACKET_TYPES
            ),
        }
