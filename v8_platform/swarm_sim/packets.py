"""Canonical application-packet serialization and shared business templates.

The public ``packet_size_bytes`` feature is the UTF-8 byte length of the
canonical JSON application payload.  It deliberately excludes link/PHY
overhead, encryption expansion and Python object-representation details.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_application_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def serialized_application_size(payload: dict[str, Any]) -> int:
    return len(canonical_application_bytes(payload))


class BusinessPacketTemplate:
    """Build one ordinary STATUS-like payload for burst and flooding traffic.

    Attack and hard-negative generators intentionally call the same method.
    No scenario name, attack marker, burst marker or mechanism-specific key is
    placed in the online payload.
    """

    @staticmethod
    def build(
        *,
        sequence_value: int,
        target_size_bytes: int,
        status_code: str = "OK",
    ) -> dict[str, Any]:
        target = int(target_size_bytes)
        payload: dict[str, Any] = {
            "padding": "",
            "status_code": str(status_code),
            "value": int(sequence_value),
        }
        minimum = serialized_application_size(payload)
        if target < minimum:
            raise ValueError(
                f"TARGET_PACKET_SIZE_TOO_SMALL:{target}<minimum:{minimum}"
            )
        payload["padding"] = "x" * (target - minimum)
        actual = serialized_application_size(payload)
        if actual != target:  # ASCII padding makes this an invariant.
            raise AssertionError(
                f"canonical packet builder produced {actual} B, expected {target} B"
            )
        return payload
