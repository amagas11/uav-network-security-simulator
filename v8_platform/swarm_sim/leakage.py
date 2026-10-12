"""Rule/statistics based audit for obvious training-label shortcuts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any

from .events import find_forbidden_online_fields, find_label_proxies


@dataclass(slots=True)
class LeakageAuditReport:
    passed: bool
    errors: list[str] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DatasetLeakageAudit:
    """Detect literals and simple one-field/one-schema perfect shortcuts.

    This is deliberately a transparent audit, not a fabricated ML metric.  It
    catches the high-risk deterministic proxies named by the contract while
    leaving genuine multivariate/statistical scenario differences intact.
    """

    IDENTIFIER_KEYS = {
        "session_id": "sess",
        "link_id": "lnk",
        "sample_link_id": "lnk",
        "probe_id": "prb",
        "flow_id": "flow",
    }
    IDENTIFIER_FORBIDDEN_TOKENS = re.compile(
        r"(?:normal|reorder|replay|spoof|eaves|fdi|dos|jam|flood|attack|profile)",
        re.IGNORECASE,
    )

    @classmethod
    def _identifier_prefix(cls, key: str | None) -> str | None:
        if key in cls.IDENTIFIER_KEYS:
            return cls.IDENTIFIER_KEYS[key]
        if key and key.endswith("session_id"):
            return "sess"
        if key and key.endswith("link_id"):
            return "lnk"
        if key and key.endswith("probe_id"):
            return "prb"
        if key and key.endswith("flow_id"):
            return "flow"
        return None

    @classmethod
    def collect_online_identifiers(
        cls, events: list[dict[str, Any]]
    ) -> list[str]:
        values: list[str] = []

        def visit(value: Any, key: str | None = None) -> None:
            if isinstance(value, dict):
                for child_key, child in value.items():
                    visit(child, str(child_key))
            elif isinstance(value, list):
                singular = (
                    key[:-1]
                    if key and key.endswith("s")
                    else key
                )
                for child in value:
                    visit(child, singular)
            elif isinstance(value, str) and cls._identifier_prefix(key):
                values.append(value)

        for event in events:
            visit(event.get("online_features", {}))
            visit(event.get("availability", {}))
            visit(event.get("extensions", {}))
        return values

    @classmethod
    def _identifier_errors(cls, events: list[dict[str, Any]]) -> list[str]:
        errors: list[str] = []

        def visit(value: Any, path: str, key: str | None = None) -> None:
            if isinstance(value, dict):
                for child_key, child in value.items():
                    visit(
                        child,
                        f"{path}.{child_key}" if path else str(child_key),
                        str(child_key),
                    )
            elif isinstance(value, list):
                singular = key[:-1] if key and key.endswith("s") else key
                for index, child in enumerate(value):
                    visit(child, f"{path}[{index}]", singular)
            elif isinstance(value, str) and cls._identifier_prefix(key):
                expected = cls._identifier_prefix(key) or "id"
                if cls.IDENTIFIER_FORBIDDEN_TOKENS.search(value):
                    errors.append(f"{path}: scenario-bearing identifier {value!r}")
                if re.search(r"(?:^|[-_:])-?\d+[-_:]-?\d+(?:$|[-_:])", value):
                    errors.append(f"{path}: endpoint-encoded identifier {value!r}")
                if not re.fullmatch(
                    rf"{re.escape(expected)}-[0-9a-f]{{12}}-\d{{8}}", value
                ):
                    errors.append(f"{path}: identifier is not opaque {value!r}")

        for index, event in enumerate(events):
            visit(event.get("online_features", {}), f"event[{index}].online_features")
            visit(event.get("availability", {}), f"event[{index}].availability")
            visit(event.get("extensions", {}), f"event[{index}].extensions")
        return errors

    @staticmethod
    def audit_events(events: list[dict[str, Any]]) -> LeakageAuditReport:
        errors: list[str] = DatasetLeakageAudit._identifier_errors(events)
        for index, event in enumerate(events):
            forbidden = find_forbidden_online_fields(
                event.get("online_features", {})
            )
            if forbidden:
                errors.append(f"event[{index}] forbidden truth fields: {forbidden}")
            proxies = find_label_proxies(event)
            if proxies:
                errors.append(f"event[{index}] literal label proxies: {proxies}")
            extensions = event.get("extensions", {})
            if isinstance(extensions, dict):
                raw_extensions = {
                    key: value
                    for key, value in extensions.items()
                    if key
                    not in {
                        "model_result",
                        "defense_result",
                        "decision_audit",
                        "redundancy_event",
                        "security_report",
                        "aggregated_report",
                    }
                }
                extension_truth = find_forbidden_online_fields(
                    raw_extensions, "extensions"
                )
                if extension_truth:
                    errors.append(
                        f"event[{index}] forbidden extension truth: {extension_truth}"
                    )
        return LeakageAuditReport(
            passed=not errors,
            errors=errors,
            statistics={"event_count": len(events)},
        )

    @staticmethod
    def _supports(events: list[dict[str, Any]]) -> dict[str, Any]:
        packet_types: set[str] = set()
        payload_schemas: set[tuple[str, ...]] = set()
        sizes: list[int] = []
        for event in events:
            if event.get("event_type") not in {
                "TX",
                "RX_SUCCESS",
                "RX_FAILURE",
                "AUTH_RESULT",
            }:
                continue
            packet = event.get("online_features", {}).get("packet", {})
            packet_type = packet.get("packet_type")
            # Hard-negative support comparison is about business traffic.
            # Security reporting and SKG control are protocol-control planes;
            # their presence is a consequence of a detection/handshake and
            # must not distort business payload/size support ranges.
            if packet_type in {
                "SECURITY_REPORT",
                "SECURITY_SUMMARY",
                "SKG_CONTROL",
            }:
                continue
            if isinstance(packet_type, str):
                packet_types.add(packet_type)
            numeric = packet.get("payload_numeric")
            if isinstance(numeric, dict):
                payload_schemas.add(tuple(sorted(str(key) for key in numeric)))
            size = packet.get("packet_size_bytes")
            if isinstance(size, int) and not isinstance(size, bool):
                sizes.append(size)
        return {
            "packet_types": packet_types,
            "payload_schemas": payload_schemas,
            "sizes": sizes,
        }

    @classmethod
    def compare_hard_negative_pair(
        cls,
        normal_events: list[dict[str, Any]],
        attack_events: list[dict[str, Any]],
        *,
        pair_name: str,
        require_payload_overlap: bool = True,
        require_size_overlap: bool = True,
    ) -> LeakageAuditReport:
        errors = [
            *cls.audit_events(normal_events).errors,
            *cls.audit_events(attack_events).errors,
        ]
        normal = cls._supports(normal_events)
        attack = cls._supports(attack_events)
        type_overlap = normal["packet_types"] & attack["packet_types"]
        schema_overlap = normal["payload_schemas"] & attack["payload_schemas"]
        normal_sizes = normal["sizes"]
        attack_sizes = attack["sizes"]
        size_overlap = bool(
            normal_sizes
            and attack_sizes
            and max(min(normal_sizes), min(attack_sizes))
            <= min(max(normal_sizes), max(attack_sizes))
        )
        if normal["packet_types"] and attack["packet_types"] and not type_overlap:
            errors.append(f"{pair_name}: packet_type support is perfectly separated")
        if (
            require_payload_overlap
            and normal["payload_schemas"]
            and attack["payload_schemas"]
            and not schema_overlap
        ):
            errors.append(f"{pair_name}: payload numeric-key schema is perfectly separated")
        if require_size_overlap and normal_sizes and attack_sizes and not size_overlap:
            errors.append(f"{pair_name}: packet-size ranges are perfectly separated")
        return LeakageAuditReport(
            passed=not errors,
            errors=errors,
            statistics={
                "pair": pair_name,
                "packet_type_overlap": sorted(type_overlap),
                "payload_schema_overlap": [list(item) for item in sorted(schema_overlap)],
                "normal_size_range": (
                    [min(normal_sizes), max(normal_sizes)] if normal_sizes else None
                ),
                "attack_size_range": (
                    [min(attack_sizes), max(attack_sizes)] if attack_sizes else None
                ),
                "packet_size_overlap": size_overlap,
            },
        )
