"""Strict config-driven business traffic and legitimate session lifecycle."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any

from .simulation import RunContext
from .telemetry_measurement import validate_measurement_model


@dataclass(slots=True)
class BusinessTrafficSpec:
    """A deterministic legitimate business flow used by every formal entrypoint."""

    source_node_id: int
    target_node_id: int
    packet_type: str
    start_s: float
    payload: dict[str, Any]
    interval_s: float = 0.2
    count: int = 1
    sensitive: bool = False
    encrypt: bool | None = None
    session_id: str | None = None
    sequence_start: int | None = None
    traffic_id: str | None = None
    measurement_model: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        def is_number(value: Any) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        if not isinstance(self.source_node_id, int) or isinstance(
            self.source_node_id, bool
        ):
            raise ValueError("TRAFFIC_SOURCE_NODE_ID_MUST_BE_INTEGER")
        if not isinstance(self.target_node_id, int) or isinstance(
            self.target_node_id, bool
        ):
            raise ValueError("TRAFFIC_TARGET_NODE_ID_MUST_BE_INTEGER")
        if not isinstance(self.packet_type, str) or not self.packet_type:
            raise ValueError("TRAFFIC_PACKET_TYPE_MUST_BE_NON_EMPTY_STRING")
        if not is_number(self.start_s) or not is_number(self.interval_s):
            raise ValueError("TRAFFIC_TIMES_MUST_BE_NUMERIC")
        if not isinstance(self.count, int) or isinstance(self.count, bool):
            raise ValueError("TRAFFIC_COUNT_MUST_BE_INTEGER")
        if not isinstance(self.sensitive, bool):
            raise ValueError("TRAFFIC_SENSITIVE_MUST_BE_BOOLEAN")
        if self.session_id is not None and (
            not isinstance(self.session_id, str) or not self.session_id
        ):
            raise ValueError("TRAFFIC_SESSION_ID_MUST_BE_NON_EMPTY_STRING_OR_NULL")
        if self.sequence_start is not None and (
            not isinstance(self.sequence_start, int)
            or isinstance(self.sequence_start, bool)
        ):
            raise ValueError("TRAFFIC_SEQUENCE_START_MUST_BE_INTEGER_OR_NULL")
        if self.traffic_id is not None and (
            not isinstance(self.traffic_id, str) or not self.traffic_id
        ):
            raise ValueError("TRAFFIC_ID_MUST_BE_NON_EMPTY_STRING_OR_NULL")
        self.packet_type = self.packet_type.upper()
        if self.start_s < 0:
            raise ValueError("TRAFFIC_START_MUST_BE_NON_NEGATIVE")
        if self.interval_s <= 0:
            raise ValueError("TRAFFIC_INTERVAL_MUST_BE_POSITIVE")
        if self.count < 1:
            raise ValueError("TRAFFIC_COUNT_MUST_BE_POSITIVE")
        if not isinstance(self.payload, dict):
            raise ValueError("TRAFFIC_PAYLOAD_MUST_BE_OBJECT")
        if self.encrypt is not None and not isinstance(self.encrypt, bool):
            raise ValueError("TRAFFIC_ENCRYPT_MUST_BE_BOOLEAN_OR_NULL")
        validate_measurement_model(self.measurement_model, self.packet_type)


@dataclass(slots=True)
class SessionLifecycleSpec:
    """A receiver-known legitimate ACTIVE -> STALE -> ACTIVE transition."""

    sender_node_id: int
    receiver_node_id: int
    rotate_at_s: float
    old_session_id: str
    new_session_id: str
    key_epoch: int | str | None = None
    sequence_namespace: int | None = None
    lifecycle_id: str | None = None

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in (self.sender_node_id, self.receiver_node_id)
        ):
            raise ValueError("SESSION_LIFECYCLE_NODE_IDS_MUST_BE_INTEGERS")
        if not isinstance(self.rotate_at_s, (int, float)) or isinstance(
            self.rotate_at_s, bool
        ):
            raise ValueError("SESSION_ROTATION_TIME_MUST_BE_NUMERIC")
        if not isinstance(self.old_session_id, str) or not isinstance(
            self.new_session_id, str
        ):
            raise ValueError("SESSION_LIFECYCLE_SESSION_IDS_MUST_BE_STRINGS")
        if self.rotate_at_s < 0:
            raise ValueError("SESSION_ROTATION_TIME_MUST_BE_NON_NEGATIVE")
        if not self.old_session_id or not self.new_session_id:
            raise ValueError("SESSION_LIFECYCLE_REQUIRES_OLD_AND_NEW_SESSION")
        if self.old_session_id == self.new_session_id:
            raise ValueError("SESSION_ROTATION_REQUIRES_DISTINCT_SESSIONS")
        if self.key_epoch is not None and (
            not isinstance(self.key_epoch, (int, str))
            or isinstance(self.key_epoch, bool)
            or self.key_epoch == ""
        ):
            raise ValueError("SESSION_KEY_EPOCH_MUST_BE_INTEGER_STRING_OR_NULL")
        if self.sequence_namespace is not None and (
            not isinstance(self.sequence_namespace, int)
            or isinstance(self.sequence_namespace, bool)
        ):
            raise ValueError("SESSION_SEQUENCE_NAMESPACE_MUST_BE_INTEGER_OR_NULL")
        if self.lifecycle_id is not None and (
            not isinstance(self.lifecycle_id, str) or not self.lifecycle_id
        ):
            raise ValueError("SESSION_LIFECYCLE_ID_MUST_BE_NON_EMPTY_STRING_OR_NULL")


class ScenarioOrchestrator:
    """Schedule one frozen ScenarioConfig identically for runtime/batch/API/RL."""

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.traffic_specs: list[BusinessTrafficSpec] = []
        self.session_lifecycle_specs: list[SessionLifecycleSpec] = []
        self.executed_traffic: list[dict[str, Any]] = []
        self.executed_session_lifecycle: list[dict[str, Any]] = []

    def load(
        self,
        traffic_specs: list[dict[str, Any]],
        session_lifecycle_specs: list[dict[str, Any]],
    ) -> None:
        for index, raw in enumerate(traffic_specs):
            try:
                spec = BusinessTrafficSpec(**deepcopy(raw))
            except TypeError as exc:
                raise ValueError(f"UNKNOWN_TRAFFIC_SPEC_FIELD:{exc}") from exc
            if spec.traffic_id is None:
                spec.traffic_id = self.context.ids.next("traffic")
            last_time = spec.start_s + (spec.count - 1) * spec.interval_s
            if last_time > self.context.config.duration_s + 1e-12:
                raise ValueError("TRAFFIC_SPEC_OUTSIDE_RUN_DURATION")
            self.traffic_specs.append(spec)
            for occurrence in range(spec.count):
                self.context.scheduler.schedule(
                    spec.start_s + occurrence * spec.interval_s,
                    "BUSINESS_TRAFFIC",
                    {"traffic_id": spec.traffic_id, "occurrence": occurrence},
                    priority=20,
                )

        for raw in session_lifecycle_specs:
            try:
                spec = SessionLifecycleSpec(**deepcopy(raw))
            except TypeError as exc:
                raise ValueError(f"UNKNOWN_SESSION_LIFECYCLE_FIELD:{exc}") from exc
            if spec.lifecycle_id is None:
                spec.lifecycle_id = self.context.ids.next("lifecycle")
            if spec.rotate_at_s > self.context.config.duration_s + 1e-12:
                raise ValueError("SESSION_LIFECYCLE_OUTSIDE_RUN_DURATION")
            self.session_lifecycle_specs.append(spec)
            self.context.scheduler.schedule(
                spec.rotate_at_s,
                "SESSION_ROTATION",
                {"lifecycle_id": spec.lifecycle_id},
                priority=10,
            )

    def traffic(self, traffic_id: str) -> BusinessTrafficSpec:
        return next(spec for spec in self.traffic_specs if spec.traffic_id == traffic_id)

    def lifecycle(self, lifecycle_id: str) -> SessionLifecycleSpec:
        return next(
            spec
            for spec in self.session_lifecycle_specs
            if spec.lifecycle_id == lifecycle_id
        )

    def provenance(self) -> dict[str, Any]:
        return {
            "traffic_specs": [asdict(spec) for spec in self.traffic_specs],
            "session_lifecycle_specs": [
                asdict(spec) for spec in self.session_lifecycle_specs
            ],
            "executed_traffic": deepcopy(self.executed_traffic),
            "executed_session_lifecycle": deepcopy(
                self.executed_session_lifecycle
            ),
        }
