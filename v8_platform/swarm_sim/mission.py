"""Shared, explainable mission-impact baseline for labels, RL and evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class MissionImpactResult:
    score: float | None
    available: bool
    components: dict[str, float]
    missing_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MissionImpactEvaluator:
    """A deliberately small baseline over measured platform outcomes."""

    @staticmethod
    def from_components(
        *,
        command_failure_ratio: float | None = None,
        telemetry_unavailability_ratio: float | None = None,
        service_degradation_ratio: float | None = None,
        unauthorized_state_change: float | None = None,
    ) -> MissionImpactResult:
        raw = {
            "command_failure_ratio": command_failure_ratio,
            "telemetry_unavailability_ratio": telemetry_unavailability_ratio,
            "service_degradation_ratio": service_degradation_ratio,
            "unauthorized_state_change": unauthorized_state_change,
        }
        components = {
            key: max(0.0, min(1.0, float(value)))
            for key, value in raw.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        if not components:
            return MissionImpactResult(
                None, False, {}, "INSUFFICIENT_MEASURED_MISSION_COMPONENTS"
            )
        return MissionImpactResult(
            round(sum(components.values()) / len(components), 9),
            True,
            components,
            None,
        )

    @classmethod
    def from_business_apply(
        cls,
        *,
        packet_type: str,
        executed: bool,
        state_changed: bool,
        mission_effect: float | None,
    ) -> MissionImpactResult:
        if mission_effect is not None:
            return cls.from_components(unauthorized_state_change=mission_effect)
        if not executed:
            return cls.from_components(unauthorized_state_change=0.0)
        if packet_type.upper() == "MISSION_COMMAND":
            return cls.from_components(
                unauthorized_state_change=1.0 if state_changed else 0.5
            )
        if packet_type.upper() == "TELEMETRY":
            return cls.from_components(
                unauthorized_state_change=0.5 if state_changed else 0.25
            )
        return MissionImpactResult(None, False, {}, "BUSINESS_EFFECT_NOT_MODELED")
