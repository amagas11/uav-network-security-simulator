"""Configurable attack-like *normal* controls.

Normal disturbances alter legitimate traffic, channel or node state through the
same runtime path as ordinary operation.  They deliberately have no attack
label API, so they cannot silently become attack truth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .simulation import RunContext


NORMAL_DISTURBANCE_TYPES = {
    "NORMAL_LOW_SNR",
    "NORMAL_PACKET_LOSS",
    "NORMAL_TRAFFIC_BURST",
    "NORMAL_OUT_OF_ORDER",
    "NORMAL_STATE_CHANGE",
    "NORMAL_CONGESTION",
}


NORMAL_PARAMETER_CONTRACTS: dict[str, set[str]] = {
    "NORMAL_LOW_SNR": {"attenuation_db"},
    "NORMAL_PACKET_LOSS": {"loss_probability"},
    "NORMAL_TRAFFIC_BURST": {
        "source_node_id",
        "packet_rate_pps",
        "packet_type",
        "packet_size_bytes",
        "target_packet_size_bytes",
    },
    "NORMAL_OUT_OF_ORDER": {
        "source_node_id",
        "sequence_numbers",
        "session_id",
        "packet_type",
    },
    "NORMAL_STATE_CHANGE": {
        "battery_pct",
        "flight_state",
        "position_xyz_m",
    },
    "NORMAL_CONGESTION": {
        "source_node_id",
        "packet_rate_pps",
        "packet_type",
        "packet_size_bytes",
        "target_packet_size_bytes",
        "busy_ratio_addition",
    },
}


@dataclass(slots=True)
class NormalDisturbancePlan:
    disturbance_type: str
    start_s: float
    end_s: float
    target_node_ids: list[int] = field(default_factory=list)
    target_link_ids: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    profile_id: str | None = None

    def __post_init__(self) -> None:
        def is_number(value: Any) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        if not isinstance(self.disturbance_type, str):
            raise ValueError("NORMAL_DISTURBANCE_TYPE_MUST_BE_STRING")
        self.disturbance_type = self.disturbance_type.upper()
        if self.disturbance_type not in NORMAL_DISTURBANCE_TYPES:
            raise ValueError(f"unsupported normal disturbance: {self.disturbance_type}")
        if not is_number(self.start_s) or not is_number(self.end_s):
            raise ValueError("NORMAL_DISTURBANCE_TIMES_MUST_BE_NUMERIC")
        if not isinstance(self.target_node_ids, list) or not isinstance(
            self.target_link_ids, list
        ):
            raise ValueError("NORMAL_TARGETS_MUST_BE_ARRAYS")
        if not isinstance(self.parameters, dict):
            raise ValueError("NORMAL_PARAMETERS_MUST_BE_OBJECT")
        if not 0 <= self.start_s < self.end_s:
            raise ValueError("normal disturbance must satisfy 0 <= start < end")
        unknown = sorted(
            set(self.parameters) - NORMAL_PARAMETER_CONTRACTS[self.disturbance_type]
        )
        if unknown:
            raise ValueError(
                "UNKNOWN_NORMAL_PARAMETER:"
                f"{self.disturbance_type}:{','.join(unknown)}"
            )
        if any(
            not isinstance(node_id, int) or isinstance(node_id, bool)
            for node_id in self.target_node_ids
        ):
            raise ValueError("NORMAL_TARGET_NODE_IDS_MUST_BE_INTEGERS")
        if any(
            not isinstance(link_id, str) or not link_id
            for link_id in self.target_link_ids
        ):
            raise ValueError("NORMAL_TARGET_LINK_IDS_MUST_BE_NON_EMPTY_STRINGS")
        if "source_node_id" in self.parameters and (
            not isinstance(self.parameters["source_node_id"], int)
            or isinstance(self.parameters["source_node_id"], bool)
        ):
            raise ValueError("NORMAL_PARAMETER_TYPE:source_node_id:integer")
        for name in ("packet_type", "session_id", "flight_state"):
            if name in self.parameters and (
                not isinstance(self.parameters[name], str)
                or not self.parameters[name]
            ):
                raise ValueError(f"NORMAL_PARAMETER_TYPE:{name}:non-empty-string")
        if self.disturbance_type == "NORMAL_PACKET_LOSS":
            if "loss_probability" in self.parameters and not is_number(
                self.parameters["loss_probability"]
            ):
                raise ValueError("NORMAL_PARAMETER_TYPE:loss_probability:number")
            probability = float(self.parameters.get("loss_probability", 0.2))
            if not 0.0 <= probability <= 1.0:
                raise ValueError("loss_probability must be between 0 and 1")
        if self.disturbance_type == "NORMAL_LOW_SNR":
            if "attenuation_db" in self.parameters and not is_number(
                self.parameters["attenuation_db"]
            ):
                raise ValueError("NORMAL_PARAMETER_TYPE:attenuation_db:number")
            if float(self.parameters.get("attenuation_db", 20.0)) < 0:
                raise ValueError("attenuation_db must be non-negative")
        if self.disturbance_type in {
            "NORMAL_TRAFFIC_BURST",
            "NORMAL_CONGESTION",
        }:
            if "packet_rate_pps" in self.parameters and not is_number(
                self.parameters["packet_rate_pps"]
            ):
                raise ValueError("NORMAL_PARAMETER_TYPE:packet_rate_pps:number")
            if float(self.parameters.get("packet_rate_pps", 20.0)) <= 0:
                raise ValueError("packet_rate_pps must be positive")
            for name in ("packet_size_bytes", "target_packet_size_bytes"):
                if name in self.parameters and (
                    not isinstance(self.parameters[name], int)
                    or isinstance(self.parameters[name], bool)
                ):
                    raise ValueError(f"NORMAL_PARAMETER_TYPE:{name}:integer")
            size = self.parameters.get(
                "target_packet_size_bytes",
                self.parameters.get("packet_size_bytes", 256),
            )
            if size < 32:
                raise ValueError("packet size must be at least 32 bytes")
            if "busy_ratio_addition" in self.parameters:
                busy = self.parameters["busy_ratio_addition"]
                if not is_number(busy) or not 0.0 <= float(busy) <= 1.0:
                    raise ValueError(
                        "NORMAL_PARAMETER_RANGE:busy_ratio_addition:[0,1]"
                    )
        if self.disturbance_type == "NORMAL_OUT_OF_ORDER":
            values = self.parameters.get("sequence_numbers", [100, 102, 101])
            if not isinstance(values, list) or not all(
                isinstance(value, int) and not isinstance(value, bool)
                for value in values
            ):
                raise ValueError("sequence_numbers must be an integer array")
        if "battery_pct" in self.parameters:
            battery = self.parameters["battery_pct"]
            if not is_number(battery) or not 0.0 <= float(battery) <= 100.0:
                raise ValueError("NORMAL_PARAMETER_RANGE:battery_pct:[0,100]")
        if "position_xyz_m" in self.parameters:
            position = self.parameters["position_xyz_m"]
            if not isinstance(position, (list, tuple)) or len(position) != 3 or not all(
                is_number(value) for value in position
            ):
                raise ValueError("NORMAL_PARAMETER_TYPE:position_xyz_m:3-number-array")


@dataclass(slots=True)
class NormalDisturbanceRecord:
    plan: NormalDisturbancePlan
    status: str = "SCHEDULED"
    evidence: dict[str, Any] = field(default_factory=dict)


class NormalDisturbanceScheduler:
    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.records: dict[str, NormalDisturbanceRecord] = {}
        self._effect_tokens: set[tuple[str, str, int | None]] = set()

    def schedule(self, plan: NormalDisturbancePlan) -> dict[str, Any]:
        if plan.profile_id is None:
            plan.profile_id = self.context.ids.next("normal-profile")
        if plan.profile_id in self.records:
            raise ValueError(f"duplicate normal profile id: {plan.profile_id}")
        self.records[plan.profile_id] = NormalDisturbanceRecord(plan=plan)
        return asdict(plan)

    def update(self, now_s: float) -> None:
        for record in self.records.values():
            if now_s >= record.plan.end_s:
                record.status = "ENDED"
            elif now_s >= record.plan.start_s:
                record.status = "ACTIVE"
            else:
                record.status = "SCHEDULED"

    def active(
        self, now_s: float, disturbance_type: str | None = None
    ) -> list[NormalDisturbanceRecord]:
        self.update(now_s)
        requested = disturbance_type.upper() if disturbance_type else None
        return [
            record
            for record in self.records.values()
            if record.status == "ACTIVE"
            and (requested is None or record.plan.disturbance_type == requested)
        ]

    def effect_once(
        self,
        record: NormalDisturbanceRecord,
        effect: str,
        tick_index: int | None = None,
    ) -> bool:
        token = (record.plan.profile_id or "", effect, tick_index)
        if token in self._effect_tokens:
            return False
        self._effect_tokens.add(token)
        return True

    def link_modifiers(self, link_id: str, now_s: float) -> dict[str, float]:
        result = {
            "attenuation_db": 0.0,
            "loss_probability": 0.0,
            "busy_ratio_addition": 0.0,
        }
        for record in self.active(now_s):
            plan = record.plan
            if plan.target_link_ids and link_id not in plan.target_link_ids:
                continue
            if plan.disturbance_type == "NORMAL_LOW_SNR":
                attenuation = float(plan.parameters.get("attenuation_db", 20.0))
                result["attenuation_db"] += attenuation
                record.evidence["affected_phy_samples"] = int(
                    record.evidence.get("affected_phy_samples", 0)
                ) + 1
                record.evidence["attenuation_db"] = attenuation
            elif plan.disturbance_type == "NORMAL_PACKET_LOSS":
                probability = float(plan.parameters.get("loss_probability", 0.2))
                result["loss_probability"] = 1.0 - (
                    1.0 - result["loss_probability"]
                ) * (1.0 - probability)
                record.evidence["affected_phy_samples"] = int(
                    record.evidence.get("affected_phy_samples", 0)
                ) + 1
                record.evidence["loss_probability"] = probability
            elif plan.disturbance_type == "NORMAL_CONGESTION":
                addition = float(plan.parameters.get("busy_ratio_addition", 0.25))
                result["busy_ratio_addition"] += addition
                record.evidence["affected_phy_samples"] = int(
                    record.evidence.get("affected_phy_samples", 0)
                ) + 1
                record.evidence["busy_ratio_addition"] = addition
        return result

    @staticmethod
    def labels() -> list[dict[str, Any]]:
        """Normal controls intentionally never create attack labels."""

        return []

    def reset(self) -> None:
        self.records.clear()
        self._effect_tokens.clear()
