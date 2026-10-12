"""Scheduled attack plans and simulator-truth effects."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any
import math

from .domain import Frame, Message
from .simulation import RunContext, SCHEMA_VERSION


ATTACK_FAMILIES = {"SPOOFING", "EAVESDROPPING", "DOS", "FDI", "REPLAY"}
ATTACK_SUBTYPES = {
    "SPOOFING": {"UNKNOWN_ID", "KNOWN_ID_CONFLICT"},
    "EAVESDROPPING": {
        "PASSIVE_CAPTURE",
        "NONSENSITIVE_PLAINTEXT_CONTROL",
        "CIPHERTEXT_ONLY",
        "PLAINTEXT_EXPOSURE",
    },
    "DOS": {"FLOODING"},
    "FDI": {
        "COMMAND_REPLACEMENT",
        "TELEMETRY_ABRUPT_CHANGE",
        "TELEMETRY_GRADUAL_DRIFT",
        "OUT_OF_RANGE_VALUE",
        "LOGICAL_INCONSISTENCY",
    },
    "REPLAY": {
        "IMMEDIATE_REPLAY",
        "DELAYED_REPLAY",
        "OLD_SESSION_REPLAY",
        # Backward-compatible name from the first V1 delivery.  Its semantics
        # are the same as IMMEDIATE_REPLAY and it is not used by new plans.
        "CAPTURE_AND_REPLAY",
    },
}


ATTACK_PARAMETER_CONTRACTS: dict[tuple[str, str], set[str]] = {
    ("SPOOFING", "UNKNOWN_ID"): {"claimed_src_id", "source_copy_mode", "legitimate_source_id"},
    ("SPOOFING", "KNOWN_ID_CONFLICT"): {"claimed_src_id", "source_copy_mode", "legitimate_source_id"},
    ("EAVESDROPPING", "PASSIVE_CAPTURE"): {"receiver_radius_m"},
    ("EAVESDROPPING", "NONSENSITIVE_PLAINTEXT_CONTROL"): {"receiver_radius_m"},
    ("EAVESDROPPING", "CIPHERTEXT_ONLY"): {"receiver_radius_m"},
    ("EAVESDROPPING", "PLAINTEXT_EXPOSURE"): {"receiver_radius_m"},
    ("DOS", "FLOODING"): {
        "packet_type",
        "packet_size_bytes",
        "target_packet_size_bytes",
    },
    ("FDI", "COMMAND_REPLACEMENT"): {"replacement"},
    ("FDI", "TELEMETRY_ABRUPT_CHANGE"): {
        "field",
        "replacement",
        "absolute_offset",
        "bias_model", "bias_amplitude_m", "bias_period_packets",
    },
    ("FDI", "TELEMETRY_GRADUAL_DRIFT"): {
        "field",
        "delta_per_step",
        "delta_per_tick",
    },
    ("FDI", "OUT_OF_RANGE_VALUE"): {"field", "value"},
    ("FDI", "LOGICAL_INCONSISTENCY"): {"altitude_m"},
    ("REPLAY", "IMMEDIATE_REPLAY"): {"max_capture_age_s", "repeat"},
    ("REPLAY", "CAPTURE_AND_REPLAY"): {"max_capture_age_s", "repeat"},
    ("REPLAY", "DELAYED_REPLAY"): {"delay_s", "repeat"},
    ("REPLAY", "OLD_SESSION_REPLAY"): {"stale_session_id", "repeat"},
}


@dataclass(slots=True)
class AttackPlan:
    attack_family: str
    attack_subtype: str
    scheduled_start_s: float
    impact_start_s: float
    end_s: float
    attacker_node_id: int | None = None
    target_node_ids: list[int] = field(default_factory=list)
    target_link_ids: list[str] = field(default_factory=list)
    intensity: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    attack_id: str | None = None

    def __post_init__(self) -> None:
        def is_number(value: Any) -> bool:
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        def require_number(name: str, *, minimum: float | None = None) -> None:
            if name not in self.parameters:
                return
            value = self.parameters[name]
            if not is_number(value):
                raise ValueError(f"ATTACK_PARAMETER_TYPE:{name}:number")
            if minimum is not None and float(value) < minimum:
                raise ValueError(f"ATTACK_PARAMETER_RANGE:{name}:minimum={minimum}")

        def require_string(name: str) -> None:
            if name in self.parameters and (
                not isinstance(self.parameters[name], str)
                or not self.parameters[name]
            ):
                raise ValueError(f"ATTACK_PARAMETER_TYPE:{name}:non-empty-string")

        if not isinstance(self.attack_family, str) or not isinstance(
            self.attack_subtype, str
        ):
            raise ValueError("ATTACK_FAMILY_AND_SUBTYPE_MUST_BE_STRINGS")
        self.attack_family = self.attack_family.upper()
        self.attack_subtype = self.attack_subtype.upper()
        if self.attack_family not in ATTACK_FAMILIES:
            raise ValueError(f"unsupported attack family: {self.attack_family}")
        if self.attack_subtype not in ATTACK_SUBTYPES[self.attack_family]:
            raise ValueError(
                f"unsupported {self.attack_family} subtype: {self.attack_subtype}"
            )
        if not all(
            is_number(value)
            for value in (
                self.scheduled_start_s,
                self.impact_start_s,
                self.end_s,
            )
        ):
            raise ValueError("ATTACK_TIMES_MUST_BE_NUMERIC")
        if not isinstance(self.target_node_ids, list) or not isinstance(
            self.target_link_ids, list
        ):
            raise ValueError("ATTACK_TARGETS_MUST_BE_ARRAYS")
        if not isinstance(self.intensity, dict) or not isinstance(
            self.parameters, dict
        ):
            raise ValueError("ATTACK_INTENSITY_AND_PARAMETERS_MUST_BE_OBJECTS")
        if self.attacker_node_id is not None and (
            not isinstance(self.attacker_node_id, int)
            or isinstance(self.attacker_node_id, bool)
        ):
            raise ValueError("ATTACKER_NODE_ID_MUST_BE_INTEGER_OR_NULL")
        if len(self.target_node_ids) > 1 or len(self.target_link_ids) > 1:
            raise ValueError("MULTI_TARGET_NOT_SUPPORTED_V6")
        if not (0 <= self.scheduled_start_s <= self.impact_start_s < self.end_s):
            raise ValueError("attack times must satisfy 0 <= scheduled <= impact < end")
        if any(
            not isinstance(node_id, int) or isinstance(node_id, bool)
            for node_id in self.target_node_ids
        ):
            raise ValueError("ATTACK_TARGET_NODE_IDS_MUST_BE_INTEGERS")
        if any(
            not isinstance(link_id, str) or not link_id
            for link_id in self.target_link_ids
        ):
            raise ValueError("ATTACK_TARGET_LINK_IDS_MUST_BE_NON_EMPTY_STRINGS")
        unit = self.intensity.get("unit")
        if self.attack_family == "DOS" and self.attack_subtype == "FLOODING":
            if unit not in {None, "pps"}:
                raise ValueError("FLOODING intensity unit must be pps")
        allowed = ATTACK_PARAMETER_CONTRACTS[(self.attack_family, self.attack_subtype)]
        if self.attack_family == 'FDI':
            allowed = allowed | {'injection_mode', 'legitimate_source_id'}
        unknown = sorted(set(self.parameters) - allowed)
        if unknown:
            raise ValueError(
                "UNKNOWN_ATTACK_PARAMETER:"
                f"{self.attack_family}/{self.attack_subtype}:{','.join(unknown)}"
            )
        unknown_intensity = sorted(set(self.intensity) - {"value", "unit"})
        if unknown_intensity:
            raise ValueError(
                f"UNKNOWN_ATTACK_INTENSITY_FIELD:{','.join(unknown_intensity)}"
            )
        if "repeat" in self.parameters and not isinstance(
            self.parameters["repeat"], bool
        ):
            raise ValueError("REPLAY_REPEAT_MUST_BE_BOOLEAN")
        if "value" in self.intensity and not is_number(self.intensity["value"]):
            raise ValueError("ATTACK_INTENSITY_VALUE_MUST_BE_NUMERIC")
        if "unit" in self.intensity and not isinstance(self.intensity["unit"], str):
            raise ValueError("ATTACK_INTENSITY_UNIT_MUST_BE_STRING")
        for name in (
            "receiver_radius_m",
            "packet_size_bytes",
            "target_packet_size_bytes",
            "replacement",
            "absolute_offset",
            "delta_per_step",
            "delta_per_tick",
            "value",
            "altitude_m",
            "max_capture_age_s",
            "delay_s",
        ):
            if name == "replacement" and self.attack_subtype == "COMMAND_REPLACEMENT":
                continue
            minimum = (
                0.0
                if name in {"receiver_radius_m", "max_capture_age_s", "delay_s"}
                else None
            )
            require_number(name, minimum=minimum)
        for name in ("packet_type", "field", "stale_session_id"):
            require_string(name)
        if self.attack_family == 'FDI' and 'injection_mode' in self.parameters:
            if self.parameters['injection_mode'] not in {'POST_HMAC_PRE_TRANSMISSION', 'ON_PATH_INTERCEPTION_REPLACEMENT', 'CAPTURE_MODIFY_INJECT'}:
                raise ValueError('UNSUPPORTED_FDI_INJECTION_MODE')
            if self.parameters['injection_mode'] in {'ON_PATH_INTERCEPTION_REPLACEMENT', 'CAPTURE_MODIFY_INJECT'}:
                source = self.parameters.get('legitimate_source_id')
                if not isinstance(source, int) or isinstance(source, bool):
                    raise ValueError('FDI_LEGITIMATE_SOURCE_REQUIRED')
        if 'bias_model' in self.parameters:
            if self.parameters['bias_model'] != 'BOUNDED_PERIODIC':
                raise ValueError('UNSUPPORTED_FDI_BIAS_MODEL')
            for name in ('bias_amplitude_m', 'bias_period_packets'):
                require_number(name)
                if name not in self.parameters or not math.isfinite(self.parameters[name]):
                    raise ValueError('INVALID_FDI_BIAS_PARAMETER')
            if not 0 <= self.parameters['bias_amplitude_m'] <= .5 or self.parameters['bias_period_packets'] < 3:
                raise ValueError('FDI_BIAS_PARAMETER_OUT_OF_RANGE')
        if "source_copy_mode" in self.parameters:
            if self.parameters["source_copy_mode"] != "LEGITIMATE_FRAME_COPY":
                raise ValueError("UNSUPPORTED_SPOOF_SOURCE_COPY_MODE")
            source = self.parameters.get("legitimate_source_id")
            if not isinstance(source, int) or isinstance(source, bool):
                raise ValueError("SPOOF_LEGITIMATE_SOURCE_MUST_BE_INTEGER")
        radius = self.parameters.get("receiver_radius_m")
        if radius is not None and float(radius) <= 0:
            raise ValueError("receiver_radius_m must be positive")
        if self.attack_subtype == "COMMAND_REPLACEMENT" and "replacement" in self.parameters:
            if not isinstance(self.parameters["replacement"], dict):
                raise ValueError("ATTACK_PARAMETER_TYPE:replacement:object")
        for name in ("packet_size_bytes", "target_packet_size_bytes"):
            if name in self.parameters:
                value = self.parameters[name]
                if not isinstance(value, int) or isinstance(value, bool) or value < 32:
                    raise ValueError(f"ATTACK_PARAMETER_RANGE:{name}:integer>=32")
        if "claimed_src_id" in self.parameters and (
            not isinstance(self.parameters["claimed_src_id"], int)
            or isinstance(self.parameters["claimed_src_id"], bool)
        ):
            raise ValueError("ATTACK_PARAMETER_TYPE:claimed_src_id:integer")


@dataclass(slots=True)
class AttackRuntimeRecord:
    plan: AttackPlan
    label_id: str
    requested_plan: dict[str, Any] = field(default_factory=dict)
    status: str = "SCHEDULED"
    truth: dict[str, Any] = field(default_factory=dict)
    outcome: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        AttackOutcomePolicy.initialize(self)

    def label(self, run_id: str) -> dict[str, Any]:
        truth = deepcopy(self.truth)
        truth.setdefault("requested_plan", deepcopy(self.requested_plan))
        truth.setdefault("resolved_plan", asdict(self.plan))
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "label_id": self.label_id,
            "attack_id": self.plan.attack_id,
            "attack_family": self.plan.attack_family,
            "attack_subtype": self.plan.attack_subtype,
            "scheduled_start_s": self.plan.scheduled_start_s,
            "impact_start_s": self.plan.impact_start_s,
            "end_s": self.plan.end_s,
            "attacker_node_id": self.plan.attacker_node_id,
            "target_node_ids": list(self.plan.target_node_ids),
            "target_link_ids": list(self.plan.target_link_ids),
            "intensity": deepcopy(self.plan.intensity),
            "parameters": deepcopy(self.plan.parameters),
            "truth": truth,
            "outcome": deepcopy(self.outcome),
        }


class AttackOutcomePolicy:
    """Frozen cross-family attack lifecycle with target-side effectiveness.

    Injection and target impact are deliberately separate.  In particular,
    successful pre-crypto mutation is never sufficient evidence that an FDI
    attack reached or changed the receiver's business state.
    """

    @staticmethod
    def initialize(record: AttackRuntimeRecord) -> None:
        record.outcome.update(
            {
                "attempted": False,
                "attack_active": False,
                "eligible_opportunity_seen": False,
                "injected": False,
                "reached_target": False,
                "malicious_content_executed": False,
                "mission_impact": None,
                "mission_impact_available": False,
                "mission_impact_missing_reason": "NOT_MEASURED",
                "attack_effective": False,
                "effectiveness_semantics": "TARGET_SIDE_SECURITY_OR_MISSION_EFFECT",
            }
        )

    @classmethod
    def attempted(cls, record: AttackRuntimeRecord) -> None:
        record.outcome["attempted"] = True

    @classmethod
    def injected(cls, record: AttackRuntimeRecord) -> None:
        cls.attempted(record)
        record.outcome["injected"] = True

    @classmethod
    def reached_target(cls, record: AttackRuntimeRecord) -> None:
        cls.injected(record)
        record.outcome["reached_target"] = True
        cls.refresh(record)

    @classmethod
    def malicious_content_executed(cls, record: AttackRuntimeRecord) -> None:
        cls.reached_target(record)
        record.outcome["malicious_content_executed"] = True
        cls.refresh(record)

    @staticmethod
    def refresh(record: AttackRuntimeRecord) -> None:
        family = record.plan.attack_family
        subtype = record.plan.attack_subtype
        outcome = record.outcome
        if family in {"FDI", "REPLAY"}:
            effective = bool(outcome.get("malicious_content_executed", False))
        elif family == "SPOOFING":
            effective = bool(
                outcome.get("reached_target", False)
                and (
                    outcome.get("identity_security_impact", False)
                    or outcome.get("malicious_content_executed", False)
                )
            )
        elif family == "DOS" and subtype == "FLOODING":
            effective = bool(
                outcome.get("reached_target", False)
                and (
                    outcome.get("service_degradation_observed", False)
                    or outcome.get("queue_pressure_observed", False)
                )
            )
        elif family == "EAVESDROPPING":
            effective = bool(outcome.get("plaintext_exposure_count", 0))
        else:  # pragma: no cover - ATTACK_FAMILIES keeps this defensive.
            effective = False
        outcome["attack_effective"] = effective


@dataclass(slots=True)
class CapturedFrame:
    frame: Frame
    capture_time_s: float


class AttackScheduler:
    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.records: dict[str, AttackRuntimeRecord] = {}
        self.captured_frames: dict[str, list[CapturedFrame]] = {}
        self._effect_tokens: set[tuple[str, str, int]] = set()
        self._fdi_drift: dict[tuple[str, int, str], float] = {}
        self.accounting = None  # read-only observer, never consulted for decisions

    def schedule(
        self, plan: AttackPlan, *, requested_plan: dict[str, Any] | None = None
    ) -> AttackPlan:
        if plan.attack_id is None:
            plan.attack_id = self.context.ids.next("attack")
        if plan.attack_id in self.records:
            raise ValueError(f"duplicate attack id: {plan.attack_id}")
        self.records[plan.attack_id] = AttackRuntimeRecord(
            plan=plan,
            label_id=self.context.ids.next("label"),
            requested_plan=deepcopy(requested_plan or asdict(plan)),
        )
        if plan.attack_family == "REPLAY":
            self.captured_frames[plan.attack_id] = []
        return plan

    def update(self, now_s: float) -> None:
        for record in self.records.values():
            plan = record.plan
            if now_s >= plan.end_s:
                record.status = "ENDED"
                attack_id = plan.attack_id or ""
                self._fdi_drift = {
                    key: value
                    for key, value in self._fdi_drift.items()
                    if key[0] != attack_id
                }
            elif now_s >= plan.impact_start_s:
                record.status = "ACTIVE"
                record.outcome["attack_active"] = True
            elif now_s >= plan.scheduled_start_s:
                record.status = "SCHEDULED"

    def active(self, now_s: float, family: str | None = None) -> list[AttackRuntimeRecord]:
        self.update(now_s)
        return [
            record
            for record in self.records.values()
            if record.status == "ACTIVE"
            and (family is None or record.plan.attack_family == family.upper())
        ]

    def effect_once_per_tick(
        self, record: AttackRuntimeRecord, effect: str, tick_index: int
    ) -> bool:
        token = (record.plan.attack_id or "", effect, tick_index)
        if token in self._effect_tokens:
            return False
        self._effect_tokens.add(token)
        return True

    def capture(self, frame: Frame, now_s: float) -> None:
        """Capture only into explicitly scheduled replay attack scopes."""
        for record in self.records.values():
            plan = record.plan
            if plan.attack_family != "REPLAY":
                continue
            if not (plan.scheduled_start_s <= now_s < plan.end_s):
                continue
            if plan.target_node_ids and frame.link_receiver_id not in plan.target_node_ids:
                continue
            if plan.target_link_ids and frame.link_id not in plan.target_link_ids:
                continue
            attack_id = plan.attack_id or ""
            buffer = self.captured_frames.setdefault(attack_id, [])
            buffer.append(
                CapturedFrame(
                    frame=frame.clone_for_replay(), capture_time_s=float(now_s)
                )
            )
            if len(buffer) > 256:
                self.captured_frames[attack_id] = buffer[-256:]
            record.truth["captured_frame_count"] = len(self.captured_frames[attack_id])
            if self.accounting is not None:
                self.accounting.replay_captured(attack_id, frame)
                self.accounting.capture_record(record, frame, now_s)

    def replay_candidate(
        self, record: AttackRuntimeRecord, now_s: float
    ) -> tuple[Frame, float] | None:
        target_ids = set(record.plan.target_node_ids)
        stale_session_id = record.plan.parameters.get("stale_session_id")
        subtype = record.plan.attack_subtype
        delay_s = float(record.plan.parameters.get("delay_s", 0.0))
        max_capture_age_s = float(
            record.plan.parameters.get("max_capture_age_s", float("inf"))
        )
        candidates = [
            captured
            for captured in self.captured_frames.get(record.plan.attack_id or "", [])
            if (not target_ids or captured.frame.link_receiver_id in target_ids)
            and (
                subtype != "OLD_SESSION_REPLAY"
                or stale_session_id is None
                or captured.frame.session_id == str(stale_session_id)
            )
            and (
                subtype != "DELAYED_REPLAY"
                or now_s + 1e-12 >= captured.capture_time_s + delay_s
            )
            and (
                subtype not in {"IMMEDIATE_REPLAY", "CAPTURE_AND_REPLAY"}
                or now_s - captured.capture_time_s <= max_capture_age_s + 1e-12
            )
        ]
        if not candidates:
            return None
        selected = candidates[0] if subtype == "OLD_SESSION_REPLAY" else candidates[-1]
        return selected.frame.clone_for_replay(), selected.capture_time_s

    def mutate_post_hmac(
        self, message: Message, now_s: float, *, on_path_record: AttackRuntimeRecord | None = None
    ) -> tuple[Message, AttackRuntimeRecord | None]:
        for record in self.active(now_s, "FDI"):
            plan = record.plan
            # The legitimate application HMAC has already been generated.
            # FDI now mutates only business payload and cannot recompute it.
            on_path = plan.parameters.get('injection_mode') in {'ON_PATH_INTERCEPTION_REPLACEMENT', 'CAPTURE_MODIFY_INJECT'}
            if on_path and record is not on_path_record:
                continue
            if not on_path and on_path_record is not None:
                continue
            if message.origin_node_id != (plan.parameters.get('legitimate_source_id') if on_path else plan.attacker_node_id):
                continue
            if (
                plan.target_node_ids
                and message.final_dst_node_id not in plan.target_node_ids
            ):
                continue
            subtype = plan.attack_subtype
            params = plan.parameters
            packet_type = message.packet_type.upper()
            field_name = str(params.get("field", "altitude_m"))
            eligible = False
            if subtype == "COMMAND_REPLACEMENT":
                eligible = "COMMAND" in packet_type or "cmd" in message.payload
            elif subtype in {
                "TELEMETRY_ABRUPT_CHANGE",
                "TELEMETRY_GRADUAL_DRIFT",
                "OUT_OF_RANGE_VALUE",
            }:
                eligible = (
                    packet_type == "TELEMETRY"
                    and field_name in message.payload
                    and isinstance(message.payload.get(field_name), (int, float))
                    and not isinstance(message.payload.get(field_name), bool)
                )
            elif subtype == "LOGICAL_INCONSISTENCY":
                eligible = packet_type == "TELEMETRY" and bool(
                    {"altitude_m", "flight_state"} & set(message.payload)
                )
            if not eligible:
                continue
            if self.accounting is not None:
                self.accounting.fdi_eligible(record, message)
            record.outcome["eligible_opportunity_seen"] = True
            AttackOutcomePolicy.attempted(record)
            original = deepcopy(message.payload)
            if subtype == "COMMAND_REPLACEMENT":
                message.payload = deepcopy(
                    params.get("replacement", {"cmd": "LAND", "altitude_m": 0.0})
                )
            elif subtype == "TELEMETRY_ABRUPT_CHANGE":
                current = float(message.payload.get(field_name, 0.0))
                replacement = params.get("replacement")
                if replacement is not None:
                    message.payload[field_name] = float(replacement)
                else:
                    offset = float(
                        params.get(
                            "absolute_offset",
                            plan.intensity.get("value", 50.0),
                        )
                    )
                    if params.get('bias_model') == 'BOUNDED_PERIODIC':
                        index = len(record.truth.get('modifications', []))
                        offset += params['bias_amplitude_m'] * math.sin(2 * math.pi * index / params['bias_period_packets'])
                        message.payload[field_name] = round(current + offset, 6)
                    else:
                        message.payload[field_name] = current + offset
            elif subtype == "TELEMETRY_GRADUAL_DRIFT":
                delta = float(
                    params.get(
                        "delta_per_step",
                        params.get("delta_per_tick", plan.intensity.get("value", 5.0)),
                    )
                )
                drift_key = (
                    plan.attack_id or "",
                    message.origin_node_id,
                    field_name,
                )
                accumulated = self._fdi_drift.get(drift_key, 0.0) + delta
                self._fdi_drift[drift_key] = accumulated
                message.payload[field_name] = (
                    float(message.payload.get(field_name, 0.0)) + accumulated
                )
            elif subtype == "OUT_OF_RANGE_VALUE":
                message.payload[field_name] = float(params.get("value", 5000.0))
            elif subtype == "LOGICAL_INCONSISTENCY":
                message.payload["flight_state"] = "LANDED"
                message.payload["altitude_m"] = float(params.get("altitude_m", 120.0))
            else:
                field_name = str(params.get("field", "altitude_m"))
                message.payload[field_name] = float(params.get("value", 250.0))
            record.truth.update(
                {
                    "actual_transmitter_id": plan.attacker_node_id if on_path else message.origin_node_id,
                    "original_value": original,
                    "modified_value": deepcopy(message.payload),
                    "injection_stage": plan.parameters.get('injection_mode', 'POST_HMAC_PRE_TRANSMISSION'),
                    "application_hmac_recomputed": False,
                }
            )
            record.truth.setdefault("modifications", []).append(
                {
                    "sim_time_s": float(now_s),
                    "message_id": message.message_id,
                    "original_value": original,
                    "modified_value": deepcopy(message.payload),
                    "modification_index": len(record.truth.get("modifications", [])) + 1,
                }
            )
            AttackOutcomePolicy.injected(record)
            if self.accounting is not None:
                self.accounting.fdi_modified(record, message, message.payload != original, now_s, original)
            return message, record
        return message, None

    def labels(self) -> list[dict[str, Any]]:
        return [
            record.label(self.context.run_id)
            for record in sorted(
                self.records.values(), key=lambda item: item.plan.impact_start_s
            )
        ]

    def reset(self) -> None:
        self.records.clear()
        self.captured_frames.clear()
        self._effect_tokens.clear()
        self._fdi_drift.clear()
