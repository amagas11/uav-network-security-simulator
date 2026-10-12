"""Simulation time, deterministic random streams, IDs, and scheduling."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, is_dataclass
import hashlib
import heapq
import json
import math
import random
from typing import Any
from uuid import uuid4

import numpy as np

from .domain import NodeRole


SCHEMA_VERSION = "3.2.0"
SOFTWARE_VERSION = "platform-v7"


def runtime_semantic_fingerprint(
    base_config_fingerprint: str,
    *,
    calibration_profile_hash: str | None,
    model_assets: dict[str, dict[str, Any]] | None,
    probe_profile: str | None = None,
) -> str:
    """Include behavior-changing runtime assets/profiles in run identity."""

    model_fields = (
        "configured",
        "model_name",
        "model_version",
        "provider_implementation_status",
        "asset_maturity",
        "bundle_hash",
        "preprocessor_version",
        "threshold_version",
        "training_data_version",
    )
    semantic_models = {
        slot: {key: model.get(key) for key in model_fields}
        for slot, model in sorted((model_assets or {}).items())
    }
    semantic_runtime = {
        "base_config_fingerprint": base_config_fingerprint,
        "calibration_profile_hash": calibration_profile_hash,
        "model_assets": semantic_models,
    }
    # Keep previously exported schema-3.2 development datasets verifiable;
    # newly produced records always provide this behavior-changing profile.
    if probe_profile is not None:
        semantic_runtime["probe_profile"] = probe_profile
    encoded = json.dumps(
        semantic_runtime,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ConfigValidationError(ValueError):
    """Raised when a public run configuration violates the frozen contract."""


def _plain_plan(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return deepcopy(value)
    raise TypeError("experiment plans must be dictionaries or dataclass instances")


def canonical_plans(
    values: list[Any] | tuple[Any, ...] | None, *, identity_field: str
) -> list[dict[str, Any]]:
    """Return the semantic plan payload without run-scoped identifiers."""

    result: list[dict[str, Any]] = []
    for value in values or []:
        plain = _plain_plan(value)
        plain.pop(identity_field, None)
        result.append(plain)
    return result


def plan_collection_id(
    prefix: str,
    values: list[Any] | tuple[Any, ...] | None,
    *,
    identity_field: str,
) -> str | None:
    plans = canonical_plans(values, identity_field=identity_field)
    if not plans:
        return None
    encoded = json.dumps(
        plans, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


@dataclass(slots=True)
class RunConfig:
    """Configuration whose values fully determine simulation semantics."""

    seed: int = 42
    duration_s: float = 10.0
    step_s: float = 0.2
    node_count: int = 4
    node_roles: dict[int, str] | None = None
    auto_traffic: bool = True
    encrypt_sensitive: bool = False
    queue_capacity: int = 32
    tx_service_per_step: int = 4
    rx_service_per_step: int = 2
    phy_sample_interval_s: float = 0.2
    traffic_statistics_window_s: float = 1.0
    flooding_packet_rate_threshold_pps: float = 8.0
    flooding_detection_enabled: bool = True
    flooding_severe_rate_multiplier: float = 1.5
    flooding_sustained_overload_s: float = 0.5
    flooding_recovery_rate_multiplier: float = 0.7
    flooding_recovery_hold_s: float = 2.0
    flooding_token_refill_rate_pps: float = 8.0
    flooding_token_bucket_capacity: float = 12.0
    replay_timestamp_freshness_s: float = 2.0
    replay_reorder_window_size: int = 32
    security_summary_window_s: float = 0.5
    decision_step_s: float = 0.2
    frequency_hz: float = 3.5e9
    bandwidth_hz: float = 20e6
    channel_profile_id: str = "uncalibrated-static-a2a-v1"
    traffic_profile_id: str = "formation-default-v1"
    software_version: str = SOFTWARE_VERSION
    data_source_kind: str = "simulation"
    calibration_status: str = "UNCALIBRATED_BASELINE"
    source_dataset_version: str | None = None
    calibration_version: str | None = None
    attack_specs: list[dict[str, Any]] = field(default_factory=list)
    normal_disturbance_specs: list[dict[str, Any]] = field(default_factory=list)
    traffic_specs: list[dict[str, Any]] = field(default_factory=list)
    session_lifecycle_specs: list[dict[str, Any]] = field(default_factory=list)
    episode_phases: dict[str, Any] | None = None
    model_recommendation_confidence_threshold: float = 0.8
    model_recommendation_quality_threshold: float = 0.5
    model_inference_timeout_ms: float = 100.0
    dataset_maturity: str = "DEVELOPMENT"
    require_formal_security: bool = False
    allow_external_model_observer: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.flooding_detection_enabled, bool):
            raise ValueError("flooding_detection_enabled must be boolean")
        if self.node_count < 2:
            raise ValueError("node_count must be at least 2")
        if self.duration_s <= 0 or self.step_s <= 0:
            raise ValueError("duration_s and step_s must be positive")
        if self.queue_capacity < 1:
            raise ValueError("queue_capacity must be positive")
        if self.tx_service_per_step < 1 or self.rx_service_per_step < 1:
            raise ValueError("queue service rates must be positive")
        if self.phy_sample_interval_s <= 0:
            raise ValueError("phy_sample_interval_s must be positive")
        if self.traffic_statistics_window_s <= 0:
            raise ValueError("traffic_statistics_window_s must be positive")
        if self.flooding_packet_rate_threshold_pps <= 0:
            raise ValueError("flooding_packet_rate_threshold_pps must be positive")
        dos_defense_fields = (
            "flooding_severe_rate_multiplier",
            "flooding_sustained_overload_s",
            "flooding_recovery_rate_multiplier",
            "flooding_recovery_hold_s",
            "flooding_token_refill_rate_pps",
            "flooding_token_bucket_capacity",
        )
        for field_name in dos_defense_fields:
            value = getattr(self, field_name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{field_name} must be a positive number")
        if self.flooding_severe_rate_multiplier < 1:
            raise ValueError("flooding_severe_rate_multiplier must be at least 1")
        if self.flooding_recovery_rate_multiplier >= 1:
            raise ValueError("flooding_recovery_rate_multiplier must be below 1")
        if self.replay_timestamp_freshness_s <= 0:
            raise ValueError("replay_timestamp_freshness_s must be positive")
        if self.replay_reorder_window_size < 1:
            raise ValueError("replay_reorder_window_size must be positive")
        if self.security_summary_window_s <= 0:
            raise ValueError("security_summary_window_s must be positive")
        if self.decision_step_s <= 0:
            raise ValueError("decision_step_s must be positive")
        if self.frequency_hz <= 0 or self.bandwidth_hz <= 0:
            raise ValueError("frequency_hz and bandwidth_hz must be positive")
        if not str(self.software_version).startswith("platform-v7"):
            raise ValueError("software_version must identify the platform-v7 producer")
        if self.data_source_kind not in {
            "simulation",
            "calibrated_simulation",
            "real_measurement",
            "augmented_real",
        }:
            raise ValueError("unsupported data_source_kind")
        if not isinstance(self.attack_specs, list) or not all(
            isinstance(item, dict) for item in self.attack_specs
        ):
            raise ValueError("attack_specs must be a list of objects")
        if not isinstance(self.normal_disturbance_specs, list) or not all(
            isinstance(item, dict) for item in self.normal_disturbance_specs
        ):
            raise ValueError("normal_disturbance_specs must be a list of objects")
        if not isinstance(self.traffic_specs, list) or not all(
            isinstance(item, dict) for item in self.traffic_specs
        ):
            raise ValueError("traffic_specs must be a list of objects")
        if not isinstance(self.session_lifecycle_specs, list) or not all(
            isinstance(item, dict) for item in self.session_lifecycle_specs
        ):
            raise ValueError("session_lifecycle_specs must be a list of objects")
        if not isinstance(self.allow_external_model_observer, bool):
            raise ValueError("allow_external_model_observer must be boolean")
        if self.episode_phases is not None and not isinstance(
            self.episode_phases, dict
        ):
            raise ValueError("episode_phases must be an object or null")
        if not 0.0 <= self.model_recommendation_confidence_threshold <= 1.0:
            raise ValueError("model recommendation confidence threshold must be in [0, 1]")
        if not 0.0 <= self.model_recommendation_quality_threshold <= 1.0:
            raise ValueError("model recommendation quality threshold must be in [0, 1]")
        if (
            not isinstance(self.model_inference_timeout_ms, (int, float))
            or isinstance(self.model_inference_timeout_ms, bool)
            or self.model_inference_timeout_ms <= 0
        ):
            raise ValueError("model_inference_timeout_ms must be positive")
        self.dataset_maturity = str(self.dataset_maturity).upper()
        if self.dataset_maturity not in {"DEVELOPMENT", "PRELIMINARY", "FORMAL"}:
            raise ValueError("dataset_maturity must be DEVELOPMENT, PRELIMINARY, or FORMAL")

    @classmethod
    def from_dict(
        cls, value: dict[str, Any] | None, *, strict: bool = True
    ) -> "RunConfig":
        if not value:
            return cls()
        if not isinstance(value, dict):
            raise ConfigValidationError("run_config must be an object")
        known = cls.__dataclass_fields__
        unknown = sorted(set(value) - set(known))
        if strict and unknown:
            raise ConfigValidationError(
                f"unknown RunConfig field(s): {', '.join(unknown)}"
            )
        filtered = {
            key: deepcopy(item) for key, item in value.items() if key in known
        }
        roles = filtered.get("node_roles")
        if isinstance(roles, dict):
            filtered["node_roles"] = {int(key): str(role) for key, role in roles.items()}
        return cls(**filtered)

    def resolved_roles(self) -> dict[int, NodeRole]:
        defaults: dict[int, NodeRole] = {0: NodeRole.GCS, 1: NodeRole.LEADER}
        defaults.update({index: NodeRole.FOLLOWER for index in range(2, self.node_count)})
        if self.node_roles:
            for node_id, raw_role in self.node_roles.items():
                if node_id < 0 or node_id >= self.node_count:
                    raise ValueError(f"node role id {node_id} is outside the run")
                defaults[node_id] = NodeRole(str(raw_role).upper())
        if NodeRole.GCS not in defaults.values() or NodeRole.LEADER not in defaults.values():
            raise ValueError("a run requires at least one GCS and one LEADER")
        return defaults

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["node_roles"] = {
            str(node_id): role.value for node_id, role in self.resolved_roles().items()
        }
        return result

    def semantic_fingerprint(
        self,
        *,
        attack_plans: list[Any] | tuple[Any, ...] | None = None,
        normal_disturbance_plans: list[Any] | tuple[Any, ...] | None = None,
    ) -> str:
        semantic_config = self.to_dict()
        # Preserve historical comprehensive-mode fingerprints. Explicitly
        # disabling a detector changes emitted behavior and remains in the hash.
        if self.flooding_detection_enabled:
            semantic_config.pop("flooding_detection_enabled", None)
        dos_defaults = {
            "flooding_severe_rate_multiplier": 1.5,
            "flooding_sustained_overload_s": 0.5,
            "flooding_recovery_rate_multiplier": 0.7,
            "flooding_recovery_hold_s": 2.0,
            "flooding_token_refill_rate_pps": 8.0,
            "flooding_token_bucket_capacity": 12.0,
        }
        for field_name, default in dos_defaults.items():
            if semantic_config[field_name] == default:
                semantic_config.pop(field_name)
        semantic_config["attack_specs"] = canonical_plans(
            self.attack_specs if attack_plans is None else attack_plans,
            identity_field="attack_id",
        )
        semantic_config["normal_disturbance_specs"] = canonical_plans(
            (
                self.normal_disturbance_specs
                if normal_disturbance_plans is None
                else normal_disturbance_plans
            ),
            identity_field="profile_id",
        )
        # These are intentionally provenance/evaluator references only until a
        # runtime phase/profile engine is introduced.  Changing metadata that
        # cannot change emitted behavior must not change the semantic hash.
        semantic_config.pop("episode_phases", None)
        semantic_config.pop("traffic_profile_id", None)
        semantic_config.pop("dataset_maturity", None)
        semantic_config.pop("require_formal_security", None)
        encoded = json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "run_config": semantic_config,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class SimulationClock:
    """Monotonic simulation clock; never consults wall time."""

    def __init__(self, start_s: float = 0.0) -> None:
        self._start_s = float(start_s)
        self._now_s = float(start_s)

    @property
    def now_s(self) -> float:
        return self._now_s

    def advance_by(self, delta_s: float) -> float:
        if delta_s < 0:
            raise ValueError("simulation time cannot move backwards")
        self._now_s = round(self._now_s + float(delta_s), 9)
        return self._now_s

    def advance_to(self, target_s: float) -> float:
        if target_s < self._now_s:
            raise ValueError("simulation time cannot move backwards")
        self._now_s = round(float(target_s), 9)
        return self._now_s

    def reset(self) -> None:
        self._now_s = self._start_s


@dataclass(order=True, slots=True)
class ScheduledItem:
    at_s: float
    priority: int
    order: int
    kind: str = field(compare=False)
    payload: dict[str, Any] = field(compare=False, default_factory=dict)


class SimulationScheduler:
    """Stable priority queue ordered by simulation time, priority, then insertion."""

    def __init__(self) -> None:
        self._items: list[ScheduledItem] = []
        self._order = 0

    def schedule(
        self,
        at_s: float,
        kind: str,
        payload: dict[str, Any] | None = None,
        *,
        priority: int = 100,
    ) -> ScheduledItem:
        if at_s < 0:
            raise ValueError("scheduled time cannot be negative")
        self._order += 1
        item = ScheduledItem(float(at_s), int(priority), self._order, kind, payload or {})
        heapq.heappush(self._items, item)
        return item

    def pop_due(self, now_s: float) -> list[ScheduledItem]:
        result: list[ScheduledItem] = []
        while self._items and self._items[0].at_s <= now_s + 1e-12:
            result.append(heapq.heappop(self._items))
        return result

    def reset(self) -> None:
        self._items.clear()
        self._order = 0

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            {
                "at_s": item.at_s,
                "priority": item.priority,
                "order": item.order,
                "kind": item.kind,
                "payload": item.payload,
            }
            for item in sorted(self._items)
        ]


class RNGRegistry:
    """Independent random streams deterministically derived from one run seed."""

    def __init__(self, seed: int) -> None:
        self.seed = int(seed)
        self._python: dict[str, random.Random] = {}
        self._numpy: dict[str, np.random.Generator] = {}

    def _derived_seed(self, name: str) -> int:
        digest = hashlib.sha256(f"{self.seed}:{name}".encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big", signed=False)

    def python(self, name: str) -> random.Random:
        if name not in self._python:
            self._python[name] = random.Random(self._derived_seed(name))
        return self._python[name]

    def numpy(self, name: str) -> np.random.Generator:
        if name not in self._numpy:
            self._numpy[name] = np.random.default_rng(self._derived_seed(name))
        return self._numpy[name]

    def reset(self) -> None:
        self._python.clear()
        self._numpy.clear()


class IdFactory:
    """Run-scoped opaque deterministic identifiers.

    The run id is deliberately hashed rather than copied into C-visible IDs.
    This preserves cross-run uniqueness without encoding scenario names or
    simulator-private participant identifiers in event/message/probe IDs.
    """

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        scope = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:12]
        # Keep the opaque scope visibly non-decimal.  A SHA-256 prefix can,
        # rarely, contain digits only; that shape is indistinguishable from a
        # legacy ``link-<src>-<dst>`` encoding to a conservative leakage
        # audit.  Replacing one nibble in that rare case retains a stable
        # 12-hex token while making the non-endpoint contract unambiguous.
        self._scope = f"a{scope[1:]}" if scope.isdigit() else scope
        self._counters: dict[str, int] = {}

    def next(self, kind: str) -> str:
        self._counters[kind] = self._counters.get(kind, 0) + 1
        return f"{kind}-{self._scope}-{self._counters[kind]:08d}"

    def reset(self) -> None:
        self._counters.clear()


@dataclass(slots=True)
class RunContext:
    run_id: str
    config: RunConfig
    clock: SimulationClock
    scheduler: SimulationScheduler
    rng: RNGRegistry
    ids: IdFactory

    @classmethod
    def create(cls, config: RunConfig, run_id: str | None = None) -> "RunContext":
        actual_run_id = run_id or f"run-{uuid4().hex}"
        return cls(
            run_id=actual_run_id,
            config=config,
            clock=SimulationClock(),
            scheduler=SimulationScheduler(),
            rng=RNGRegistry(config.seed),
            ids=IdFactory(actual_run_id),
        )

    def run_record(
        self,
        *,
        attack_plans: list[Any] | tuple[Any, ...] | None = None,
        normal_disturbance_plans: list[Any] | tuple[Any, ...] | None = None,
    ) -> dict[str, Any]:
        roles = {
            str(node_id): role.value for node_id, role in self.config.resolved_roles().items()
        }
        actual_attacks = [
            _plain_plan(item)
            for item in (
                self.config.attack_specs if attack_plans is None else attack_plans
            )
        ]
        actual_normal = [
            _plain_plan(item)
            for item in (
                self.config.normal_disturbance_specs
                if normal_disturbance_plans is None
                else normal_disturbance_plans
            )
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "seed": self.config.seed,
            "duration_s": self.config.duration_s,
            "step_s": self.config.step_s,
            "start_sim_time_s": 0.0,
            "node_count": self.config.node_count,
            "node_roles": roles,
            "data_source": {
                "kind": self.config.data_source_kind,
                "source_dataset_version": self.config.source_dataset_version,
                "calibration_version": self.config.calibration_version,
            },
            "profiles": {
                "channel_profile_id": self.config.channel_profile_id,
                "traffic_profile_id": self.config.traffic_profile_id,
                "attack_plan_id": plan_collection_id(
                    "attack-plan", actual_attacks, identity_field="attack_id"
                ),
                "normal_disturbance_plan_id": plan_collection_id(
                    "normal-plan", actual_normal, identity_field="profile_id"
                ),
            },
            "software_version": self.config.software_version,
            "run_config": self.config.to_dict(),
            "attack_plan": actual_attacks,
            "normal_disturbance_plan": actual_normal,
            "config_fingerprint": self.config.semantic_fingerprint(
                attack_plans=actual_attacks,
                normal_disturbance_plans=actual_normal,
            ),
            "calibration_status": self.config.calibration_status,
        }
