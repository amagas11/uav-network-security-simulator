"""Uncalibrated feature-level RFF simulation and receiver-local identification.

Device profiles belong to the simulator. Only noisy observations and detector
results may be serialized into online events.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Real
import statistics
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .simulation import RNGRegistry


RFF_FEATURE_SCHEMA = "RFF_FEATURE_V1"
RFF_FEATURE_NAMES = (
    "cfo_ppm", "iq_gain_imbalance_db", "iq_phase_imbalance_deg",
    "dc_offset_i", "dc_offset_q", "pa_am_am", "pa_am_pm",
    "clock_skew_ppm",
)


def _finite(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, Real):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _device_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _quality_threshold(value: float) -> float:
    if not _finite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("quality_threshold must be finite and in [0, 1]")
    return float(value)


def _sample_count(value: int) -> int:
    if not _device_id(value) or value <= 0:
        raise ValueError("sample_count must be a positive integer")
    return value


def _vector(value: Any) -> bool:
    return (isinstance(value, (tuple, list)) and len(value) == len(RFF_FEATURE_NAMES)
            and all(_finite(item) for item in value))


@dataclass(frozen=True, slots=True)
class DeviceRffProfile:
    device_id: int
    feature_schema: str
    baseline: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class RffObservation:
    sample_id: str
    feature_schema: str
    feature_vector: tuple[float, ...]
    quality: float
    extraction_status: str
    missing_reason: str | None

    def to_online_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "feature_schema": self.feature_schema,
            "feature_vector": list(self.feature_vector),
            "quality": self.quality,
            "extraction_status": self.extraction_status,
            "missing_reason": self.missing_reason,
        }


class DeviceRffProfileRegistry:
    _FEATURE_RANGES = (
        (-12.0, 12.0), (-1.2, 1.2), (-4.0, 4.0),
        (-0.08, 0.08), (-0.08, 0.08), (0.92, 1.08),
        (-3.0, 3.0), (-8.0, 8.0),
    )

    def __init__(self, rng_registry: RNGRegistry) -> None:
        self._rng_registry = rng_registry
        self._profiles: dict[int, DeviceRffProfile] = {}

    def ensure(self, device_id: int) -> DeviceRffProfile:
        if not _device_id(device_id):
            raise ValueError("device_id must be an integer")
        existing = self._profiles.get(device_id)
        if existing is not None:
            return existing
        rng = self._rng_registry.python(f"rff-profile:{device_id}")
        baseline = tuple(round(rng.uniform(lower, upper), 6)
                         for lower, upper in self._FEATURE_RANGES)
        profile = DeviceRffProfile(device_id, RFF_FEATURE_SCHEMA, baseline)
        self._profiles[device_id] = profile
        return profile


class RffObservationGenerator:
    _DRIFT_SIGMA = (0.03, 0.005, 0.015, 0.0004, 0.0004, 0.0005, 0.01, 0.02)
    _NOISE_SIGMA = (0.20, 0.03, 0.08, 0.002, 0.002, 0.003, 0.05, 0.10)
    _DRIFT_RETENTION = 0.98
    _REFERENCE_QUALITY = 0.95
    _CHANNEL_RESIDUAL_SCALE = 0.25

    @classmethod
    def enrollment_noise_std(cls, feature_index: int) -> float:
        return cls._NOISE_SIGMA[feature_index] * math.sqrt(
            cls._REFERENCE_QUALITY ** -2 + cls._CHANNEL_RESIDUAL_SCALE ** 2
        )

    def __init__(
        self,
        registry: DeviceRffProfileRegistry,
        rng_registry: RNGRegistry,
        quality_threshold: float = 0.45,
    ) -> None:
        self._registry = registry
        self._rng_registry = rng_registry
        self._quality_threshold = _quality_threshold(quality_threshold)
        self._drift: dict[int, tuple[float, tuple[float, ...]]] = {}
        self._receiver_biases: dict[int, tuple[float, ...]] = {}

    def receiver_bias(self, receiver_id: int) -> tuple[float, ...]:
        if not _device_id(receiver_id):
            raise ValueError("receiver_id must be an integer")
        cached = self._receiver_biases.get(receiver_id)
        if cached is not None:
            return cached
        rng = self._rng_registry.python(f"rff-receiver-bias:{receiver_id}")
        bias = tuple(rng.gauss(0.0, sigma * 0.5) for sigma in self._NOISE_SIGMA)
        self._receiver_biases[receiver_id] = bias
        return bias

    def _device_drift(self, device_id: int, sim_time_s: float) -> tuple[float, ...]:
        previous_time, previous = self._drift.get(device_id, (0.0, (0.0,) * 8))
        elapsed = sim_time_s - previous_time
        if elapsed == 0.0:
            return previous
        # Fractional-time AR(1): the one-second innovation has _DRIFT_SIGMA;
        # multiple receivers at the same timestamp share one device state.
        retention = self._DRIFT_RETENTION ** elapsed
        innovation_scale = math.sqrt(
            -math.expm1(2.0 * elapsed * math.log(self._DRIFT_RETENTION))
            / (1.0 - self._DRIFT_RETENTION ** 2)
        )
        rng = self._rng_registry.python(f"rff-drift:{device_id}")
        drift = tuple(retention * value + rng.gauss(0.0, sigma * innovation_scale)
                      for value, sigma in zip(previous, self._DRIFT_SIGMA))
        self._drift[device_id] = (sim_time_s, drift)
        return drift

    def observe(
        self, *, actual_device_id: int, receiver_id: int,
        sim_time_s: float, sinr_db: float | None,
        measurement_quality: float | None, sample_id: str,
    ) -> RffObservation:
        def unavailable(reason: str) -> RffObservation:
            return RffObservation(
                sample_id if isinstance(sample_id, str) else "",
                RFF_FEATURE_SCHEMA, (), 0.0, "UNAVAILABLE", reason,
            )

        if not _device_id(actual_device_id) or not _device_id(receiver_id):
            return unavailable("INVALID_DEVICE_OR_RECEIVER_ID")
        if not isinstance(sample_id, str) or not sample_id:
            return unavailable("INVALID_SAMPLE_ID")
        if not _finite(sim_time_s) or sim_time_s < 0.0:
            return unavailable("INVALID_SIM_TIME")
        if sinr_db is None or measurement_quality is None:
            return unavailable("PHY_QUALITY_UNAVAILABLE")
        if not _finite(sinr_db) or not _finite(measurement_quality):
            return unavailable("INVALID_PHY_QUALITY")
        if sim_time_s < self._drift.get(actual_device_id, (0.0, ()))[0]:
            return unavailable("NON_MONOTONIC_SIM_TIME")
        sinr_factor = max(0.0, min(1.0, (sinr_db + 5.0) / 25.0))
        quality = max(0.0, min(1.0, measurement_quality * sinr_factor))
        profile = self._registry.ensure(actual_device_id)
        bias = self.receiver_bias(receiver_id)
        drift = self._device_drift(actual_device_id, sim_time_s)
        noise_rng = self._rng_registry.python(f"rff-online:{actual_device_id}:{receiver_id}")
        channel_rng = self._rng_registry.python(f"rff-channel:{actual_device_id}:{receiver_id}")
        values = tuple(
            baseline + bias[index] + drift[index]
            + channel_rng.gauss(0.0, sigma * self._CHANNEL_RESIDUAL_SCALE)
            + noise_rng.gauss(0.0, sigma / max(quality, 0.05))
            for index, (baseline, sigma) in enumerate(zip(profile.baseline, self._NOISE_SIGMA))
        )
        status = "AVAILABLE" if quality >= self._quality_threshold else "LOW_QUALITY"
        reason = "OK" if status == "AVAILABLE" else "QUALITY_BELOW_THRESHOLD"
        return RffObservation(sample_id, RFF_FEATURE_SCHEMA, values, quality, status, reason)


@dataclass(frozen=True, slots=True)
class RffTemplate:
    receiver_id: int
    device_id: int
    feature_schema: str
    feature_mean: tuple[float, ...]
    feature_std: tuple[float, ...]
    sample_count: int


@dataclass(frozen=True, slots=True)
class RffIdentificationResult:
    identity_result: str
    predicted_device_id: int | None
    claimed_link_sender_id: int | None
    distance: float | None
    threshold: float
    confidence: float | None
    quality: float | None
    reason: str

    def to_security_state(self) -> dict[str, Any]:
        return {
            "rff_identity_result": self.identity_result,
            "rff_predicted_device_id": self.predicted_device_id,
            "rff_claimed_link_sender_id": self.claimed_link_sender_id,
            "rff_distance": self.distance,
            "rff_threshold": self.threshold,
            "rff_identity_confidence": self.confidence,
            "rff_quality": self.quality,
            "rff_reason": self.reason,
        }


class ReceiverRffTemplateStore:
    _STD_FLOOR = (0.10, 0.015, 0.04, 0.001, 0.001, 0.0015, 0.025, 0.05)

    def __init__(
        self, rng_registry: RNGRegistry, observation_generator: RffObservationGenerator,
        *, quality_threshold: float = 0.45, distance_threshold: float = 3.0,
        min_identity_margin: float = 0.5,
    ) -> None:
        self._rng_registry = rng_registry
        self._observation_generator = observation_generator
        self._quality_threshold = _quality_threshold(quality_threshold)
        if not _finite(distance_threshold) or distance_threshold <= 0:
            raise ValueError("distance_threshold must be finite and positive")
        if not _finite(min_identity_margin) or min_identity_margin < 0:
            raise ValueError("min_identity_margin must be finite and nonnegative")
        self._distance_threshold = float(distance_threshold)
        self._min_identity_margin = float(min_identity_margin)
        self._templates: dict[tuple[int, int], RffTemplate] = {}

    def enroll(
        self, receiver_id: int, device_id: int,
        profile: DeviceRffProfile, sample_count: int,
    ) -> RffTemplate:
        if not _device_id(receiver_id) or receiver_id < 0:
            raise ValueError("receiver_id must identify a legitimate receiver")
        if not _device_id(device_id) or device_id < 0:
            raise ValueError("external devices cannot be enrolled")
        if (not isinstance(profile, DeviceRffProfile) or profile.device_id != device_id
                or profile.feature_schema != RFF_FEATURE_SCHEMA or not _vector(profile.baseline)):
            raise ValueError("invalid device profile")
        _sample_count(sample_count)
        rng = self._rng_registry.python(f"rff-enroll:{receiver_id}:{device_id}")
        bias = self._observation_generator.receiver_bias(receiver_id)
        columns = [
            [baseline + bias[index] + rng.gauss(
                0.0, self._observation_generator.enrollment_noise_std(index),
            )
             for _ in range(sample_count)]
            for index, baseline in enumerate(profile.baseline)
        ]
        template = RffTemplate(
            receiver_id, device_id, RFF_FEATURE_SCHEMA,
            tuple(statistics.fmean(column) for column in columns),
            tuple(max(statistics.pstdev(column), self._STD_FLOOR[index])
                  for index, column in enumerate(columns)),
            sample_count,
        )
        self._templates[(receiver_id, device_id)] = template
        return template

    def templates_for_receiver(self, receiver_id: int) -> tuple[RffTemplate, ...]:
        return tuple(template for (stored_receiver, _), template in sorted(self._templates.items())
                     if stored_receiver == receiver_id)

    def is_whitelisted(self, receiver_id: int, device_id: int) -> bool:
        if not _device_id(receiver_id) or not _device_id(device_id):
            return False
        return (receiver_id, device_id) in self._templates

    @staticmethod
    def _valid_template(template: Any, receiver_id: int, device_id: int) -> bool:
        return (
            isinstance(template, RffTemplate)
            and _device_id(template.receiver_id) and template.receiver_id == receiver_id
            and _device_id(template.device_id) and template.device_id == device_id
            and template.device_id >= 0
            and template.feature_schema == RFF_FEATURE_SCHEMA
            and _vector(template.feature_mean) and _vector(template.feature_std)
            and all(std > 0 for std in template.feature_std)
            and _device_id(template.sample_count) and template.sample_count > 0
        )

    def identify(
        self, receiver_id: int, claimed_link_sender_id: int | None,
        observation: RffObservation | None,
    ) -> RffIdentificationResult:
        claim = claimed_link_sender_id if _device_id(claimed_link_sender_id) else None
        quality = None

        def result(
            status: str, reason: str, *, predicted: int | None = None,
            distance: float | None = None, confidence: float | None = None,
        ) -> RffIdentificationResult:
            return RffIdentificationResult(
                status, predicted, claim, distance, self._distance_threshold,
                confidence, quality, reason,
            )

        if not _device_id(receiver_id) or receiver_id < 0:
            return result("UNAVAILABLE", "INVALID_RECEIVER_ID")
        if claimed_link_sender_id is not None and claim is None:
            return result("UNAVAILABLE", "INVALID_CLAIMED_LINK_SENDER_ID")
        if observation is None:
            return result("UNAVAILABLE", "OBSERVATION_UNAVAILABLE")
        if not isinstance(observation, RffObservation):
            return result("UNAVAILABLE", "INVALID_OBSERVATION")
        if not _finite(observation.quality) or not 0 <= observation.quality <= 1:
            return result("UNAVAILABLE", "INVALID_OBSERVATION_QUALITY")
        quality = float(observation.quality)
        if observation.feature_schema != RFF_FEATURE_SCHEMA:
            return result("UNAVAILABLE", "UNSUPPORTED_FEATURE_SCHEMA")
        if not isinstance(observation.sample_id, str) or not observation.sample_id:
            return result("UNAVAILABLE", "INVALID_SAMPLE_ID")
        if observation.extraction_status not in ("AVAILABLE", "LOW_QUALITY", "UNAVAILABLE"):
            return result("UNAVAILABLE", "INVALID_EXTRACTION_STATUS")
        if observation.extraction_status == "UNAVAILABLE":
            reason = observation.missing_reason
            return result("UNAVAILABLE", reason if isinstance(reason, str) and reason
                          else "OBSERVATION_UNAVAILABLE")
        if not _vector(observation.feature_vector):
            return result("UNAVAILABLE", "INVALID_FEATURE_VECTOR")
        if observation.extraction_status == "LOW_QUALITY" or quality < self._quality_threshold:
            return result("LOW_QUALITY", "QUALITY_BELOW_THRESHOLD")

        distances = []
        for (stored_receiver, device_id), template in self._templates.items():
            if stored_receiver != receiver_id:
                continue
            if not self._valid_template(template, receiver_id, device_id):
                return result("UNAVAILABLE", "INVALID_TEMPLATE")
            standardized = tuple(
                (value - mean) / max(std, floor)
                for value, mean, std, floor in zip(
                    observation.feature_vector, template.feature_mean,
                    template.feature_std, self._STD_FLOOR,
                )
            )
            scale = max(abs(value) for value in standardized)
            if not math.isfinite(scale):
                return result("UNAVAILABLE", "NONFINITE_TEMPLATE_DISTANCE")
            distance = scale * math.sqrt(statistics.fmean(
                (value / scale) ** 2 for value in standardized
            )) if scale else 0.0
            distances.append((distance, device_id))
        if not distances:
            return result("UNKNOWN", "NO_ENROLLED_TEMPLATES")
        distances.sort()
        nearest_distance, predicted = distances[0]
        margin = distances[1][0] - nearest_distance if len(distances) > 1 else None
        margin_factor = (1.0 if margin is None else
                         1.0 / (1.0 + self._min_identity_margin / margin) if margin > 0 else 0.0)
        confidence = quality * max(0.0, 1.0 - nearest_distance / self._distance_threshold) * margin_factor
        confidence = max(0.0, min(1.0, confidence))
        if nearest_distance > self._distance_threshold:
            return result("UNKNOWN", "NO_TEMPLATE_WITHIN_THRESHOLD",
                          distance=nearest_distance, confidence=confidence)
        if margin is not None and margin < self._min_identity_margin:
            return result("AMBIGUOUS", "CANDIDATES_TOO_CLOSE",
                          distance=nearest_distance, confidence=confidence)
        if claim is None:
            return result("UNKNOWN", "CLAIMED_LINK_SENDER_UNAVAILABLE", predicted=predicted,
                          distance=nearest_distance, confidence=confidence)
        status = "MATCH" if predicted == claim else "MISMATCH"
        return result(status, "NEAREST_TEMPLATE_ACCEPTED", predicted=predicted,
                      distance=nearest_distance, confidence=confidence)


class RffService:
    """Simulator-facing observation API and observation-only identification API."""

    def __init__(
        self, rng_registry: RNGRegistry, enrollment_samples: int = 20,
        quality_threshold: float = 0.45, distance_threshold: float = 3.0,
        min_identity_margin: float = 0.5,
    ) -> None:
        self._enrollment_samples = _sample_count(enrollment_samples)
        self._registry = DeviceRffProfileRegistry(rng_registry)
        self._registered_devices: set[int] = set()
        self._observation_generator = RffObservationGenerator(
            self._registry, rng_registry, quality_threshold,
        )
        self.template_store = ReceiverRffTemplateStore(
            rng_registry, self._observation_generator,
            quality_threshold=quality_threshold, distance_threshold=distance_threshold,
            min_identity_margin=min_identity_margin,
        )

    def register_device(self, device_id: int) -> DeviceRffProfile:
        profile = self._registry.ensure(device_id)
        self._registered_devices.add(device_id)
        return profile

    def enroll(self, *, receiver_id: int, device_id: int) -> RffTemplate:
        if not _device_id(device_id) or device_id < 0:
            raise ValueError("external devices cannot be enrolled")
        if device_id not in self._registered_devices:
            raise ValueError("device must be explicitly registered before enrollment")
        return self.template_store.enroll(
            receiver_id, device_id, self._registry.ensure(device_id), self._enrollment_samples,
        )

    def observe(
        self, *, actual_device_id: int, receiver_id: int,
        sim_time_s: float, sinr_db: float | None,
        measurement_quality: float | None, sample_id: str,
    ) -> RffObservation:
        return self._observation_generator.observe(
            actual_device_id=actual_device_id, receiver_id=receiver_id,
            sim_time_s=sim_time_s, sinr_db=sinr_db,
            measurement_quality=measurement_quality, sample_id=sample_id,
        )

    def identify(
        self, receiver_id: int, claimed_link_sender_id: int | None,
        observation: RffObservation | None,
    ) -> RffIdentificationResult:
        return self.template_store.identify(receiver_id, claimed_link_sender_id, observation)
