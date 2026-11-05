"""Receiver-local physical admission; no frames, application data or truth."""

from dataclasses import dataclass
import math

from .rff import RffIdentificationResult


def _number(value, name, minimum=0.0, maximum=None):
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or value < minimum
            or (maximum is not None and value > maximum)):
        raise ValueError(f"invalid {name}")
    return float(value)


@dataclass(frozen=True, slots=True)
class RffIngressDecision:
    identity_result: str
    policy_state: str
    would_drop: bool
    drop: bool
    confirmed_identity_anomaly: bool
    reason: str
    transition: str | None


class RffIngressPolicy:
    def __init__(self, *, policy_mode="OBSERVE_ONLY", quality_threshold=0.45,
                 queue_pressure_ratio=0.60, strict_hold_s=2.0,
                 strict_on_rate_alarm=True, rate_threshold_pps=8.0):
        if policy_mode not in ("OBSERVE_ONLY", "ENFORCE"):
            raise ValueError("invalid policy_mode")
        if not isinstance(strict_on_rate_alarm, bool):
            raise ValueError("invalid strict_on_rate_alarm")
        self.policy_mode = policy_mode
        self.quality_threshold = _number(quality_threshold, "quality_threshold", maximum=1)
        self.queue_pressure_ratio = _number(queue_pressure_ratio, "queue_pressure_ratio", maximum=1)
        self.strict_hold_s = _number(strict_hold_s, "strict_hold_s")
        self.rate_threshold_pps = _number(rate_threshold_pps, "rate_threshold_pps")
        if self.strict_hold_s == 0 or self.rate_threshold_pps == 0:
            raise ValueError("hold duration and rate threshold must be positive")
        self.strict_on_rate_alarm = strict_on_rate_alarm
        self.state = "NORMAL"
        self.strict_since_s = None
        self.clear_since_s = None
        self._last_time_s = 0.0

    def refresh(self, *, sim_time_s, queue_ratio, packet_rate_pps):
        now = _number(sim_time_s, "sim_time_s")
        queue = _number(queue_ratio, "queue_ratio", maximum=1)
        rate = _number(packet_rate_pps, "packet_rate_pps")
        if now < self._last_time_s:
            raise ValueError("simulation time cannot regress")
        self._last_time_s = now
        pressure = (queue >= self.queue_pressure_ratio
                    or (self.strict_on_rate_alarm and rate >= self.rate_threshold_pps))
        if pressure:
            self.clear_since_s = None
            if self.state == "NORMAL":
                self.state = "RFF_STRICT_WHITELIST"
                self.strict_since_s = now
                return "ENTER_STRICT"
        elif self.state == "RFF_STRICT_WHITELIST":
            if self.clear_since_s is None:
                self.clear_since_s = now
            if now - self.clear_since_s >= self.strict_hold_s - 1e-12:
                self.state = "NORMAL"
                self.strict_since_s = None
                self.clear_since_s = None
                return "EXIT_STRICT"
        return None

    def evaluate(self, *, sim_time_s, identification: RffIdentificationResult,
                 claimed_is_whitelisted, predicted_is_whitelisted,
                 queue_ratio, packet_rate_pps):
        if not isinstance(identification, RffIdentificationResult):
            raise ValueError("identification must be an RFF result")
        if not isinstance(claimed_is_whitelisted, bool) or not isinstance(predicted_is_whitelisted, bool):
            raise ValueError("whitelist membership must be boolean")
        transition = self.refresh(sim_time_s=sim_time_s, queue_ratio=queue_ratio,
                                  packet_rate_pps=packet_rate_pps)
        result = identification
        quality = result.quality
        good_quality = (isinstance(quality, (int, float)) and not isinstance(quality, bool)
                        and math.isfinite(quality) and self.quality_threshold <= quality <= 1)
        claim, predicted = result.claimed_link_sender_id, result.predicted_device_id
        has_claim = isinstance(claim, int) and not isinstance(claim, bool)
        has_prediction = isinstance(predicted, int) and not isinstance(predicted, bool)
        confirmed = bool(good_quality and has_claim and (
            (result.identity_result == "MISMATCH" and has_prediction
             and predicted != claim and predicted_is_whitelisted)
            or (result.identity_result == "UNKNOWN" and predicted is None
                and result.reason == "NO_TEMPLATE_WITHIN_THRESHOLD")
        ))
        matched = (good_quality and result.identity_result == "MATCH" and has_claim
                   and has_prediction and predicted == claim
                   and claimed_is_whitelisted and predicted_is_whitelisted)
        unverified_strict = self.state == "RFF_STRICT_WHITELIST" and not matched
        would_drop = bool(confirmed or unverified_strict)
        reason = ("RFF_IDENTITY_MISMATCH" if confirmed else "RFF_STRICT_UNVERIFIED"
                  if unverified_strict else "RFF_WHITELIST_MATCH" if matched else "RFF_UNVERIFIED")
        return RffIngressDecision(
            result.identity_result, self.state, would_drop,
            would_drop and self.policy_mode == "ENFORCE", confirmed, reason, transition,
        )
