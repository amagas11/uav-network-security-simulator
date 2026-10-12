"""Pure flooding-defense state machine and token buckets."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
import math
from typing import Deque


class FloodDefenseState(str, Enum):
    NORMAL = "NORMAL"
    ALERT = "ALERT"
    LIMITING = "LIMITING"
    RECOVERING = "RECOVERING"


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    allowed: bool
    reason: str | None
    bucket_scope: str | None
    tokens_remaining: float | None


def _positive_finite(value: float, name: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


def _finite_time(now_s: float) -> float:
    if (
        not isinstance(now_s, (int, float))
        or isinstance(now_s, bool)
        or not math.isfinite(now_s)
    ):
        raise ValueError("simulation time must be finite")
    return float(now_s)


class TokenBucket:
    def __init__(
        self,
        *,
        refill_rate_per_s: float,
        capacity: float,
        bucket_scope: str | None = None,
    ) -> None:
        self.refill_rate_per_s = _positive_finite(
            refill_rate_per_s, "refill_rate_per_s"
        )
        self.capacity = _positive_finite(capacity, "capacity")
        self.bucket_scope = bucket_scope
        self._tokens = self.capacity
        self._last_time_s: float | None = None

    def _refill(self, now_s: float) -> None:
        now_s = _finite_time(now_s)
        if self._last_time_s is not None and now_s < self._last_time_s:
            raise ValueError("simulation time cannot decrease")
        if self._last_time_s is not None:
            elapsed_s = now_s - self._last_time_s
            self._tokens = min(
                self.capacity,
                self._tokens + elapsed_s * self.refill_rate_per_s,
            )
        self._last_time_s = now_s

    def _can_consume(self, amount: float) -> bool:
        return self._tokens >= amount

    def _consume(self, amount: float) -> None:
        self._tokens -= amount

    def admit(self, now_s: float, amount: float = 1.0) -> AdmissionDecision:
        amount = _positive_finite(amount, "amount")
        self._refill(now_s)
        if not self._can_consume(amount):
            return AdmissionDecision(
                allowed=False,
                reason="token_bucket_exhausted",
                bucket_scope=self.bucket_scope,
                tokens_remaining=self._tokens,
            )
        self._consume(amount)
        return AdmissionDecision(
            allowed=True,
            reason=None,
            bucket_scope=self.bucket_scope,
            tokens_remaining=self._tokens,
        )

    def refund(self, now_s: float, amount: float = 1.0) -> None:
        amount = _positive_finite(amount, "amount")
        self._refill(now_s)
        self._tokens = min(self.capacity, self._tokens + amount)

    def _snapshot(self) -> dict[str, object]:
        return {
            "capacity": self.capacity,
            "refill_rate_per_s": self.refill_rate_per_s,
            "tokens": self._tokens,
        }


class FloodDefenseController:
    def __init__(
        self,
        *,
        window_s: float,
        alert_threshold_pps: float,
        severe_multiplier: float,
        sustained_overload_s: float,
        recovery_multiplier: float,
        recovery_hold_s: float,
        token_refill_rate_pps: float,
        token_bucket_capacity: float,
        enabled: bool,
    ) -> None:
        self.window_s = _positive_finite(window_s, "window_s")
        self.alert_threshold_pps = _positive_finite(
            alert_threshold_pps, "alert_threshold_pps"
        )
        self.severe_multiplier = _positive_finite(
            severe_multiplier, "severe_multiplier"
        )
        if self.severe_multiplier < 1:
            raise ValueError("severe_multiplier must be at least 1")
        self.sustained_overload_s = _positive_finite(
            sustained_overload_s, "sustained_overload_s"
        )
        self.recovery_multiplier = _positive_finite(
            recovery_multiplier, "recovery_multiplier"
        )
        if self.recovery_multiplier >= 1:
            raise ValueError("recovery_multiplier must be below 1")
        self.recovery_hold_s = _positive_finite(
            recovery_hold_s, "recovery_hold_s"
        )
        self.token_refill_rate_pps = _positive_finite(
            token_refill_rate_pps, "token_refill_rate_pps"
        )
        self.token_bucket_capacity = _positive_finite(
            token_bucket_capacity, "token_bucket_capacity"
        )
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        self.enabled = enabled
        self.reset()

    @property
    def severe_threshold_pps(self) -> float:
        return self.alert_threshold_pps * self.severe_multiplier

    @property
    def recovery_threshold_pps(self) -> float:
        return self.alert_threshold_pps * self.recovery_multiplier

    def reset(self) -> None:
        self._arrivals: Deque[float] = deque()
        self._total_arrival_count = 0
        self._state = FloodDefenseState.NORMAL
        self._previous_state = FloodDefenseState.NORMAL
        self._state_entered_at_s: float | None = None
        self._overload_started_at_s: float | None = None
        self._recovery_started_at_s: float | None = None
        self._limiting_started_at_s: float | None = None
        self._recovered_at_s: float | None = None
        self._last_time_s: float | None = None
        self._receiver_global_bucket: TokenBucket | None = None
        self._ingress_buckets: dict[tuple[int, str], TokenBucket] = {}
        self._pre_auth_reservations: dict[tuple[int, str], set[str]] = {}
        self._authenticated_device_buckets: dict[int, TokenBucket] = {}
        self._pre_auth_drop_count = 0
        self._post_auth_drop_count = 0
        self._hmac_rejected_count = 0

    def _observe_time(self, now_s: float) -> float:
        now_s = _finite_time(now_s)
        if self._last_time_s is not None and now_s < self._last_time_s:
            raise ValueError("simulation time cannot decrease")
        self._last_time_s = now_s
        return now_s

    def _evict_old_arrivals(self, now_s: float) -> None:
        cutoff_s = now_s - self.window_s
        while self._arrivals and self._arrivals[0] < cutoff_s:
            self._arrivals.popleft()

    def _rate_pps(self) -> float:
        return len(self._arrivals) / self.window_s

    def _transition(self, state: FloodDefenseState, now_s: float) -> None:
        if state == self._state:
            return
        previous = self._state
        self._previous_state = previous
        self._state = state
        self._state_entered_at_s = now_s
        if state == FloodDefenseState.LIMITING:
            self._limiting_started_at_s = now_s
            self._recovered_at_s = None
        elif previous == FloodDefenseState.RECOVERING and state == FloodDefenseState.NORMAL:
            self._recovered_at_s = now_s
            self._receiver_global_bucket = None
            self._ingress_buckets.clear()
            self._authenticated_device_buckets.clear()
            self._pre_auth_reservations.clear()

    @staticmethod
    def _held_for(now_s: float, started_at_s: float, duration_s: float) -> bool:
        elapsed_s = now_s - started_at_s
        return elapsed_s > duration_s or math.isclose(
            elapsed_s, duration_s, rel_tol=0.0, abs_tol=1e-12
        )

    def _evaluate_state(self, now_s: float) -> None:
        if not self.enabled:
            self._state = FloodDefenseState.NORMAL
            self._previous_state = FloodDefenseState.NORMAL
            self._state_entered_at_s = None
            self._overload_started_at_s = None
            self._recovery_started_at_s = None
            return

        rate_pps = self._rate_pps()
        if self._state == FloodDefenseState.NORMAL:
            if rate_pps >= self.severe_threshold_pps:
                self._transition(FloodDefenseState.LIMITING, now_s)
            elif rate_pps >= self.alert_threshold_pps:
                self._transition(FloodDefenseState.ALERT, now_s)
                self._overload_started_at_s = (
                    now_s if rate_pps > self.alert_threshold_pps else None
                )
            return

        if self._state == FloodDefenseState.ALERT:
            if rate_pps >= self.severe_threshold_pps:
                self._overload_started_at_s = None
                self._transition(FloodDefenseState.LIMITING, now_s)
            elif rate_pps > self.alert_threshold_pps:
                if self._overload_started_at_s is None:
                    self._overload_started_at_s = now_s
                elif self._held_for(
                    now_s,
                    self._overload_started_at_s,
                    self.sustained_overload_s,
                ):
                    self._overload_started_at_s = None
                    self._transition(FloodDefenseState.LIMITING, now_s)
            elif rate_pps < self.alert_threshold_pps:
                self._overload_started_at_s = None
                self._transition(FloodDefenseState.NORMAL, now_s)
            else:
                self._overload_started_at_s = None
            return

        if self._state == FloodDefenseState.LIMITING:
            if rate_pps < self.recovery_threshold_pps:
                self._recovery_started_at_s = now_s
                self._transition(FloodDefenseState.RECOVERING, now_s)
            return

        if rate_pps >= self.alert_threshold_pps:
            self._recovery_started_at_s = None
            self._transition(FloodDefenseState.LIMITING, now_s)
        elif rate_pps < self.recovery_threshold_pps:
            if self._recovery_started_at_s is None:
                self._recovery_started_at_s = now_s
            elif self._held_for(
                now_s, self._recovery_started_at_s, self.recovery_hold_s
            ):
                self._recovery_started_at_s = None
                self._transition(FloodDefenseState.NORMAL, now_s)
        else:
            self._recovery_started_at_s = None

    def _update(self, now_s: float) -> float:
        now_s = self._observe_time(now_s)
        self._evict_old_arrivals(now_s)
        self._evaluate_state(now_s)
        return now_s

    def record_arrival(self, now_s: float) -> dict[str, object]:
        now_s = self._observe_time(now_s)
        self._evict_old_arrivals(now_s)
        self._evaluate_state(now_s)
        self._arrivals.append(now_s)
        self._total_arrival_count += 1
        self._evaluate_state(now_s)
        return self._snapshot()

    def record_hmac_rejection(self) -> None:
        self._hmac_rejected_count += 1

    def advance(self, now_s: float) -> dict[str, object]:
        now_s = self._update(now_s)
        if self._receiver_global_bucket is not None:
            self._receiver_global_bucket._refill(now_s)
        for ingress_key, bucket in list(self._ingress_buckets.items()):
            bucket._refill(now_s)
            if (
                bucket._tokens >= bucket.capacity
                and not self._pre_auth_reservations.get(ingress_key)
            ):
                self._ingress_buckets.pop(ingress_key)
        for bucket in self._authenticated_device_buckets.values():
            bucket._refill(now_s)
        return self._snapshot()

    def _new_bucket(self, scope: str) -> TokenBucket:
        return TokenBucket(
            refill_rate_per_s=self.token_refill_rate_pps,
            capacity=self.token_bucket_capacity,
            bucket_scope=scope,
        )

    @staticmethod
    def _unlimited_decision() -> AdmissionDecision:
        return AdmissionDecision(True, None, None, None)

    def admit_pre_auth(
        self,
        now_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str | None = None,
    ) -> AdmissionDecision:
        now_s = self._observe_time(now_s)
        if not self.enabled or self._state != FloodDefenseState.LIMITING:
            return self._unlimited_decision()
        if not isinstance(reservation_id, str) or not reservation_id:
            raise ValueError("reservation_id is required while limiting")

        if self._receiver_global_bucket is None:
            self._receiver_global_bucket = self._new_bucket("receiver_global")
        ingress_key = (link_sender_id, link_id)
        reservations = self._pre_auth_reservations.get(ingress_key)
        if reservations is not None and reservation_id in reservations:
            raise ValueError("reservation_id is already outstanding")
        receiver_bucket = self._receiver_global_bucket
        receiver_bucket._refill(now_s)

        if not receiver_bucket._can_consume(1.0):
            self._pre_auth_drop_count += 1
            return AdmissionDecision(
                False,
                "token_bucket_exhausted",
                "receiver_global",
                receiver_bucket._tokens,
            )
        ingress_bucket = self._ingress_buckets.get(ingress_key)
        if ingress_bucket is None:
            ingress_bucket = self._new_bucket("ingress")
            self._ingress_buckets[ingress_key] = ingress_bucket
        ingress_bucket._refill(now_s)
        if not ingress_bucket._can_consume(1.0):
            self._pre_auth_drop_count += 1
            return AdmissionDecision(
                False,
                "token_bucket_exhausted",
                "ingress",
                ingress_bucket._tokens,
            )

        receiver_bucket._consume(1.0)
        ingress_bucket._consume(1.0)
        if reservations is None:
            reservations = set()
            self._pre_auth_reservations[ingress_key] = reservations
        reservations.add(reservation_id)
        return AdmissionDecision(
            True,
            None,
            "receiver_global+ingress",
            min(receiver_bucket._tokens, ingress_bucket._tokens),
        )

    def admit_post_auth(
        self, now_s: float, authenticated_device_id: int
    ) -> AdmissionDecision:
        now_s = self._observe_time(now_s)
        if not self.enabled or self._state != FloodDefenseState.LIMITING:
            return self._unlimited_decision()

        bucket = self._authenticated_device_buckets.get(authenticated_device_id)
        if bucket is None:
            bucket = self._new_bucket("authenticated_device")
            self._authenticated_device_buckets[authenticated_device_id] = bucket
        decision = bucket.admit(now_s)
        if not decision.allowed:
            self._post_auth_drop_count += 1
        return decision

    def release_pre_auth(
        self,
        now_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str,
    ) -> None:
        now_s = self._observe_time(now_s)
        if (
            not self.enabled
            or self._state != FloodDefenseState.LIMITING
            or self._receiver_global_bucket is None
        ):
            return
        ingress_key = (link_sender_id, link_id)
        reservations = self._pre_auth_reservations.get(ingress_key)
        ingress_bucket = self._ingress_buckets.get(ingress_key)
        if (
            reservations is None
            or reservation_id not in reservations
            or ingress_bucket is None
        ):
            return
        self._receiver_global_bucket.refund(now_s)
        ingress_bucket.refund(now_s)
        reservations.remove(reservation_id)
        if not reservations:
            self._pre_auth_reservations.pop(ingress_key, None)

    def finalize_pre_auth(
        self,
        now_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str,
    ) -> None:
        self._observe_time(now_s)
        ingress_key = (link_sender_id, link_id)
        reservations = self._pre_auth_reservations.get(ingress_key)
        if reservations is None or reservation_id not in reservations:
            return
        reservations.remove(reservation_id)
        if not reservations:
            self._pre_auth_reservations.pop(ingress_key, None)

    def snapshot(self, now_s: float) -> dict[str, object]:
        now_s = _finite_time(now_s)
        if self._last_time_s is not None and now_s < self._last_time_s:
            raise ValueError("simulation time cannot decrease")
        return self._snapshot()

    def _snapshot(self) -> dict[str, object]:
        receiver_global = (
            None
            if self._receiver_global_bucket is None
            else self._receiver_global_bucket._snapshot()
        )
        ingress = []
        for (link_sender_id, link_id), bucket in sorted(
            self._ingress_buckets.items(), key=lambda item: item[0]
        ):
            ingress.append(
                {
                    "link_sender_id": link_sender_id,
                    "link_id": link_id,
                    **bucket._snapshot(),
                }
            )
        authenticated_devices = []
        for device_id, bucket in sorted(self._authenticated_device_buckets.items()):
            authenticated_devices.append(
                {"device_id": device_id, **bucket._snapshot()}
            )

        return {
            "enabled": self.enabled,
            "state": self._state.value,
            "previous_state": self._previous_state.value,
            "state_entered_at_s": self._state_entered_at_s,
            "last_observed_at_s": self._last_time_s,
            "window_s": self.window_s,
            "arrival_count": len(self._arrivals),
            "total_arrival_count": self._total_arrival_count,
            "rate_pps": self._rate_pps(),
            "alert_threshold_pps": self.alert_threshold_pps,
            "severe_threshold_pps": self.severe_threshold_pps,
            "recovery_threshold_pps": self.recovery_threshold_pps,
            "overload_started_at_s": self._overload_started_at_s,
            "recovery_started_at_s": self._recovery_started_at_s,
            "limiting_started_at_s": self._limiting_started_at_s,
            "recovered_at_s": self._recovered_at_s,
            "pre_auth_drop_count": self._pre_auth_drop_count,
            "post_auth_drop_count": self._post_auth_drop_count,
            "hmac_rejected_count": self._hmac_rejected_count,
            "buckets": {
                "receiver_global": receiver_global,
                "ingress": ingress,
                "authenticated_devices": authenticated_devices,
            },
        }
