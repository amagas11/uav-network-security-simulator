"""Observer-local rolling traffic statistics.

Only events actually produced for an observer enter that observer's state.  The
accumulator never receives attack labels or simulator-global traffic truth.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque


@dataclass(slots=True)
class _Arrival:
    sim_time_s: float
    packet_size_bytes: int
    decode_success: bool
    latency_ms: float | None
    duplicate: int = 0


@dataclass(slots=True)
class _SequenceState:
    highest: int | None = None
    seen: set[int] = field(default_factory=set)
    # Missing sequence -> local time at which the forward gap was observed.
    # ``sequence_gap_count`` is a recent-window statistic, not lifetime state.
    missing: dict[int, float] = field(default_factory=dict)


class LocalTrafficAccumulator:
    """Maintains local receive statistics with an explicit recent window."""

    def __init__(self, default_window_s: float = 1.0, sequence_history: int = 512) -> None:
        if default_window_s <= 0:
            raise ValueError("default_window_s must be positive")
        self.default_window_s = float(default_window_s)
        self.sequence_history = max(32, int(sequence_history))
        self._arrivals: dict[int, Deque[_Arrival]] = defaultdict(deque)
        self._last_arrival: dict[tuple[Any, ...], float] = {}
        self._sequences: dict[tuple[Any, ...], _SequenceState] = {}

    @staticmethod
    def _stream_key(event: dict[str, Any]) -> tuple[Any, ...]:
        packet = event["online_features"]["packet"]
        return (
            event["observer_node_id"],
            "RX",
            packet.get("packet_type"),
            packet.get("claimed_src_id"),
            packet.get("session_id"),
            str(packet.get("key_epoch")),
        )

    def enrich(self, event: dict[str, Any]) -> None:
        """Update state from one local event and attach the current snapshot."""

        observer_id = int(event["observer_node_id"])
        now_s = float(event["sim_time_s"])
        event_type = str(event["event_type"])
        packet = event["online_features"]["packet"]

        if event_type in {"RX_SUCCESS", "RX_FAILURE"}:
            stream_key = self._stream_key(event)
            previous = self._last_arrival.get(stream_key)
            packet["inter_arrival_s"] = (
                None if previous is None else round(max(0.0, now_s - previous), 9)
            )
            self._last_arrival[stream_key] = now_s

            duplicate = 0
            sequence = packet.get("sequence_no")
            if isinstance(sequence, int):
                state = self._sequences.setdefault(stream_key, _SequenceState())
                if sequence in state.seen:
                    duplicate = 1
                else:
                    if state.highest is None:
                        state.highest = sequence
                    elif sequence > state.highest:
                        if sequence > state.highest + 1:
                            for missing in range(state.highest + 1, sequence):
                                state.missing[missing] = now_s
                        state.highest = sequence
                    else:
                        state.missing.pop(sequence, None)
                    state.seen.add(sequence)
                    cutoff = (state.highest or sequence) - self.sequence_history
                    state.seen = {value for value in state.seen if value >= cutoff}
                    state.missing = {
                        value: detected_at
                        for value, detected_at in state.missing.items()
                        if value >= cutoff
                    }

            raw_size = packet.get("packet_size_bytes")
            packet_size = int(raw_size) if isinstance(raw_size, (int, float)) else 0
            raw_latency = event["online_features"]["traffic"].get("latency_ms")
            latency = (
                float(raw_latency) if isinstance(raw_latency, (int, float)) else None
            )
            self._arrivals[observer_id].append(
                _Arrival(
                    sim_time_s=now_s,
                    packet_size_bytes=max(0, packet_size),
                    decode_success=event_type == "RX_SUCCESS",
                    latency_ms=latency,
                    duplicate=duplicate,
                )
            )

        snapshot = self.snapshot(observer_id, now_s, self.default_window_s)
        traffic = event["online_features"]["traffic"]
        for key in (
            "packet_rate_pps",
            "byte_rate_Bps",
            "duplicate_count",
            "sequence_gap_count",
            "latency_ms",
            "throughput_mbps",
        ):
            traffic[key] = snapshot[key]

    def snapshot(
        self, observer_id: int, now_s: float, window_s: float | None = None
    ) -> dict[str, Any]:
        width = float(window_s or self.default_window_s)
        if width <= 0:
            raise ValueError("window_s must be positive")
        cutoff = float(now_s) - width
        arrivals = self._arrivals.get(int(observer_id), deque())
        selected = [item for item in arrivals if item.sim_time_s >= cutoff - 1e-12]
        byte_count = sum(item.packet_size_bytes for item in selected)
        successful_bytes = sum(
            item.packet_size_bytes for item in selected if item.decode_success
        )
        latencies = [
            item.latency_ms
            for item in selected
            if item.decode_success and item.latency_ms is not None
        ]
        failures = sum(not item.decode_success for item in selected)
        gaps = sum(
            sum(detected_at >= cutoff - 1e-12 for detected_at in state.missing.values())
            for key, state in self._sequences.items()
            if key[0] == int(observer_id)
        )
        return {
            "window_s": width,
            "sample_count": len(selected),
            "packet_rate_pps": len(selected) / width,
            "byte_rate_Bps": byte_count / width,
            "duplicate_count": sum(item.duplicate for item in selected),
            "sequence_gap_count": gaps,
            "latency_ms": sum(latencies) / len(latencies) if latencies else None,
            "throughput_mbps": successful_bytes * 8.0 / width / 1e6,
            "error_rate": failures / len(selected) if selected else 0.0,
        }

    def reset(self) -> None:
        self._arrivals.clear()
        self._last_arrival.clear()
        self._sequences.clear()
