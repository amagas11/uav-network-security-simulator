"""Single causal online-event router for external model adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adapters import ModelAdapter, ModelResult


DEFAULT_MODEL_SUBSCRIPTIONS: dict[str, frozenset[str]] = {
    "bilstm": frozenset(
        {
            "TX",
            "RX_SUCCESS",
            "RX_FAILURE",
            "PHY_SAMPLE",
            "QUEUE_SAMPLE",
            "NODE_STATE",
            "TOPOLOGY_UPDATE",
            "AUTH_RESULT",
        }
    ),
    "dueling_q": frozenset(
        {
            "PHY_SAMPLE",
            "QUEUE_SAMPLE",
            "NODE_STATE",
            "TOPOLOGY_UPDATE",
            "AUTH_RESULT",
            "MODEL_RESULT",
            "DEFENSE_RESULT",
        }
    ),
    "rff": frozenset({"RX_SUCCESS", "RX_FAILURE", "PHY_SAMPLE"}),
}


@dataclass(slots=True)
class DispatchedResult:
    adapter_name: str
    result: ModelResult


class OnlineEventDispatcher:
    """Route every stored event by adapter subscription.

    `MODEL_RESULT` is deliberately directional: BiLSTM and RFF results may
    feed Dueling-Q state construction, while a model never receives its own
    result and Dueling-Q results are terminal.  This both preserves causal
    composition and prevents result recursion.
    """

    def __init__(
        self,
        adapters: dict[str, ModelAdapter],
        *,
        allow_external_observer: bool = False,
    ) -> None:
        self.adapters = adapters
        self.allow_external_observer = bool(allow_external_observer)

    @staticmethod
    def _source_adapter(event: dict[str, Any]) -> str | None:
        extensions = event.get("extensions", {})
        explicit = extensions.get("source_adapter")
        if explicit:
            return str(explicit)
        result = extensions.get("model_result", {})
        model_name = str(result.get("model_name", "")).lower()
        if model_name.startswith("bilstm"):
            return "bilstm"
        if model_name.startswith("rff"):
            return "rff"
        if model_name.startswith("dueling"):
            return "dueling_q"
        return None

    @staticmethod
    def _subscriptions(name: str, adapter: ModelAdapter) -> frozenset[str]:
        declared = getattr(adapter, "accepted_event_types", None)
        if declared is not None:
            return frozenset(str(item).upper() for item in declared)
        return DEFAULT_MODEL_SUBSCRIPTIONS.get(name, frozenset())

    def dispatch(self, event: dict[str, Any]) -> list[DispatchedResult]:
        if (
            not self.allow_external_observer
            and str(event.get("observer_role", "")).upper() == "EXTERNAL"
        ):
            return []
        event_type = str(event.get("event_type", "")).upper()
        source = self._source_adapter(event) if event_type == "MODEL_RESULT" else None
        dispatched: list[DispatchedResult] = []
        for name, adapter in self.adapters.items():
            if event_type not in self._subscriptions(name, adapter):
                continue
            if event_type == "MODEL_RESULT":
                if source == name:
                    continue
                if name != "dueling_q" or source not in {"bilstm", "rff"}:
                    continue
            for result in adapter.observe(event):
                dispatched.append(DispatchedResult(name, result))
        return dispatched
