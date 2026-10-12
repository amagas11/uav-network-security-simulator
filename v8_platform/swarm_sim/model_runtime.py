"""Fault and timeout boundary for externally supplied C model adapters."""

from __future__ import annotations

from copy import deepcopy
from queue import Empty, Queue
from itertools import count
from threading import BoundedSemaphore, Lock, Thread
from time import perf_counter
from typing import Any, Callable

from .adapters import ModelAdapter, ModelResult
from .simulation import RunContext, SCHEMA_VERSION


class ModelExecutionSupervisor:
    """A bounded daemon worker generation owned by exactly one runtime.

    Python cannot safely kill an arbitrary stuck extension call.  A timed-out
    adapter is therefore disabled for its run, while the next independent run
    receives a fresh supervisor and cannot inherit exhausted worker capacity.
    """

    _generation_ids = count(1)

    def __init__(self, workers: int = 8) -> None:
        if workers < 1:
            raise ValueError("model supervisor requires at least one worker")
        self.workers = workers
        self.generation_id = next(self._generation_ids)
        self.closed = False
        self._capacity = BoundedSemaphore(workers)
        self._tasks: Queue[
            tuple[Callable[..., Any], tuple[Any, ...], Queue[tuple[str, Any]]] | None
        ] = Queue(maxsize=workers)
        self._threads: list[Thread] = []
        for index in range(workers):
            worker = Thread(
                target=self._worker_loop,
                name=(
                    f"safe-model-worker-run-{self.generation_id}-{index + 1}"
                ),
                daemon=True,
            )
            worker.start()
            self._threads.append(worker)

    def submit(
        self,
        function: Callable[..., Any],
        args: tuple[Any, ...],
        response: Queue[tuple[str, Any]],
    ) -> bool:
        if self.closed:
            return False
        if not self._capacity.acquire(blocking=False):
            return False
        try:
            self._tasks.put_nowait((function, args, response))
        except Exception:
            self._capacity.release()
            raise
        return True

    def _worker_loop(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                return
            function, args, response = task
            try:
                try:
                    result = ("OK", function(*args))
                except Exception as exc:  # third-party boundary by design
                    result = ("EXCEPTION", exc)
                response.put(result)
            finally:
                self._capacity.release()

    def close(self) -> None:
        # Running calls are deliberately not force-killed.  Marking this
        # generation closed prevents new work; daemon workers are reclaimed
        # naturally after cooperative calls return.
        self.closed = True
        for _ in range(self.workers):
            try:
                self._tasks.put_nowait(None)
            except Exception:
                break
        for worker in self._threads:
            worker.join(timeout=0.02)


def _safe_error_summary(exc: Exception) -> str:
    """Return a useful diagnostic without copying provider exception payloads."""

    return f"{type(exc).__name__}: external adapter call failed"


class SafeModelAdapterRunner:
    """Run one external adapter behind a bounded, fail-closed worker.

    Calls share the owning runtime's bounded daemon-worker generation and each
    adapter permits at most one call in flight. After a timeout or exception that
    adapter is disabled for the rest of the run. A permanently blocked third-party
    call therefore cannot consume execution capacity belonging to a later runtime.
    Wall time is used only as a software deadline and never advances
    ``SimulationClock``.
    """

    implementation_status = "B_SAFE_MODEL_BOUNDARY"

    def __init__(
        self,
        name: str,
        adapter: ModelAdapter,
        context: RunContext,
        *,
        timeout_ms: float,
        supervisor: ModelExecutionSupervisor,
    ) -> None:
        if timeout_ms <= 0:
            raise ValueError("model inference timeout must be positive")
        self.name = str(name)
        self.adapter = adapter
        self.context = context
        self.timeout_ms = float(timeout_ms)
        self.supervisor = supervisor
        declared = getattr(adapter, "accepted_event_types", None)
        if declared is not None:
            self.accepted_event_types = frozenset(
                str(item).upper() for item in declared
            )
        self._call_lock = Lock()
        self._disabled = False
        self._failure_code: str | None = None
        self._failure_summary: str | None = None
        self._failure_time_ms: float | None = None
        self._failure_pending = False
        self._model_name = str(getattr(adapter, "name", self.name))
        self._model_version = getattr(adapter, "model_version", None)
        self._last_health: dict[str, Any] | None = None
    def _mark_failure(
        self, code: str, *, summary: str, elapsed_ms: float
    ) -> None:
        self._disabled = True
        self._failure_code = code
        self._failure_summary = summary[:240]
        self._failure_time_ms = max(0.0, float(elapsed_ms))
        self._failure_pending = True

    def _invoke(
        self,
        operation: str,
        function: Callable[..., Any],
        *args: Any,
    ) -> tuple[bool, Any]:
        if self._disabled:
            return False, None
        with self._call_lock:
            if self._disabled:
                return False, None
            response: Queue[tuple[str, Any]] = Queue(maxsize=1)
            started = perf_counter()
            if not self.supervisor.submit(function, args, response):
                self._mark_failure(
                    (
                        "MODEL_RUNTIME_CLOSED"
                        if self.supervisor.closed
                        else "MODEL_RUNTIME_SATURATED"
                    ),
                    summary=(
                        "bounded model worker pool has no free slot; "
                        "the call was not submitted"
                    ),
                    elapsed_ms=(perf_counter() - started) * 1000.0,
                )
                return False, None
            try:
                status, value = response.get(timeout=self.timeout_ms / 1000.0)
            except Empty:
                elapsed = (perf_counter() - started) * 1000.0
                code = (
                    "MODEL_INFERENCE_TIMEOUT"
                    if operation == "observe"
                    else f"MODEL_{operation.upper()}_TIMEOUT"
                )
                self._mark_failure(
                    code,
                    summary=f"{operation} exceeded configured {self.timeout_ms:g} ms deadline",
                    elapsed_ms=elapsed,
                )
                return False, None
            elapsed = (perf_counter() - started) * 1000.0
            if status == "EXCEPTION":
                code = f"MODEL_{operation.upper()}_EXCEPTION"
                self._mark_failure(
                    code,
                    summary=_safe_error_summary(value),
                    elapsed_ms=elapsed,
                )
                return False, None
            return True, value

    def reset(self, run_info: dict[str, Any]) -> None:
        self._invoke("reset", self.adapter.reset, deepcopy(run_info))

    def _failure_result(self, event: dict[str, Any]) -> ModelResult | None:
        if not self._failure_pending or self._failure_code is None:
            return None
        self._failure_pending = False
        return ModelResult(
            schema_version=SCHEMA_VERSION,
            run_id=str(event.get("run_id", self.context.run_id)),
            result_id=self.context.ids.next("result"),
            observer_node_id=int(event.get("observer_node_id", 0)),
            decision_time_s=float(
                event.get("sim_time_s", self.context.clock.now_s)
            ),
            model_name=self._model_name,
            model_version=self._model_version,
            status="ERROR",
            predicted_label=None,
            scores=None,
            confidence=None,
            quality=None,
            recommended_action=None,
            evidence_event_ids=(
                [str(event["event_id"])] if event.get("event_id") else []
            ),
            inference_time_ms=self._failure_time_ms,
            error_code=self._failure_code,
            error_summary=self._failure_summary,
        )

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if self._disabled:
            failure = self._failure_result(event)
            return [failure] if failure is not None else []
        ok, raw = self._invoke("observe", self.adapter.observe, deepcopy(event))
        if not ok:
            failure = self._failure_result(event)
            return [failure] if failure is not None else []
        if raw is None:
            return []
        if not isinstance(raw, list) or not all(
            isinstance(item, ModelResult) for item in raw
        ):
            self._mark_failure(
                "MODEL_OBSERVE_INVALID_RESULT",
                summary="observe must return list[ModelResult]",
                elapsed_ms=0.0,
            )
            failure = self._failure_result(event)
            return [failure] if failure is not None else []
        return raw

    def health(self) -> dict[str, Any]:
        if self._disabled:
            return {
                "model_name": self._model_name,
                "model_version": self._model_version,
                "status": "ERROR",
                "error_code": self._failure_code,
                "error_summary": self._failure_summary,
                "implementation_status": self.implementation_status,
            }
        if self.supervisor.closed and self._last_health is not None:
            return deepcopy(self._last_health)
        ok, raw = self._invoke("health", self.adapter.health)
        if not ok:
            return self.health()
        if not isinstance(raw, dict):
            self._mark_failure(
                "MODEL_HEALTH_INVALID_RESULT",
                summary="health must return an object",
                elapsed_ms=0.0,
            )
            return self.health()
        result = deepcopy(raw)
        self._model_name = str(result.get("model_name") or self._model_name)
        self._model_version = result.get("model_version", self._model_version)
        provider_implementation_status = result.get(
            "implementation_status",
            getattr(self.adapter, "implementation_status", "EXTERNAL"),
        )
        result.setdefault("error_summary", None)
        result["provider_implementation_status"] = str(
            provider_implementation_status
        )
        result["implementation_status"] = self.implementation_status
        self._last_health = deepcopy(result)
        return result
