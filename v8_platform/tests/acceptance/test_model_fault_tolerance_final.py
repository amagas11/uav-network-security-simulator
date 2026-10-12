"""Acceptance evidence for V6P-MODEL-FAULT-001 and V6P-MODEL-TIMEOUT-001."""

from __future__ import annotations

import time
import threading
from typing import Any

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.simulation import SCHEMA_VERSION


class FaultAdapter:
    name = "bilstm-fault-fixture"

    def __init__(self, mode: str, accepted: set[str] | None = None) -> None:
        self.mode = mode
        self.accepted_event_types = frozenset(accepted or {"QUEUE_SAMPLE"})
        self.observe_calls = 0

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        if self.mode == "reset_exception":
            raise RuntimeError("reset boom")

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        self.observe_calls += 1
        if self.mode == "observe_exception":
            raise RuntimeError("model boom")
        if self.mode == "timeout":
            time.sleep(0.08)
            return []
        if self.mode == "no_result":
            return []
        if self.mode in {"error_result", "unavailable_result"}:
            status = "ERROR" if self.mode == "error_result" else "UNAVAILABLE"
            return [
                ModelResult(
                    schema_version=SCHEMA_VERSION,
                    run_id=event["run_id"],
                    result_id=f"fixture-{self.mode}",
                    observer_node_id=event["observer_node_id"],
                    decision_time_s=event["sim_time_s"],
                    model_name=self.name,
                    model_version="test-v1",
                    status=status,
                    predicted_label=None,
                    scores=None,
                    confidence=None,
                    quality=None,
                    recommended_action=None,
                    evidence_event_ids=[event["event_id"]],
                    inference_time_ms=0.0,
                    error_code=f"MODEL_RETURNED_{status}",
                )
            ]
        return []

    def health(self) -> dict[str, Any]:
        if self.mode == "health_exception":
            raise RuntimeError("health boom")
        return {
            "model_name": self.name,
            "model_version": "test-v1",
            "status": "OK",
            "error_code": None,
        }


class MessageObserveFaultAdapter(FaultAdapter):
    def __init__(self) -> None:
        super().__init__("observe_exception", {"AUTH_RESULT"})

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if event.get("message_id") is None:
            return []
        return super().observe(event)


def _error_results(runtime: PlatformRuntime) -> list[dict[str, Any]]:
    return [
        event["extensions"]["model_result"]
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("model_result", {}).get("status")
        in {"ERROR", "UNAVAILABLE"}
    ]


def test_model_reset_exception_isolated_and_recorded_without_false_normal():
    adapter = FaultAdapter("reset_exception", {"NODE_STATE"})
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False),
        run_id="model-reset-fault",
        model_adapters={"bilstm": adapter},
    )
    runtime.run_to_completion()

    health = runtime.model_status()["bilstm"]
    assert health["status"] == "ERROR"
    assert health["error_code"] == "MODEL_RESET_EXCEPTION"
    failures = _error_results(runtime)
    assert any(item["error_code"] == "MODEL_RESET_EXCEPTION" for item in failures)
    assert all(item.get("predicted_label") is None for item in failures)


def test_model_observe_exception_does_not_stop_rule_detection_or_run():
    adapter = MessageObserveFaultAdapter()
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.2,
            auto_traffic=False,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        run_id="model-observe-fault",
        model_adapters={"bilstm": adapter},
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "UNKNOWN_ID",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 0.8,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "parameters": {"claimed_src_id": 999},
        }
    )
    runtime.run_to_completion()

    assert runtime.status()["state"] == "COMPLETED"
    assert any(
        item["error_code"] == "MODEL_OBSERVE_EXCEPTION"
        for item in _error_results(runtime)
    )
    assert any(
        event.get("extensions", {}).get("model_result", {}).get("model_name")
        == "deterministic-rule"
        for event in runtime.events
    )


def test_model_health_exception_isolated_and_later_logged():
    adapter = FaultAdapter("health_exception")
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False),
        run_id="model-health-fault",
        model_adapters={"bilstm": adapter},
    )
    assert runtime.model_status()["bilstm"]["error_code"] == "MODEL_HEALTH_EXCEPTION"
    runtime.run_to_completion()
    assert any(
        item["error_code"] == "MODEL_HEALTH_EXCEPTION"
        for item in _error_results(runtime)
    )


def test_model_inference_timeout_is_bounded_and_disables_repeat_submissions():
    adapter = FaultAdapter("timeout")
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            auto_traffic=False,
            model_inference_timeout_ms=5.0,
        ),
        run_id="model-timeout",
        model_adapters={"bilstm": adapter},
    )
    runtime.schedule_attack(
        {
            "attack_family": "SPOOFING",
            "attack_subtype": "UNKNOWN_ID",
            "scheduled_start_s": 0.0,
            "impact_start_s": 0.2,
            "end_s": 0.6,
            "attacker_node_id": -1,
            "target_node_ids": [1],
            "parameters": {"claimed_src_id": 999},
        }
    )
    started = time.perf_counter()
    runtime.run_to_completion()
    elapsed_s = time.perf_counter() - started

    assert elapsed_s < 0.08
    assert adapter.observe_calls == 1
    assert runtime.model_status()["bilstm"]["error_code"] == "MODEL_INFERENCE_TIMEOUT"
    assert any(
        item["error_code"] == "MODEL_INFERENCE_TIMEOUT"
        for item in _error_results(runtime)
    )
    assert any(
        event.get("extensions", {}).get("model_result", {}).get("model_name")
        == "deterministic-rule"
        for event in runtime.events
    )
    assert DatasetLeakageAudit.audit_events(runtime.events).passed


@pytest.mark.parametrize(
    "mode, expected_status",
    (("error_result", "ERROR"), ("unavailable_result", "UNAVAILABLE")),
)
def test_model_declared_failure_is_logged_without_fabricated_normal(
    mode: str, expected_status: str
):
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False),
        run_id=f"model-{mode}",
        model_adapters={"bilstm": FaultAdapter(mode)},
    )
    runtime.run_to_completion()
    results = _error_results(runtime)
    assert any(item["status"] == expected_status for item in results)
    assert all(item.get("predicted_label") is None for item in results)


def test_model_no_result_is_a_valid_absence_not_a_normal_prediction():
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False),
        run_id="model-no-result",
        model_adapters={"bilstm": FaultAdapter("no_result")},
    )
    runtime.run_to_completion()
    assert not any(
        event.get("extensions", {}).get("source_adapter") == "bilstm"
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
    )


def test_model_runners_release_healthy_per_run_workers_after_completion():
    before = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("safe-model-worker-")
    }
    runtimes = [
        PlatformRuntime(
            RunConfig(duration_s=0.2, auto_traffic=False),
            run_id=f"model-pool-{index}",
            model_adapters={"bilstm": FaultAdapter("no_result")},
        )
        for index in range(20)
    ]
    for runtime in runtimes:
        runtime.run_to_completion()
    after = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("safe-model-worker-")
    }
    assert runtimes
    assert not (after - before)


def test_safe_wrapper_preserves_dispatcher_default_subscription_for_legacy_adapter():
    adapter = FaultAdapter("observe_exception")
    del adapter.accepted_event_types
    runtime = PlatformRuntime(
        RunConfig(duration_s=0.4, auto_traffic=False),
        run_id="model-default-subscription",
        model_adapters={"bilstm": adapter},
    )
    runtime.run_to_completion()
    assert adapter.observe_calls == 1
    assert any(
        item["error_code"] == "MODEL_OBSERVE_EXCEPTION"
        for item in _error_results(runtime)
    )
