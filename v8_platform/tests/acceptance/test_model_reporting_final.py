"""Acceptance evidence for V6P-MODEL-REPORTING-001."""

from __future__ import annotations

from typing import Any

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.simulation import SCHEMA_VERSION


class ObservableTelemetryModel:
    """A test adapter driven only by the authenticated payload it observes."""

    name = "bilstm-reporting-fixture"
    accepted_event_types = frozenset({"AUTH_RESULT"})

    def __init__(self, *, confidence: float = 0.99) -> None:
        self.confidence = confidence
        self.emitted = False

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.emitted = False

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        packet = event.get("online_features", {}).get("packet", {})
        numeric = packet.get("payload_numeric") or {}
        if (
            self.emitted
            or event.get("observer_node_id") != 1
            or event.get("message_id") is None
            or packet.get("packet_type") != "TELEMETRY"
            or float(numeric.get("altitude_m", 0.0)) < 140.0
        ):
            return []
        self.emitted = True
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id="model-reporting-result-1",
                observer_node_id=event["observer_node_id"],
                decision_time_s=event["sim_time_s"],
                model_name=self.name,
                model_version="test-v1",
                status="OK",
                predicted_label="FDI",
                scores={"FDI": self.confidence},
                confidence=self.confidence,
                quality=1.0,
                recommended_action="INCREASE_MONITORING",
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=0.2,
                error_code=None,
            )
        ]

    def health(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "model_version": "test-v1",
            "status": "OK",
            "error_code": None,
        }


def _runtime(run_id: str, *, confidence: float = 0.99, duration_s: float = 2.4):
    return PlatformRuntime(
        RunConfig.from_dict(
            {
                "seed": 7001,
                "duration_s": duration_s,
                "step_s": 0.2,
                "auto_traffic": False,
                "tx_service_per_step": 32,
                "rx_service_per_step": 32,
                "security_summary_window_s": 0.4,
                "traffic_specs": [
                    {
                        "source_node_id": 2,
                        "target_node_id": 1,
                        "packet_type": "TELEMETRY",
                        "start_s": 0.2,
                        "payload": {"altitude_m": 151.0, "battery_pct": 88.0},
                        "count": 1,
                        "interval_s": 0.2,
                        "sensitive": False,
                    }
                ],
            }
        ),
        run_id=run_id,
        model_adapters={"bilstm": ObservableTelemetryModel(confidence=confidence)},
    )


def _external_model_events(runtime: PlatformRuntime) -> list[dict[str, Any]]:
    return [
        event
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event.get("extensions", {}).get("source_adapter") == "bilstm"
        and event.get("extensions", {}).get("model_result", {}).get("status") == "OK"
    ]


def test_model_detection_and_executed_defense_traverse_leader_to_gcs_once():
    runtime = _runtime("model-report-e2e")
    runtime.run_to_completion()

    model_events = _external_model_events(runtime)
    assert len(model_events) == 1
    result_id = model_events[0]["extensions"]["model_result"]["result_id"]
    defenses = [
        event["extensions"]["defense_result"]
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and event.get("extensions", {}).get("decision_audit", {}).get("model_result_id")
        == result_id
    ]
    assert len(defenses) == 1
    assert defenses[0]["executed"] is True
    assert runtime.nodes[1].local_security_cache

    reports = [
        item
        for item in runtime.reporting.gcs_inbox
        if item.get("correlation_id") == result_id
    ]
    assert len(reports) == 1
    report = reports[0]
    assert report["decision_source"] == "MODEL"
    assert report["model_name"] == "bilstm-reporting-fixture"
    assert report["model_result_id"] == result_id
    assert report["predicted_label"] == "FDI"
    assert report["action_result"]["executed"] is True
    assert report["report_received_time_s"] is not None


def test_denied_model_recommendation_is_audited_without_duplicate_report():
    runtime = _runtime("model-report-denied", confidence=0.2)
    runtime.run_to_completion()
    result_id = _external_model_events(runtime)[0]["extensions"]["model_result"][
        "result_id"
    ]
    local = [
        item
        for item in runtime.nodes[1].local_security_cache
        if item.get("correlation_id") == result_id
    ]
    assert len(local) == 1
    assert local[0]["action_result"]["executed"] is False
    assert local[0]["action_result"]["failure_reason"] == "MODEL_CONFIDENCE_BELOW_THRESHOLD"


def test_disconnected_model_report_is_cached_then_uploaded_with_delay():
    runtime = _runtime("model-report-disconnected", duration_s=3.0)
    runtime.set_bidirectional_link_active(
        0, 1, False, reason="MODEL_REPORT_LINK_DOWN"
    )
    runtime.start()
    while runtime.context.clock.now_s < 1.4:
        runtime.step()
    assert _external_model_events(runtime)
    assert not runtime.reporting.gcs_inbox
    assert runtime.reporting.pending_summary_count > 0 or runtime.reporting.pending_for(1)

    runtime.set_bidirectional_link_active(
        0, 1, True, reason="MODEL_REPORT_LINK_RECOVERED"
    )
    while runtime.state.value == "RUNNING":
        runtime.step()
    result_id = _external_model_events(runtime)[0]["extensions"]["model_result"][
        "result_id"
    ]
    delivered = [
        item
        for item in runtime.reporting.gcs_inbox
        if item.get("correlation_id") == result_id
    ]
    assert len(delivered) == 1
    assert delivered[0]["report_delay_s"] > 0
