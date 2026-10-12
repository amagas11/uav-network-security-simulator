"""Link-constrained local reporting with real Leader aggregation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .simulation import RunContext, SCHEMA_VERSION


@dataclass(slots=True)
class SecurityReport:
    schema_version: str
    run_id: str
    report_id: str
    source_node_id: int
    event_time_s: float
    detection_time_s: float
    action_time_s: float | None
    report_received_time_s: float | None
    category: str
    severity: str
    source_event_ids: list[str]
    evidence: dict[str, Any]
    action_result: dict[str, Any] | None
    report_type: str = "SECURITY_REPORT"
    delivery_mode: str = "BATCHABLE"
    decision_source: str = "RULE"
    correlation_id: str | None = None
    model_result_id: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    predicted_label: str | None = None
    confidence: float | None = None
    quality: float | None = None
    decision_time_s: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReportingService:
    """Moves reports Source -> Leader -> GCS over simulated communication.

    Non-emergency reports are aggregated at the Leader by source, category,
    severity and a fixed simulation-time window. Every original report remains
    in its source node's local cache and every summary retains report/evidence
    identifiers.
    """

    def __init__(
        self,
        context: RunContext,
        gcs_node_id: int,
        leader_node_id: int,
        *,
        summary_window_s: float = 0.5,
    ) -> None:
        self.context = context
        self.gcs_node_id = gcs_node_id
        self.leader_node_id = leader_node_id
        self.summary_window_s = float(summary_window_s)
        self._source_pending: dict[str, dict[str, Any]] = {}
        self._leader_buckets: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._gcs_pending: dict[str, dict[str, Any]] = {}
        self._reports_by_correlation: dict[str, SecurityReport] = {}
        self.gcs_inbox: list[dict[str, Any]] = []

    def create(
        self,
        source_node_id: int,
        *,
        event_time_s: float,
        detection_time_s: float,
        action_time_s: float | None,
        category: str,
        evidence: dict[str, Any],
        action_result: dict[str, Any] | None,
        severity: str = "MEDIUM",
        source_event_ids: list[str] | None = None,
        decision_source: str = "RULE",
        correlation_id: str | None = None,
        model_result_id: str | None = None,
        model_name: str | None = None,
        model_version: str | None = None,
        predicted_label: str | None = None,
        confidence: float | None = None,
        quality: float | None = None,
        decision_time_s: float | None = None,
    ) -> SecurityReport:
        normalized_correlation = (
            str(correlation_id) if correlation_id is not None else None
        )
        if normalized_correlation is not None:
            existing = self._reports_by_correlation.get(normalized_correlation)
            if existing is not None:
                return existing
        report = SecurityReport(
            schema_version=SCHEMA_VERSION,
            run_id=self.context.run_id,
            report_id=self.context.ids.next("report"),
            source_node_id=source_node_id,
            event_time_s=float(event_time_s),
            detection_time_s=float(detection_time_s),
            action_time_s=action_time_s,
            report_received_time_s=None,
            category=str(category).upper(),
            severity=str(severity).upper(),
            source_event_ids=list(source_event_ids or []),
            evidence=deepcopy(evidence),
            action_result=deepcopy(action_result),
            decision_source=str(decision_source).upper(),
            correlation_id=normalized_correlation,
            model_result_id=model_result_id,
            model_name=model_name,
            model_version=model_version,
            predicted_label=predicted_label,
            confidence=confidence,
            quality=quality,
            decision_time_s=decision_time_s,
        )
        if normalized_correlation is not None:
            self._reports_by_correlation[normalized_correlation] = report
        if source_node_id == self.gcs_node_id:
            payload = report.to_dict()
            payload["delivery_mode"] = "LOCAL_GCS"
            payload["report_received_time_s"] = self.context.clock.now_s
            payload["report_delay_s"] = max(
                0.0, self.context.clock.now_s - report.detection_time_s
            )
            self.gcs_inbox.append(payload)
        elif source_node_id == self.leader_node_id:
            self._accept_at_leader(report, self.context.clock.now_s)
        else:
            self._source_pending[report.report_id] = {
                "report": report,
                "in_flight": False,
            }
        return report

    def pending_for(self, node_id: int) -> list[SecurityReport]:
        result = [
            item["report"]
            for item in self._source_pending.values()
            if item["report"].source_node_id == node_id
        ]
        for item in self._gcs_pending.values():
            payload = item["payload"]
            if (
                payload.get("source_node_id") == node_id
                and payload.get("report_type") == "SECURITY_REPORT"
            ):
                report = item.get("report")
                if isinstance(report, SecurityReport):
                    result.append(report)
        return result

    @property
    def pending_summary_count(self) -> int:
        return sum(
            1
            for item in self._gcs_pending.values()
            if item["payload"].get("report_type") == "SECURITY_SUMMARY"
        )

    def flush_sources(
        self,
        can_route: Callable[[int, int], bool],
        enqueue: Callable[[SecurityReport, int], bool],
    ) -> None:
        for item in list(self._source_pending.values()):
            report: SecurityReport = item["report"]
            if item["in_flight"]:
                continue
            if not can_route(report.source_node_id, self.leader_node_id):
                continue
            item["in_flight"] = bool(enqueue(report, self.leader_node_id))

    def receive_at_leader(
        self, report_id: str, sim_time_s: float
    ) -> dict[str, Any] | None:
        item = self._source_pending.pop(report_id, None)
        if item is None:
            return None
        report: SecurityReport = item["report"]
        self._accept_at_leader(report, sim_time_s)
        return report.to_dict()

    def _accept_at_leader(
        self, report: SecurityReport, accepted_time_s: float
    ) -> None:
        if report.severity in {"HIGH", "CRITICAL", "EMERGENCY"}:
            payload = report.to_dict()
            payload["delivery_mode"] = "EMERGENCY_BYPASS"
            self._gcs_pending[report.report_id] = {
                "payload": payload,
                "report": report,
                "in_flight": False,
            }
            return
        key = (
            report.source_node_id,
            report.category,
            report.severity,
        )
        bucket = self._leader_buckets.setdefault(
            key,
            {
                "reports": [],
                "opened_time_s": float(accepted_time_s),
                "due_time_s": float(accepted_time_s) + self.summary_window_s,
            },
        )
        bucket["reports"].append(report)

    def prepare_due_summaries(self, sim_time_s: float, *, force: bool = False) -> None:
        for key, bucket in list(self._leader_buckets.items()):
            reports: list[SecurityReport] = bucket["reports"]
            if not reports:
                self._leader_buckets.pop(key, None)
                continue
            window_end = float(bucket["due_time_s"])
            if not force and sim_time_s + 1e-12 < float(bucket["due_time_s"]):
                continue
            source_ids = sorted(
                {
                    event_id
                    for report in reports
                    for event_id in report.source_event_ids
                }
            )
            summary_id = self.context.ids.next("summary")
            payload = {
                "schema_version": SCHEMA_VERSION,
                "run_id": self.context.run_id,
                "report_type": "SECURITY_SUMMARY",
                "summary_id": summary_id,
                "report_id": summary_id,
                "source_node_id": key[0],
                "leader_node_id": self.leader_node_id,
                "category": key[1],
                "severity": key[2],
                "window_start_s": float(bucket["opened_time_s"]),
                "window_end_s": window_end,
                "count": len(reports),
                "source_report_ids": [report.report_id for report in reports],
                "source_event_ids": source_ids,
                "first_event_time_s": min(report.event_time_s for report in reports),
                "first_detection_time_s": min(
                    report.detection_time_s for report in reports
                ),
                "latest_detection_time_s": max(
                    report.detection_time_s for report in reports
                ),
                "latest_timestamp_s": max(
                    report.detection_time_s for report in reports
                ),
                "action_time_s": max(
                    (
                        report.action_time_s
                        for report in reports
                        if report.action_time_s is not None
                    ),
                    default=None,
                ),
                "report_received_time_s": None,
                "delivery_mode": "LEADER_AGGREGATED",
            }
            # DOS summaries are the GCS-visible presentation of a detector
            # that ran at the attacked receiver. Preserve only the detector's
            # already-produced, non-secret evidence and action result so the
            # UI does not substitute an unrelated secondary GCS alarm. This
            # changes neither the detector nor its decision/defense path.
            if key[1] == "DOS":
                latest_report = max(reports, key=lambda report: report.detection_time_s)
                payload["evidence"] = deepcopy(latest_report.evidence)
                payload["evidence"].update(
                    {
                        "detector_node_id": latest_report.source_node_id,
                        "detection_time_s": latest_report.detection_time_s,
                        "source_report_id": latest_report.report_id,
                        "observed_packet_rate_pps": latest_report.evidence.get(
                            "observed_packet_rate_pps",
                            latest_report.evidence.get("packet_rate_pps"),
                        ),
                        "flooding_threshold_pps": latest_report.evidence.get(
                            "flooding_threshold_pps",
                            latest_report.evidence.get("threshold_pps"),
                        ),
                        "statistics_window_s": latest_report.evidence.get(
                            "statistics_window_s",
                            latest_report.evidence.get("window_s"),
                        ),
                    }
                )
                payload["action_result"] = deepcopy(latest_report.action_result)
            self._gcs_pending[summary_id] = {
                "payload": payload,
                "report": None,
                "in_flight": False,
            }
            self._leader_buckets.pop(key, None)

    def flush_gcs(
        self,
        can_route: Callable[[int, int], bool],
        enqueue: Callable[[dict[str, Any], int], bool],
    ) -> None:
        for item in list(self._gcs_pending.values()):
            if item["in_flight"]:
                continue
            if not can_route(self.leader_node_id, self.gcs_node_id):
                continue
            item["in_flight"] = bool(
                enqueue(deepcopy(item["payload"]), self.gcs_node_id)
            )

    def mark_delivery_failed(self, delivery_id: str) -> None:
        if delivery_id in self._source_pending:
            self._source_pending[delivery_id]["in_flight"] = False
        if delivery_id in self._gcs_pending:
            self._gcs_pending[delivery_id]["in_flight"] = False

    def receive_at_gcs(
        self, delivery_id: str, sim_time_s: float
    ) -> dict[str, Any] | None:
        item = self._gcs_pending.pop(delivery_id, None)
        if item is None:
            return None
        payload = deepcopy(item["payload"])
        payload["report_received_time_s"] = float(sim_time_s)
        detection_time = payload.get(
            "latest_detection_time_s", payload.get("detection_time_s")
        )
        payload["report_delay_s"] = (
            max(0.0, float(sim_time_s) - float(detection_time))
            if isinstance(detection_time, (int, float))
            else None
        )
        self.gcs_inbox.append(payload)
        return payload

    def reset(self) -> None:
        self._source_pending.clear()
        self._leader_buckets.clear()
        self._gcs_pending.clear()
        self._reports_by_correlation.clear()
        self.gcs_inbox.clear()
