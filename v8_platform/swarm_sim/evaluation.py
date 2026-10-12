"""Offline episode/window evaluation over physically separated truth."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from statistics import mean
from typing import Any

from .dos_target_evaluation import evaluate_dos_targets


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _mean_or_none(values: list[float]) -> float | None:
    return mean(values) if values else None


@dataclass(slots=True)
class DefensePolicyResult:
    effective: bool
    policy: str
    evidence: dict[str, Any]


class AttackScopeType(str, Enum):
    NODE_SCOPE = "NODE_SCOPE"
    LINK_SCOPE = "LINK_SCOPE"
    MESSAGE_SCOPE = "MESSAGE_SCOPE"
    FLOW_SCOPE = "FLOW_SCOPE"
    COMPOSITE_SCOPE = "COMPOSITE_SCOPE"


@dataclass(slots=True)
class AttackEpisodeScope:
    """Offline ownership boundary for one attack episode."""

    attack_id: str | None
    target_node_ids: set[int]
    target_link_ids: set[str]
    affected_message_ids: set[str]
    attacker_node_id: int | None
    relevant_observer_ids: set[int]
    relevant_evidence_event_ids: set[str]
    scope_type: AttackScopeType

    @staticmethod
    def _event_link_ids(event: dict[str, Any]) -> set[str]:
        packet = event.get("online_features", {}).get("packet", {})
        extensions = event.get("extensions", {})
        defense = extensions.get("defense_result", {}) if isinstance(extensions, dict) else {}
        target = defense.get("target", {}) if isinstance(defense, dict) else {}
        values = {
            packet.get("link_id") if isinstance(packet, dict) else None,
            extensions.get("sample_link_id") if isinstance(extensions, dict) else None,
            target.get("link_id") if isinstance(target, dict) else None,
        }
        return {str(value) for value in values if isinstance(value, str) and value}

    @classmethod
    def from_label(
        cls, label: dict[str, Any], events: list[dict[str, Any]]
    ) -> "AttackEpisodeScope":
        truth = label.get("truth", {}) if isinstance(label.get("truth"), dict) else {}
        targets = {
            int(value)
            for value in label.get("target_node_ids", [])
            if isinstance(value, int) and not isinstance(value, bool)
        }
        observable_links = truth.get("observable_target_link_ids")
        links = {
            str(value)
            for value in (
                observable_links
                if isinstance(observable_links, list)
                else label.get("target_link_ids", [])
            )
        }
        messages = {str(value) for value in truth.get("affected_message_ids", [])}
        evidence_ids = {
            str(value) for value in truth.get("relevant_evidence_event_ids", [])
        }
        family = str(label.get("attack_family", "")).upper()
        subtype = str(label.get("attack_subtype", "")).upper()
        if family in {"FDI", "REPLAY", "SPOOFING"} and messages:
            scope_type = AttackScopeType.MESSAGE_SCOPE
        elif links:
            scope_type = AttackScopeType.LINK_SCOPE
        elif targets:
            scope_type = AttackScopeType.NODE_SCOPE
        else:
            scope_type = AttackScopeType.COMPOSITE_SCOPE
        observers = set(targets)
        for event in events:
            packet = event.get("online_features", {}).get("packet", {})
            receiver_observation = event.get("event_type") in {
                "RX_SUCCESS",
                "RX_FAILURE",
                "AUTH_RESULT",
                "PHY_SAMPLE",
                "QUEUE_SAMPLE",
                "NODE_STATE",
            }
            event_matches = (
                event.get("message_id") in messages
                if scope_type == AttackScopeType.MESSAGE_SCOPE
                else bool(cls._event_link_ids(event) & links)
                if scope_type == AttackScopeType.LINK_SCOPE
                else event.get("observer_node_id") in targets
            )
            if receiver_observation and (
                event_matches or event.get("event_id") in evidence_ids
            ) and isinstance(event.get("observer_node_id"), int):
                observers.add(int(event["observer_node_id"]))
                if event.get("event_id"):
                    evidence_ids.add(str(event["event_id"]))
        attacker = label.get("attacker_node_id")
        return cls(
            attack_id=str(label.get("attack_id")) if label.get("attack_id") is not None else None,
            target_node_ids=targets,
            target_link_ids=links,
            affected_message_ids=messages,
            attacker_node_id=int(attacker) if isinstance(attacker, int) else None,
            relevant_observer_ids=observers,
            relevant_evidence_event_ids=evidence_ids,
            scope_type=scope_type,
        )

    def event_is_relevant(self, event: dict[str, Any]) -> bool:
        if self.scope_type == AttackScopeType.LINK_SCOPE:
            return bool(
                self._event_link_ids(event) & self.target_link_ids
                or event.get("event_id") in self.relevant_evidence_event_ids
            )
        if self.scope_type == AttackScopeType.MESSAGE_SCOPE:
            return bool(
                event.get("message_id") in self.affected_message_ids
                or event.get("event_id") in self.relevant_evidence_event_ids
            )
        if self.scope_type == AttackScopeType.NODE_SCOPE:
            return event.get("observer_node_id") in self.target_node_ids
        return bool(
            event.get("event_id") in self.relevant_evidence_event_ids
            or event.get("message_id") in self.affected_message_ids
        )

    def decision_is_relevant(self, decision: dict[str, Any]) -> bool:
        evidence = set(decision.get("evidence_event_ids", []))
        if self.scope_type in {
            AttackScopeType.LINK_SCOPE,
            AttackScopeType.MESSAGE_SCOPE,
            AttackScopeType.FLOW_SCOPE,
        }:
            return bool(evidence & self.relevant_evidence_event_ids)
        return bool(
            decision.get("observer") in self.relevant_observer_ids
            or evidence & self.relevant_evidence_event_ids
        )

    def defense_is_relevant(self, defense: dict[str, Any]) -> bool:
        result = defense.get("result", {})
        target = result.get("target", {}) if isinstance(result, dict) else {}
        if self.scope_type == AttackScopeType.LINK_SCOPE:
            return target.get("link_id") in self.target_link_ids
        if self.scope_type == AttackScopeType.MESSAGE_SCOPE:
            return bool(
                defense.get("message_id") in self.affected_message_ids
                or defense.get("event_id") in self.relevant_evidence_event_ids
            )
        if self.scope_type == AttackScopeType.NODE_SCOPE:
            return bool(
                target.get("node_id") in self.target_node_ids
                or defense.get("observer") in self.target_node_ids
            )
        return self.event_is_relevant(defense.get("event", {}))


class EvaluationPolicyRegistry:
    """Family-specific offline defense semantics over measured outcomes."""

    @staticmethod
    def _phy_values(
        events: list[dict[str, Any]],
        start_s: float,
        end_s: float,
        field: str,
        scope: AttackEpisodeScope | None = None,
    ) -> list[float]:
        result: list[float] = []
        for event in events:
            if scope is not None and not scope.event_is_relevant(event):
                continue
            if event.get("event_type") not in {"PHY_SAMPLE", "RX_SUCCESS", "RX_FAILURE"}:
                continue
            at_s = event.get("sim_time_s")
            if not isinstance(at_s, (int, float)) or not start_s <= at_s <= end_s:
                continue
            value = event.get("online_features", {}).get("phy", {}).get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                result.append(float(value))
        return result

    @staticmethod
    def _service_counts(
        events: list[dict[str, Any]], start_s: float, end_s: float,
        scope: AttackEpisodeScope | None = None,
    ) -> tuple[int, int]:
        success = 0
        failure = 0
        for event in events:
            if scope is not None and not scope.event_is_relevant(event):
                continue
            at_s = event.get("sim_time_s")
            if not isinstance(at_s, (int, float)) or not start_s <= at_s <= end_s:
                continue
            success += event.get("event_type") == "RX_SUCCESS"
            failure += event.get("event_type") == "RX_FAILURE"
        return success, failure

    def evaluate(
        self,
        *,
        family: str,
        subtype: str,
        action_executed: bool,
        action: str | None,
        action_time_s: float | None,
        start_s: float,
        end_s: float,
        events: list[dict[str, Any]],
        outcome: dict[str, Any],
        service: dict[str, Any],
        defense_outcome: dict[str, Any],
        scope: AttackEpisodeScope,
    ) -> DefensePolicyResult:
        blocked = int(
            outcome.get(
                "malicious_traffic_blocked",
                outcome.get("malicious_blocked_count", 0),
            )
            or 0
        )
        delivered_after = int(
            outcome.get("malicious_traffic_delivered_after_action", 0) or 0
        )
        harm_score = defense_outcome.get("legitimate_traffic_harm_score")
        harm_bounded = not isinstance(harm_score, (int, float)) or harm_score <= 0.5
        recovery = service.get("service_recovery_time_s") is not None

        if family == "DOS" and subtype == "FLOODING":
            effective = bool(
                action_executed
                and blocked > 0
                and outcome.get("receiver_total_rate_exceeded", False)
                and harm_bounded
            )
            return DefensePolicyResult(
                effective,
                "FLOODING_RECEIVER_RATE_AND_HMAC_GATE",
                {
                    "receiver_total_rate_exceeded": bool(
                        outcome.get("receiver_total_rate_exceeded", False)
                    ),
                    "observed_packet_rate_pps": outcome.get(
                        "observed_packet_rate_pps"
                    ),
                    "malicious_traffic_blocked": blocked,
                    "service_recovered": recovery,
                    "legitimate_harm_bounded": harm_bounded,
                    # Expose the actual policy input's availability. Keep legacy
                    # formulas/booleans compatible; a missing input is not UI proof.
                    "legitimate_harm_available": isinstance(harm_score, (int, float)) and not isinstance(harm_score, bool) and float('-inf') < harm_score < float('inf'),
                    "legitimate_traffic_harm_score": harm_score,
                },
            )

        if family == "REPLAY":
            effective = bool(
                action_executed
                and blocked > 0
                and outcome.get("application_hmac_passed_before_replay_check", False)
                and not outcome.get("malicious_content_executed", False)
                and harm_bounded
            )
            return DefensePolicyResult(
                effective,
                "REPLAY_REJECTION_WITH_LEGITIMATE_CONTINUITY",
                {
                    "replayed_packet_rejected": blocked > 0,
                    "application_hmac_passed": bool(
                        outcome.get("application_hmac_passed_before_replay_check", False)
                    ),
                    "replay_rejection_reason": outcome.get(
                        "replay_rejection_reason"
                    ),
                    "malicious_delivered_after_action": delivered_after,
                    "legitimate_harm_bounded": harm_bounded,
                },
            )

        if family == "SPOOFING":
            effective = bool(
                action_executed
                and blocked > 0
                and outcome.get("application_hmac_rejected", False)
                and not outcome.get("malicious_content_executed", False)
                and harm_bounded
            )
            return DefensePolicyResult(
                effective,
                "SPOOFED_IDENTITY_REJECTION",
                {
                    "spoofed_packet_rejected": blocked > 0,
                    "application_hmac_rejected": bool(
                        outcome.get("application_hmac_rejected", False)
                    ),
                    "legitimate_harm_bounded": harm_bounded,
                },
            )

        if family == "FDI":
            effective = bool(
                action_executed
                and blocked > 0
                and outcome.get("application_hmac_rejected", False)
                and not outcome.get("malicious_content_executed", False)
                and harm_bounded
            )
            return DefensePolicyResult(
                effective,
                "FDI_POST_HMAC_REJECTION_AND_NO_UPDATE",
                {
                    "modified_effect_prevented": blocked > 0,
                    "application_hmac_rejected": bool(
                        outcome.get("application_hmac_rejected", False)
                    ),
                    "legitimate_harm_bounded": harm_bounded,
                },
            )

        return DefensePolicyResult(
            False,
            "UNSUPPORTED_FAMILY_POLICY",
            {"failure_reason": "NO_FAMILY_SPECIFIC_DEFENSE_POLICY"},
        )


class ExperimentEvaluator:
    """Evaluate attack episodes and normal decision windows.

    The evaluator is offline-only and never changes events or label records.
    One attack label is one positive episode.  False positives and true
    negatives use fixed normal windows, so repeated alarms inside a detected
    episode cannot inflate TP or become FP.
    """

    def __init__(
        self,
        *,
        evaluation_window_s: float = 1.0,
        detection_grace_s: float = 0.0,
        recovery_throughput_ratio: float = 0.8,
        recovery_latency_ratio: float = 1.25,
    ) -> None:
        if evaluation_window_s <= 0:
            raise ValueError("evaluation_window_s must be positive")
        if detection_grace_s < 0:
            raise ValueError("detection_grace_s must be non-negative")
        self.evaluation_window_s = float(evaluation_window_s)
        self.detection_grace_s = float(detection_grace_s)
        self.recovery_throughput_ratio = float(recovery_throughput_ratio)
        self.recovery_latency_ratio = float(recovery_latency_ratio)

    @staticmethod
    def _decisions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        decisions: list[dict[str, Any]] = []
        for event in events:
            if event.get("event_type") != "MODEL_RESULT":
                continue
            result = event.get("extensions", {}).get("model_result", {})
            predicted = result.get("predicted_label")
            if not predicted:
                continue
            decisions.append(
                {
                    "time": float(event.get("sim_time_s", 0.0)),
                    "label": str(predicted).upper(),
                    "observer": event.get("observer_node_id"),
                    "result_id": result.get("result_id"),
                    "evidence_event_ids": list(result.get("evidence_event_ids") or []),
                }
            )
        return decisions

    @staticmethod
    def _defenses(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for event in events:
            if event.get("event_type") != "DEFENSE_RESULT":
                continue
            result = event.get("extensions", {}).get("defense_result", {})
            if not isinstance(result, dict):
                continue
            values.append(
                {
                    "event_id": event.get("event_id"),
                    "message_id": event.get("message_id"),
                    "time": float(event.get("sim_time_s", 0.0)),
                    "observer": event.get("observer_node_id"),
                    "result": result,
                    "phase": event.get("extensions", {}).get("result_phase"),
                    "audit": event.get("extensions", {}).get("decision_audit", {}),
                    "event": event,
                }
            )
        return values

    def _duration(
        self,
        events: list[dict[str, Any]],
        labels: list[dict[str, Any]],
        run_record: dict[str, Any] | None,
    ) -> float:
        candidates = [self.evaluation_window_s]
        if run_record and isinstance(run_record.get("duration_s"), (int, float)):
            candidates.append(float(run_record["duration_s"]))
        candidates.extend(
            float(event.get("sim_time_s", 0.0)) for event in events
        )
        candidates.extend(float(label.get("end_s", 0.0)) for label in labels)
        return max(candidates)

    def _normal_windows(
        self, duration_s: float, labels: list[dict[str, Any]]
    ) -> list[tuple[float, float]]:
        windows: list[tuple[float, float]] = []
        start = 0.0
        while start < duration_s - 1e-12:
            end = min(duration_s, start + self.evaluation_window_s)
            overlaps_attack = any(
                float(label.get("impact_start_s", 0.0)) < end
                and float(label.get("end_s", 0.0)) > start
                for label in labels
            )
            if not overlaps_attack:
                windows.append((start, end))
            start = end
        return windows

    @staticmethod
    def _traffic_points(
        events: list[dict[str, Any]],
        start_s: float,
        end_s: float,
        *,
        excluded_message_ids: set[str] | None = None,
        scope: AttackEpisodeScope | None = None,
    ) -> list[dict[str, float | bool]]:
        points: list[dict[str, float | bool]] = []
        for event in events:
            if scope is not None and not scope.event_is_relevant(event):
                continue
            if event.get("event_type") not in {"RX_SUCCESS", "RX_FAILURE"}:
                continue
            if event.get("message_id") in (excluded_message_ids or set()):
                continue
            at_s = float(event.get("sim_time_s", 0.0))
            if not start_s <= at_s <= end_s:
                continue
            traffic = event.get("online_features", {}).get("traffic", {})
            throughput = traffic.get("throughput_mbps")
            latency = traffic.get("latency_ms")
            points.append(
                {
                    "time": at_s,
                    "throughput": (
                        float(throughput)
                        if isinstance(throughput, (int, float))
                        else 0.0
                    ),
                    "latency": (
                        float(latency)
                        if isinstance(latency, (int, float))
                        else 0.0
                    ),
                    "failure": event.get("event_type") == "RX_FAILURE",
                }
            )
        return points

    def _service_metrics(
        self,
        events: list[dict[str, Any]],
        start_s: float,
        end_s: float,
        duration_s: float,
        excluded_message_ids: set[str] | None = None,
        scope: AttackEpisodeScope | None = None,
    ) -> dict[str, float | None]:
        baseline = self._traffic_points(
            events, 0.0, max(0.0, start_s - 1e-12), scope=scope
        )
        impacted = self._traffic_points(
            events,
            start_s,
            end_s,
            excluded_message_ids=excluded_message_ids,
            scope=scope,
        )
        post = self._traffic_points(
            events,
            end_s,
            duration_s,
            excluded_message_ids=excluded_message_ids,
            scope=scope,
        )
        baseline_success = [point for point in baseline if not point["failure"]]
        impacted_success = [point for point in impacted if not point["failure"]]

        baseline_throughput = _mean_or_none(
            [float(point["throughput"]) for point in baseline_success]
        )
        baseline_latency = _mean_or_none(
            [float(point["latency"]) for point in baseline_success]
        )
        impacted_throughput = _mean_or_none(
            [float(point["throughput"]) for point in impacted_success]
        )
        impacted_latency = _mean_or_none(
            [float(point["latency"]) for point in impacted_success]
        )

        components: list[float] = []
        if baseline_throughput is not None and baseline_throughput > 0:
            current = impacted_throughput or 0.0
            components.append(
                max(0.0, min(1.0, (baseline_throughput - current) / baseline_throughput))
            )
        if baseline_latency is not None and baseline_latency > 0 and impacted_latency is not None:
            components.append(
                max(0.0, min(1.0, (impacted_latency - baseline_latency) / baseline_latency))
            )
        if impacted:
            components.append(
                sum(bool(point["failure"]) for point in impacted) / len(impacted)
            )

        recovered_at: float | None = None
        if baseline_throughput is not None and baseline_latency is not None:
            for point in sorted(post, key=lambda item: float(item["time"])):
                if point["failure"]:
                    continue
                if (
                    float(point["throughput"])
                    >= baseline_throughput * self.recovery_throughput_ratio
                    and float(point["latency"])
                    <= baseline_latency * self.recovery_latency_ratio
                ):
                    recovered_at = float(point["time"])
                    break
        return {
            "baseline_throughput_mbps": baseline_throughput,
            "baseline_latency_ms": baseline_latency,
            "impacted_throughput_mbps": impacted_throughput,
            "impacted_latency_ms": impacted_latency,
            "legitimate_service_damage": (
                sum(components) / len(components) if components else None
            ),
            "service_recovery_time_s": (
                max(0.0, recovered_at - end_s) if recovered_at is not None else None
            ),
        }

    @staticmethod
    def _accepted_online_attribution_labels(family: str) -> set[str]:
        """Return online labels that offline evaluation may attribute here.

        Application HMAC can only report the mathematical fact that
        authentication failed.  Once an attack episode is already known from
        offline truth, that generic evidence may be attributed to Spoofing or
        FDI without teaching the online detector either attack label.
        """

        accepted = {str(family).upper()}
        if str(family).upper() in {"SPOOFING", "FDI"}:
            accepted.add("AUTH_FAILURE")
        return accepted

    @classmethod
    def _matching_defenses(
        cls,
        defenses: list[dict[str, Any]],
        family: str,
        start_s: float,
        end_s: float,
        scope: AttackEpisodeScope,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for item in defenses:
            if not start_s <= item["time"] <= end_s:
                continue
            request = item["result"].get("request", {})
            target = item["result"].get("target", {})
            if not scope.defense_is_relevant(item):
                continue
            reason = str(request.get("reason") or "").upper()
            accepted_reasons = cls._accepted_online_attribution_labels(family) | {
                "RL_RECOMMENDATION"
            }
            if reason and reason not in accepted_reasons:
                continue
            matches.append(item)
        return sorted(
            matches,
            key=lambda item: (
                item["time"],
                item.get("phase") != "POST_ACTION_EVALUATION",
            ),
        )

    @staticmethod
    def _matching_report(
        reports: list[dict[str, Any]], family: str, start_s: float, end_s: float,
        scope: AttackEpisodeScope,
    ) -> dict[str, Any] | None:
        matches = [
            report
            for report in reports
            if str(report.get("category", "")).upper() == family
            and (
                not scope.relevant_observer_ids
                or report.get("source_node_id") in scope.relevant_observer_ids
            )
            and start_s
            <= float(
                report.get(
                    "latest_detection_time_s", report.get("detection_time_s", -1.0)
                )
            )
            <= end_s
            and report.get("report_received_time_s") is not None
        ]
        return (
            min(matches, key=lambda item: float(item["report_received_time_s"]))
            if matches
            else None
        )

    def evaluate(
        self,
        events: list[dict[str, Any]],
        labels: list[dict[str, Any]],
        *,
        reports: list[dict[str, Any]] | None = None,
        run_record: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        decisions = self._decisions(events)
        defenses = self._defenses(events)
        reports = list(reports or [])
        duration_s = self._duration(events, labels, run_record)
        detection_labels = [
            label
            for label in labels
            if str(label.get("attack_family", "")).upper() != "EAVESDROPPING"
        ]
        normal_windows = self._normal_windows(duration_s, detection_labels)
        policy_registry = EvaluationPolicyRegistry()

        by_family: dict[str, dict[str, Any]] = {}
        episode_rows: list[dict[str, Any]] = []
        families = sorted(
            {
                str(label.get("attack_family", "UNKNOWN")).upper()
                for label in detection_labels
            }
            | {
                str(decision["label"]).upper()
                for decision in decisions
                if str(decision["label"]).upper()
                not in {"EAVESDROPPING", "AUTH_FAILURE"}
            }
        )
        for family in families:
            family_labels = [
                label
                for label in detection_labels
                if str(label.get("attack_family", "")).upper() == family
            ]
            accepted_online_labels = self._accepted_online_attribution_labels(family)
            family_decisions = [
                decision
                for decision in decisions
                if decision["label"] in accepted_online_labels
            ]
            family_normal_windows = self._normal_windows(duration_s, family_labels)
            matched_alarm_ids: set[int] = set()
            detection_delays: list[float] = []
            action_delays: list[float] = []
            duplicate_alarms = 0
            tp = 0
            fn = 0

            for label in family_labels:
                start_s = float(label["impact_start_s"])
                end_s = float(label["end_s"])
                scope = AttackEpisodeScope.from_label(label, events)
                hits = [
                    (index, decision)
                    for index, decision in enumerate(family_decisions)
                    if index not in matched_alarm_ids
                    if start_s
                    <= decision["time"]
                    <= end_s + self.detection_grace_s
                    if scope.decision_is_relevant(decision)
                ]
                first_decision: dict[str, Any] | None = None
                if hits:
                    tp += 1
                    hits.sort(key=lambda item: item[1]["time"])
                    first_decision = hits[0][1]
                    matched_alarm_ids.update(index for index, _ in hits)
                    duplicate_alarms += max(0, len(hits) - 1)
                    detection_delays.append(first_decision["time"] - start_s)
                else:
                    fn += 1

                defense_attempts = self._matching_defenses(
                    defenses,
                    family,
                    first_decision["time"] if first_decision else start_s,
                    end_s + self.detection_grace_s,
                    scope,
                )
                executed_attempts = [
                    item
                    for item in defense_attempts
                    if bool(item["result"].get("executed", False))
                ]
                selected_defense = executed_attempts[0] if executed_attempts else None
                defense_result = (
                    selected_defense["result"] if selected_defense else {}
                )
                action_executed = bool(executed_attempts)
                action_time = defense_result.get("executed_time_s")
                action_delay = (
                    max(0.0, float(action_time) - start_s)
                    if action_executed and isinstance(action_time, (int, float))
                    else None
                )
                if action_delay is not None:
                    action_delays.append(action_delay)

                report = self._matching_report(
                    reports, family, start_s, end_s + self.detection_grace_s, scope
                )
                report_delay = None
                if report is not None:
                    detected_at = report.get(
                        "latest_detection_time_s", report.get("detection_time_s")
                    )
                    received_at = report.get("report_received_time_s")
                    if isinstance(detected_at, (int, float)) and isinstance(
                        received_at, (int, float)
                    ):
                        report_delay = round(
                            max(0.0, float(received_at) - float(detected_at)), 9
                        )

                truth = label.get("truth", {})
                excluded_message_ids = {
                    str(message_id)
                    for message_id in truth.get("affected_message_ids", [])
                }
                service = self._service_metrics(
                    events,
                    start_s,
                    end_s,
                    duration_s,
                    excluded_message_ids,
                    scope,
                )
                outcome = label.get("outcome", {})
                attack_effective = bool(outcome.get("attack_effective", False))
                defense_outcome = (
                    defense_result.get("outcome", {})
                    if isinstance(defense_result.get("outcome", {}), dict)
                    else {}
                )
                policy_results: list[DefensePolicyResult] = []
                for attempt in executed_attempts or [None]:
                    attempt_result = attempt["result"] if attempt else {}
                    attempt_time = attempt_result.get("executed_time_s")
                    policy_results.append(
                        policy_registry.evaluate(
                            family=family,
                            subtype=str(label.get("attack_subtype", "")).upper(),
                            action_executed=bool(attempt),
                            action=(
                                str(attempt_result.get("request", {}).get("action"))
                                if attempt_result
                                else None
                            ),
                            action_time_s=(
                                float(attempt_time)
                                if isinstance(attempt_time, (int, float))
                                else None
                            ),
                            start_s=start_s,
                            end_s=end_s + self.detection_grace_s,
                            events=events,
                            outcome=outcome,
                            service=service,
                            defense_outcome=(
                                attempt_result.get("outcome", {})
                                if isinstance(attempt_result.get("outcome", {}), dict)
                                else {}
                            ),
                            scope=scope,
                        )
                    )
                policy = next(
                    (candidate for candidate in policy_results if candidate.effective),
                    policy_results[0],
                )
                denied_action_count = sum(
                    not bool(item["result"].get("executed", False))
                    for item in defense_attempts
                )
                denied_recommendation_count = sum(
                    not bool(item["result"].get("executed", False))
                    and item.get("audit", {}).get("recommendation_source") == "MODEL"
                    for item in defense_attempts
                )
                episode_rows.append(
                    {
                        "attack_id": label.get("attack_id"),
                        "attack_family": family,
                        "attack_subtype": label.get("attack_subtype"),
                        "impact_start_s": start_s,
                        "end_s": end_s,
                        "episode_detected": first_decision is not None,
                        "alarm_count": len(hits),
                        "duplicate_alarm_count": max(0, len(hits) - 1),
                        "detection_delay_s": (
                            round(first_decision["time"] - start_s, 9)
                            if first_decision
                            else None
                        ),
                        "action_executed": action_executed,
                        "action_delay_s": action_delay,
                        "defense_attempts": [
                            {
                                "event_id": item.get("event_id"),
                                "sim_time_s": item["time"],
                                "allowed": bool(item["result"].get("allowed", False)),
                                "executed": bool(item["result"].get("executed", False)),
                                "action": item["result"].get("request", {}).get("action"),
                                "failure_reason": item["result"].get("failure_reason"),
                                "source": item.get("audit", {}).get("source"),
                            }
                            for item in defense_attempts
                        ],
                        "executed_defense_count": len(executed_attempts),
                        "denied_action_count": denied_action_count,
                        "denied_recommendation_count": denied_recommendation_count,
                        "report_delay_s": report_delay,
                        "attack_effective": attack_effective,
                        "mission_impact": outcome.get("mission_impact"),
                        "mission_impact_available": bool(
                            outcome.get("mission_impact_available", False)
                        ),
                        "mission_impact_components": outcome.get(
                            "mission_impact_components", {}
                        ),
                        "defense_effective": policy.effective,
                        "defense_policy": policy.policy,
                        "defense_evidence": policy.evidence,
                        "attack_scope": {
                            "scope_type": scope.scope_type.value,
                            "attack_id": scope.attack_id,
                            "attacker_node_id": scope.attacker_node_id,
                            "target_node_ids": sorted(scope.target_node_ids),
                            "target_link_ids": sorted(scope.target_link_ids),
                            "affected_message_ids": sorted(scope.affected_message_ids),
                            "relevant_observer_ids": sorted(scope.relevant_observer_ids),
                            "relevant_receiver_ids": sorted(scope.relevant_observer_ids),
                            "relevant_evidence_event_ids": sorted(
                                scope.relevant_evidence_event_ids
                            ),
                        },
                        **service,
                    }
                )

            false_positive_windows = 0
            true_negative_windows = 0
            normal_alarm_count = 0
            for window_start, window_end in family_normal_windows:
                alarms = [
                    decision
                    for decision in family_decisions
                    if window_start <= decision["time"] < window_end
                ]
                if alarms:
                    false_positive_windows += 1
                    normal_alarm_count += len(alarms)
                else:
                    true_negative_windows += 1

            # Same-family alarms from an unrelated observer during an attack
            # interval are not swallowed by that episode.  They are one false
            # positive per observer/decision window; relevant duplicate alarms
            # remain duplicate-alarm metadata and never become FP.
            unmatched_attack_windows = {
                (
                    decision.get("observer"),
                    int(float(decision["time"]) // self.evaluation_window_s),
                )
                for index, decision in enumerate(family_decisions)
                if index not in matched_alarm_ids
                if any(
                    float(label["impact_start_s"])
                    <= float(decision["time"])
                    <= float(label["end_s"]) + self.detection_grace_s
                    for label in family_labels
                )
            }
            false_positive_windows += len(unmatched_attack_windows)
            normal_alarm_count += sum(
                1
                for index, decision in enumerate(family_decisions)
                if index not in matched_alarm_ids
                and any(
                    float(label["impact_start_s"])
                    <= float(decision["time"])
                    <= float(label["end_s"]) + self.detection_grace_s
                    for label in family_labels
                )
            )

            precision = _safe_div(tp, tp + false_positive_windows)
            recall = _safe_div(tp, tp + fn)
            by_family[family] = {
                "TP": tp,
                "FP": false_positive_windows,
                "FN": fn,
                "TN": true_negative_windows,
                "precision": precision,
                "recall_pd": recall,
                "pfa_fpr": _safe_div(
                    false_positive_windows,
                    false_positive_windows + true_negative_windows,
                ),
                "f1": _safe_div(2 * precision * recall, precision + recall),
                "alarm_count": len(family_decisions),
                "matched_alarm_count": len(matched_alarm_ids),
                "duplicate_alarm_count": duplicate_alarms,
                "normal_alarm_count": normal_alarm_count,
                "normal_window_count": len(family_normal_windows),
                "mean_detection_delay_s": _mean_or_none(detection_delays),
                "mean_action_delay_s": _mean_or_none(action_delays),
                # Compatibility alias, now explicitly detection-only.
                "response_time_s": _mean_or_none(detection_delays),
            }

        outcomes = [label.get("outcome", {}) for label in labels]
        attack_effective_values = [
            bool(item.get("attack_effective"))
            for item in outcomes
            if "attack_effective" in item
        ]
        defense_effective_values = [
            bool(item["defense_effective"]) for item in episode_rows
        ]
        eaves_labels = [
            label
            for label in labels
            if str(label.get("attack_family", "")).upper() == "EAVESDROPPING"
        ]
        eaves_points: list[dict[str, float | bool]] = []
        for label in eaves_labels:
            eaves_points.extend(
                self._traffic_points(
                    events,
                    float(label.get("impact_start_s", 0.0)),
                    float(label.get("end_s", 0.0)),
                )
            )
        plaintext_exposure = sum(
            int(label.get("outcome", {}).get("plaintext_exposure_count", 0))
            for label in eaves_labels
        )
        ciphertext_protected = sum(
            int(label.get("outcome", {}).get("ciphertext_count", 0))
            for label in eaves_labels
        )
        content_recovery = sum(
            int(label.get("outcome", {}).get("content_recovery_count", 0))
            for label in eaves_labels
        )
        eaves = {
            "detection_evaluation_applicable": False,
            "sensitive_plaintext_exposure_count": plaintext_exposure,
            "ciphertext_protected_count": ciphertext_protected,
            "content_recovery_count": content_recovery,
            "sensitive_data_exposed": plaintext_exposure > 0,
            "protection_effective": bool(
                eaves_labels
                and ciphertext_protected > 0
                and plaintext_exposure == 0
                and content_recovery == 0
            ),
            "legitimate_service_availability": (
                sum(not bool(point["failure"]) for point in eaves_points)
                / len(eaves_points)
                if eaves_points
                else None
            ),
            "online_detection_rate": None,
            "note": "Pure passive eavesdropping is exposure/protection evaluation, not fabricated detection accuracy.",
        }
        action_latencies = [
            float(row["action_delay_s"])
            for row in episode_rows
            if row["action_delay_s"] is not None
        ]
        report_delays = [
            float(row["report_delay_s"])
            for row in episode_rows
            if row["report_delay_s"] is not None
        ]
        damages = [
            float(row["legitimate_service_damage"])
            for row in episode_rows
            if row["legitimate_service_damage"] is not None
        ]
        recovery_times = [
            float(row["service_recovery_time_s"])
            for row in episode_rows
            if row["service_recovery_time_s"] is not None
        ]
        return {
            "scope": "GROUND_TRUTH_OFFLINE_EVALUATION",
            "dos_target_receiver_evaluation": evaluate_dos_targets(
                events, labels, duration_s, self.evaluation_window_s,
                float((run_record or {}).get("run_config", {}).get("traffic_statistics_window_s", 1.0)),
                self.detection_grace_s,
                bool((run_record or {}).get("run_config", {}).get("flooding_detection_enabled", True)),
            ),
            # Compatibility metadata: the historical numeric formulas below
            # remain unchanged. Consumers must not treat disabled rules as
            # zero-error performance measurements.
            "detector_applicability": {
                "DOS": {
                    "applicable": (run_record or {}).get("run_config", {}).get(
                        "flooding_detection_enabled", True
                    ),
                    "reason": "FLOODING_DETECTOR_CONFIGURATION",
                },
                "EAVESDROPPING": {
                    "applicable": False,
                    "reason": "PASSIVE_EAVESDROPPING_HAS_NO_DIRECT_DETECTOR",
                },
                **{family: {"applicable": True, "reason": "BASE_SECURITY_VALIDATION"}
                   for family in ("SPOOFING", "FDI", "REPLAY")},
            },
            "metric_definitions": {
                "evaluation_unit": "ATTACK_EPISODE_AND_NORMAL_TIME_WINDOW",
                "normal_window_s": self.evaluation_window_s,
                "detection_grace_s": self.detection_grace_s,
                "detection_delay": "first_correct_alarm_time - impact_start_s",
                "action_delay": "first_executed_action_time - impact_start_s",
                "report_delay": "GCS_report_received_time - local_detection_time",
                "service_recovery": (
                    f"first post-attack success at >= {self.recovery_throughput_ratio:.2f}x "
                    f"baseline throughput and <= {self.recovery_latency_ratio:.2f}x baseline latency"
                ),
                "legitimate_service_damage": (
                    "mean of normalized throughput loss, latency increase, and legitimate receive-failure ratio; each component clipped to [0,1]"
                ),
                "defense_policy": "Family/subtype-specific registry; action execution is never treated as proof of effectiveness.",
                "passive_eavesdropping": "PASSIVE_CAPTURE is excluded from ordinary TP/FP/FN/TN and evaluated as exposure/protection.",
            },
            "attack_episode_count": len(labels),
            "detection_attack_episode_count": len(detection_labels),
            "normal_window_count": len(normal_windows),
            "per_attack_family": by_family,
            "episodes": episode_rows,
            "attack_effective_rate": (
                _safe_div(sum(attack_effective_values), len(attack_effective_values))
                if attack_effective_values
                else None
            ),
            "defense_effective_rate": (
                _safe_div(sum(defense_effective_values), len(defense_effective_values))
                if defense_effective_values
                else None
            ),
            "legitimate_service_damage": _mean_or_none(damages),
            "mean_detection_delay_s": _mean_or_none(
                [
                    float(row["detection_delay_s"])
                    for row in episode_rows
                    if row["detection_delay_s"] is not None
                ]
            ),
            "mean_time_to_action_s": _mean_or_none(action_latencies),
            "report_delay_s": _mean_or_none(report_delays),
            "service_recovery_time_s": _mean_or_none(recovery_times),
            "eavesdropping": eaves,
        }
