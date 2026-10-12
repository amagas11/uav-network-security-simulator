"""Offline mechanism gate for the V6 final scenario matrix.

Schema validity proves that records conform to the data contract.  This module
provides the separate, family-specific proof that the configured mechanism
actually ran.  It reads runtime truth only after a run and is never reachable
from online model dispatch or detector decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ScenarioMechanismResult:
    scenario: str
    passed: bool
    errors: tuple[str, ...]
    evidence: dict[str, Any]


class ScenarioMechanismValidator:
    """Validate concrete mechanism evidence instead of label presence."""

    @classmethod
    def validate(cls, runtime: Any, scenario: str) -> ScenarioMechanismResult:
        scenario = str(scenario).upper()
        if scenario == "NORMAL_BASELINE":
            return cls._normal_baseline(runtime, scenario)
        if scenario.startswith("NORMAL_"):
            return cls._normal(runtime, scenario)
        return cls._attack(runtime, scenario)

    @staticmethod
    def _finish(
        scenario: str, errors: list[str], evidence: dict[str, Any]
    ) -> ScenarioMechanismResult:
        return ScenarioMechanismResult(
            scenario=scenario,
            passed=not errors,
            errors=tuple(errors),
            evidence=evidence,
        )

    @classmethod
    def _normal_baseline(
        cls, runtime: Any, scenario: str
    ) -> ScenarioMechanismResult:
        tx = [event for event in runtime.events if event.get("event_type") == "TX"]
        receives = [
            event
            for event in runtime.events
            if event.get("event_type") in {"RX_SUCCESS", "RX_FAILURE"}
        ]
        errors: list[str] = []
        if runtime.attack_scheduler.labels():
            errors.append("baseline unexpectedly contains attack labels")
        if not tx or not receives:
            errors.append("baseline legitimate traffic did not traverse the radio path")
        return cls._finish(
            scenario,
            errors,
            {"tx_count": len(tx), "receive_count": len(receives)},
        )

    @classmethod
    def _normal(cls, runtime: Any, scenario: str) -> ScenarioMechanismResult:
        records = [
            record
            for record in runtime.normal_disturbances.records.values()
            if record.plan.disturbance_type == scenario
        ]
        errors: list[str] = []
        if len(records) != 1:
            errors.append(f"expected one {scenario} record, found {len(records)}")
            return cls._finish(scenario, errors, {"record_count": len(records)})
        record = records[0]
        plan = record.plan
        evidence = dict(record.evidence)
        if runtime.attack_scheduler.labels():
            errors.append("normal disturbance created an attack label")

        link_aliases = {
            runtime.observable_link_id(link_id) for link_id in plan.target_link_ids
        }
        relevant_phy = [
            event
            for event in runtime.events
            if event.get("event_type") in {"PHY_SAMPLE", "RX_SUCCESS", "RX_FAILURE"}
            and (
                not link_aliases
                or event.get("extensions", {}).get("sample_link_id") in link_aliases
                or event.get("online_features", {})
                .get("packet", {})
                .get("link_id")
                in link_aliases
            )
            and plan.start_s - 1e-12
            <= float(event.get("sim_time_s", -1.0))
            < plan.end_s + 1e-12
        ]

        if scenario == "NORMAL_LOW_SNR":
            snr = [
                event["online_features"]["phy"].get("snr_db")
                for event in relevant_phy
                if isinstance(
                    event.get("online_features", {}).get("phy", {}).get("snr_db"),
                    (int, float),
                )
            ]
            evidence["min_snr_db"] = min(snr) if snr else None
            if not snr or not evidence.get("affected_phy_samples"):
                errors.append("low-SNR profile did not affect an observed PHY sample")
        elif scenario == "NORMAL_PACKET_LOSS":
            failures = [
                event for event in relevant_phy if event.get("event_type") == "RX_FAILURE"
            ]
            evidence["rx_failure_count"] = len(failures)
            if not failures:
                errors.append("normal loss produced no receiver-observed packet loss")
        elif scenario in {"NORMAL_TRAFFIC_BURST", "NORMAL_CONGESTION"}:
            rates = [
                event.get("online_features", {})
                .get("traffic", {})
                .get("packet_rate_pps")
                for event in runtime.events
                if event.get("observer_node_id") in plan.target_node_ids
            ]
            numeric_rates = [value for value in rates if isinstance(value, (int, float))]
            evidence["max_packet_rate_pps"] = max(numeric_rates, default=0.0)
            if int(evidence.get("generated_count", 0)) <= 0:
                errors.append("configured normal load generated no business packets")
            if max(numeric_rates, default=0.0) <= 0.0:
                errors.append("configured normal load caused no receiver-observed rate")
            if scenario == "NORMAL_CONGESTION" and not evidence.get(
                "affected_phy_samples"
            ):
                errors.append("congestion profile did not affect channel occupancy")
        elif scenario == "NORMAL_OUT_OF_ORDER":
            expected = list(plan.parameters.get("sequence_numbers", [100, 102, 101]))
            session = runtime.observable_session_id(
                str(plan.parameters.get("session_id", ""))
            )
            auth = [
                event
                for event in runtime.events
                if event.get("event_type") == "AUTH_RESULT"
                and event.get("online_features", {})
                .get("packet", {})
                .get("session_id")
                == session
            ]
            actual = [
                event["online_features"]["packet"].get("sequence_no") for event in auth
            ]
            results = [
                event["online_features"]["security_state"].get(
                    "replay_check_result"
                )
                for event in auth
            ]
            evidence.update({"observed_sequence_numbers": actual, "results": results})
            if actual != expected or any(result != "PASS" for result in results):
                errors.append("legal out-of-order stream was not accepted in configured order")
        elif scenario == "NORMAL_STATE_CHANGE":
            changes = evidence.get("state_changes", [])
            referenced = {
                change.get("consistent_telemetry_message_id")
                for change in changes
                if isinstance(change, dict)
            }
            event_messages = {
                event.get("message_id")
                for event in runtime.events
                if event.get("event_type") == "TX"
                and event.get("online_features", {})
                .get("packet", {})
                .get("packet_type")
                == "TELEMETRY"
            }
            if not changes or not (referenced & event_messages):
                errors.append("normal state change did not cause consistent telemetry")

        return cls._finish(scenario, errors, evidence)

    @classmethod
    def _attack(cls, runtime: Any, scenario: str) -> ScenarioMechanismResult:
        labels = runtime.attack_scheduler.labels()
        errors: list[str] = []
        if len(labels) != 1:
            errors.append(f"expected one attack label, found {len(labels)}")
            return cls._finish(scenario, errors, {"label_count": len(labels)})
        label = labels[0]
        family = label["attack_family"]
        subtype = label["attack_subtype"]
        truth = label["truth"]
        outcome = label["outcome"]
        evidence: dict[str, Any] = {
            "attack_family": family,
            "attack_subtype": subtype,
            "attempted": outcome.get("attempted"),
            "injected": outcome.get("injected"),
            "reached_target": outcome.get("reached_target"),
            "malicious_content_executed": outcome.get(
                "malicious_content_executed"
            ),
            "attack_effective": outcome.get("attack_effective"),
        }

        if family == "FDI":
            modifications = truth.get("modifications", [])
            evidence["modification_count"] = len(modifications)
            evidence["modified_values"] = [
                item.get("modified_value") for item in modifications
            ]
            if not outcome.get("eligible_opportunity_seen"):
                errors.append("FDI saw no eligible business opportunity")
            if not outcome.get("attempted") or not outcome.get("injected"):
                errors.append("FDI mechanism was not attempted and injected")
            if not modifications:
                errors.append("FDI has no plaintext modification evidence")
            if truth.get("injection_stage") != "POST_HMAC_PRE_TRANSMISSION":
                errors.append("FDI did not mutate after application HMAC")
            if not outcome.get("application_hmac_rejected"):
                errors.append("FDI mutation was not rejected by application HMAC")
            elif subtype == "COMMAND_REPLACEMENT":
                if all(
                    item.get("original_value", {}).get("cmd")
                    == item.get("modified_value", {}).get("cmd")
                    for item in modifications
                ):
                    errors.append("command replacement did not change the command")
            elif subtype == "TELEMETRY_GRADUAL_DRIFT":
                field = str(label.get("parameters", {}).get("field", "altitude_m"))
                values = [
                    item.get("modified_value", {}).get(field) for item in modifications
                ]
                evidence["drift_values"] = values
                if len(values) < 3 or any(
                    not isinstance(value, (int, float)) for value in values
                ):
                    errors.append("gradual drift requires at least three numeric modifications")
                elif not all(left < right for left, right in zip(values, values[1:])):
                    errors.append("gradual drift did not accumulate monotonically")
            elif subtype == "OUT_OF_RANGE_VALUE":
                field = str(label.get("parameters", {}).get("field", "altitude_m"))
                values = [
                    item.get("modified_value", {}).get(field) for item in modifications
                ]
                if not any(isinstance(value, (int, float)) and abs(value) > 1000 for value in values):
                    errors.append("configured out-of-range value was not produced")
            elif subtype == "LOGICAL_INCONSISTENCY":
                if not any(
                    item.get("modified_value", {}).get("flight_state") == "LANDED"
                    and float(item.get("modified_value", {}).get("altitude_m", 0.0)) > 0
                    for item in modifications
                ):
                    errors.append("logical inconsistency evidence is missing")
        elif family == "SPOOFING":
            claimed = truth.get("claimed_src_id")
            actual = truth.get("actual_transmitter_id")
            evidence.update(
                {
                    "claimed_src_id": claimed,
                    "actual_transmitter_id": actual,
                    "identity_conflict": truth.get("identity_conflict"),
                }
            )
            affected = set(truth.get("affected_message_ids", []))
            failures = [
                event
                for event in runtime.events
                if event.get("event_type") == "AUTH_RESULT"
                and event.get("message_id") in affected
                and event.get("online_features", {})
                .get("security_state", {})
                .get("auth_result")
                == "FAIL"
            ]
            evidence["auth_failure_count"] = len(failures)
            if actual == claimed or not outcome.get("injected") or not failures:
                errors.append("spoofing identity conflict/auth-failure mechanism did not occur")
            if truth.get("modified_fields") != ["claimed_src_id"]:
                errors.append("spoofing changed fields other than device identity")
            if subtype == "UNKNOWN_ID" and claimed in runtime.nodes:
                errors.append("UNKNOWN_ID used a registered legitimate identity")
            if subtype == "KNOWN_ID_CONFLICT" and claimed not in runtime.nodes:
                errors.append("KNOWN_ID_CONFLICT did not claim a registered identity")
        elif family == "EAVESDROPPING":
            captured = int(outcome.get("captured_count", 0) or 0)
            ciphertext = int(outcome.get("ciphertext_count", 0) or 0)
            plaintext = int(outcome.get("plaintext_exposure_count", 0) or 0)
            ordinary = int(outcome.get("ordinary_plaintext_count", 0) or 0)
            evidence.update(
                {
                    "captured_count": captured,
                    "ciphertext_count": ciphertext,
                    "plaintext_exposure_count": plaintext,
                    "ordinary_plaintext_count": ordinary,
                    "protection_effective": outcome.get("protection_effective"),
                }
            )
            if captured <= 0:
                errors.append("passive receiver captured no transmission")
            if subtype == "NONSENSITIVE_PLAINTEXT_CONTROL":
                if ordinary <= 0 or ciphertext != 0 or plaintext != 0:
                    errors.append("nonsensitive plaintext control semantics failed")
            elif subtype == "CIPHERTEXT_ONLY":
                if ciphertext <= 0 or plaintext != 0:
                    errors.append("ciphertext-only eavesdropping semantics failed")
                if outcome.get("protection_effective") is not True:
                    errors.append("ciphertext protection was not effective")
            elif subtype == "PLAINTEXT_EXPOSURE" and plaintext <= 0:
                errors.append("sensitive unauthorized plaintext exposure did not occur")
            elif subtype == "PASSIVE_CAPTURE" and (
                ordinary + ciphertext + plaintext <= 0
            ):
                errors.append("passive capture content class was not recorded")
        elif family == "DOS" and subtype == "FLOODING":
            generated = int(truth.get("generated_packets", 0) or 0)
            affected = len(truth.get("affected_message_ids", []))
            rates = [
                event.get("online_features", {})
                .get("traffic", {})
                .get("packet_rate_pps")
                for event in runtime.events
                if event.get("observer_node_id") in label.get("target_node_ids", [])
            ]
            max_rate = max(
                (value for value in rates if isinstance(value, (int, float))),
                default=0.0,
            )
            evidence.update(
                {
                    "generated_packets": generated,
                    "observable_message_count": affected,
                    "max_packet_rate_pps": max_rate,
                    "queued_backlog_count": outcome.get("queued_backlog_count", 0),
                    "receiver_total_rate_exceeded": outcome.get(
                        "receiver_total_rate_exceeded", False
                    ),
                    "hmac_rejected_count": outcome.get(
                        "malicious_traffic_blocked", 0
                    ),
                }
            )
            if generated <= 0 or affected <= 0 or not outcome.get(
                "receiver_total_rate_exceeded", False
            ):
                errors.append("flooding generated no observable target load")
        elif family == "REPLAY":
            captured = int(truth.get("captured_frame_count", 0) or 0)
            replayed = int(truth.get("replay_count", 0) or 0)
            capture_time = truth.get("capture_time_s")
            replay_time = truth.get("replay_time_s")
            checks = [
                event.get("online_features", {})
                .get("security_state", {})
                .get("replay_check_result")
                for event in runtime.events
                if event.get("event_type") == "AUTH_RESULT"
                and event.get("message_id") == truth.get("replayed_message_id")
            ]
            evidence.update(
                {
                    "captured_frame_count": captured,
                    "replay_count": replayed,
                    "capture_time_s": capture_time,
                    "replay_time_s": replay_time,
                    "replay_check_results": checks,
                }
            )
            if captured <= 0 or replayed <= 0 or not outcome.get("injected"):
                errors.append("replay capture/retransmission mechanism did not occur")
            if subtype in {"IMMEDIATE_REPLAY", "CAPTURE_AND_REPLAY"}:
                maximum = float(label.get("parameters", {}).get("max_capture_age_s", 1.0))
                if not isinstance(capture_time, (int, float)) or not isinstance(
                    replay_time, (int, float)
                ) or replay_time - capture_time > maximum + 1e-12:
                    errors.append("immediate replay timing contract failed")
                if "DUPLICATE" not in checks:
                    errors.append("immediate replay was not detected as duplicate")
            elif subtype == "DELAYED_REPLAY":
                delay = float(label.get("parameters", {}).get("delay_s", 0.0))
                if not isinstance(capture_time, (int, float)) or not isinstance(
                    replay_time, (int, float)
                ) or replay_time - capture_time + 1e-12 < delay:
                    errors.append("delayed replay occurred before configured delay")
                if not ({"DUPLICATE", "STALE", "STALE_TIMESTAMP"} & set(checks)):
                    errors.append("delayed replay produced no replay anomaly")
            elif subtype == "OLD_SESSION_REPLAY" and "WRONG_SESSION" not in checks:
                errors.append("old-session replay did not return WRONG_SESSION")

        return cls._finish(scenario, errors, evidence)
