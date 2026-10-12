"""Additive offline target-node evaluation; never an input to security decisions.

Positive units are episode/target-node pairs. Negative units are complete,
fixed, target-node time windows with at least one real decoded arrival. The
receiver lookback interval must not overlap an attack (including its tail).
This measures alarm entries, not an unobserved continuous detector state.
Legacy network evaluation is deliberately left untouched.
"""
from __future__ import annotations

from statistics import mean
from typing import Any


def evaluate_dos_targets(events: list[dict[str, Any]], labels: list[dict[str, Any]],
                         duration_s: float, window_s: float = 1.0,
                         receiver_window_s: float = 1.0, grace_s: float = 0.0,
                         enabled: bool = True) -> dict[str, Any]:
    episodes = [label for label in labels if str(label.get("attack_family", "")).upper() == "DOS"]
    targets = sorted({int(node) for label in episodes for node in label.get("target_node_ids", [])})
    applicable = enabled and bool(targets)
    decisions = []
    for event in events:
        result = event.get("extensions", {}).get("model_result", {})
        if event.get("event_type") != "MODEL_RESULT" or str(result.get("predicted_label", "")).upper() != "DOS":
            continue
        decisions.append({"event_id": event.get("event_id"), "result_id": result.get("result_id"),
                          "observer_node_id": event.get("observer_node_id"),
                          "time_s": float(event.get("sim_time_s", 0)),
                          "evidence_event_ids": result.get("evidence_event_ids", [])})
    positives, negatives, excluded, delays = [], [], [], []
    matched_ids: set[str] = set()
    if applicable:
        for label in episodes:
            start, end = float(label["impact_start_s"]), float(label["end_s"])
            for node in sorted(set(label.get("target_node_ids", []))):
                matches = [d for d in decisions if d["observer_node_id"] == node and start <= d["time_s"] <= end + grace_s]
                matched_ids.update(str(d["event_id"]) for d in matches)
                delay = min(d["time_s"] for d in matches) - start if matches else None
                if delay is not None:
                    delays.append(delay)
                positives.append({"attack_id": label.get("attack_id"), "target_node_id": node,
                                  "start_s": start, "end_s": end, "classification": "TP" if matches else "FN",
                                  "decision_event_ids": [d["event_id"] for d in matches], "detection_delay_s": delay})
        for node in targets:
            node_episodes = [label for label in episodes if node in label.get("target_node_ids", [])]
            index = 0
            while index * window_s < duration_s - 1e-12:
                start, end = index * window_s, min(duration_s, (index + 1) * window_s)
                index += 1
                row: dict[str, Any] = {"target_node_id": node, "start_s": start, "end_s": end,
                                       "receiver_lookback_start_s": max(0.0, start - receiver_window_s)}
                if end - start < window_s - 1e-9:
                    row["reason"] = "INCOMPLETE_NORMAL_WINDOW"
                elif any(float(l["impact_start_s"]) < end and float(l["end_s"]) + receiver_window_s >= start - 1e-9 for l in node_episodes):
                    row["reason"] = "ATTACK_OR_RECEIVER_LOOKBACK_TAIL"
                else:
                    arrivals = [e for e in events if e.get("event_type") == "RX_SUCCESS"
                                and e.get("observer_node_id") == node and start <= float(e.get("sim_time_s", 0)) < end]
                    if not arrivals:
                        row["reason"] = "NO_DECODED_ARRIVAL_OBSERVATION"
                    else:
                        alarms = [d for d in decisions if d["observer_node_id"] == node and start <= d["time_s"] < end]
                        row.update({"classification": "FP" if alarms else "TN",
                                    "arrival_event_ids": [e.get("event_id") for e in arrivals],
                                    "decision_event_ids": [d["event_id"] for d in alarms]})
                        negatives.append(row)
                        continue
                excluded.append(row)
    tp = sum(p["classification"] == "TP" for p in positives)
    fn = len(positives) - tp
    fp = sum(n["classification"] == "FP" for n in negatives)
    tn = len(negatives) - fp
    return {"scope": "ATTACK_TARGET_RECEIVER", "applicable": applicable,
            "target_node_ids": targets, "TP": tp if applicable else None, "FN": fn if applicable else None,
            "FP": fp if applicable else None, "TN": tn if applicable else None,
            "recall_pd": tp / len(positives) if positives else None,
            "pfa_fpr": fp / len(negatives) if negatives else None,
            "normal_window_count": len(negatives), "mean_detection_delay_s": mean(delays) if delays else None,
            "target_alarm_count": sum(d["observer_node_id"] in targets for d in decisions),
            "non_target_alarm_count": sum(d["observer_node_id"] not in targets for d in decisions),
            "positive_units": positives, "normal_windows": negatives, "excluded_windows": excluded,
            "decisions": [{**d, "is_target": d["observer_node_id"] in targets,
                           "matched_attack_episode": str(d["event_id"]) in matched_ids} for d in decisions],
            "metric_definitions": {"positive_unit": "ATTACK_EPISODE_TARGET_NODE_PAIR",
                                   "negative_unit": "FULL_OBSERVED_TARGET_NODE_TIME_WINDOW_OUTSIDE_ATTACK_AND_RECEIVER_LOOKBACK_TAIL",
                                   "normal_window_s": window_s, "receiver_lookback_s": receiver_window_s,
                                   "alarm_semantics": "THRESHOLD_ENTRY_REPORT_NOT_CONTINUOUS_STATE",
                                   "missing_normal_samples": "N/A; no claim of zero false positives"}}
