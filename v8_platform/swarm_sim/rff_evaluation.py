"""Offline causal evaluation of physical identity decisions, never policy input."""

from __future__ import annotations

import math
from statistics import mean
from typing import Any


FAMILIES = ("SPOOFING", "FDI", "DOS", "REPLAY", "EAVESDROPPING")


def _qualified(event: dict[str, Any]) -> bool:
    online = event.get("online_features", {})
    observation = online.get("phy", {}).get("rff_observation") or {}
    quality = observation.get("quality")
    claim = online.get("packet", {}).get("claimed_link_sender_id")
    return (
        observation.get("extraction_status") == "AVAILABLE"
        and isinstance(quality, (int, float)) and not isinstance(quality, bool)
        and math.isfinite(quality) and 0 <= quality <= 1
        and isinstance(claim, int) and not isinstance(claim, bool)
    )


def evaluate_rff(events: list[dict[str, Any]], labels: list[dict[str, Any]], *,
                 transmissions: list[dict[str, Any]], legitimate_node_ids: list[int],
                 enabled: bool, policy_mode: str) -> dict[str, Any]:
    """Join exact air emissions to independent truth after the run."""
    legal = set(legitimate_node_ids)
    emissions = {item["emission_id"]: item for item in transmissions if item.get("emission_id")}
    receives: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for event in events:
        if event.get("event_type") not in {"RX_SUCCESS", "RX_FAILURE"}:
            continue
        extension = event.get("extensions", {})
        emission = emissions.get(extension.get("air_emission_ref"))
        if (emission is None or emission.get("receiver_id") != event.get("observer_node_id")
                or not isinstance(extension.get("rff_decision"), dict)):
            continue
        receives.setdefault(str(event["event_id"]), (event, emission))

    episodes = []
    for label in labels:
        family = str(label.get("attack_family", "")).upper()
        if family not in FAMILIES:
            continue
        targets = set(label.get("target_node_ids", []))
        external = {key for key, item in emissions.items()
                    if item.get("attack_id") == label.get("attack_id")
                    and item.get("actual_sender_id") not in legal
                    and item.get("receiver_id") in targets}
        owned = [event for event, emission in receives.values()
                 if emission["emission_id"] in external]
        qualified = [event for event in owned if enabled and _qualified(event)]
        confirmed = [event for event in qualified
                     if event["extensions"]["rff_decision"].get("confirmed_identity_anomaly") is True]
        opportunities = [event for event in qualified if event["event_type"] == "RX_SUCCESS"]
        blocked = [event for event in opportunities if policy_mode == "ENFORCE"
                   and event["extensions"]["rff_decision"].get("drop") is True]
        reason = (
            "RFF_DISABLED" if not enabled else
            "PASSIVE_EAVESDROPPING_NOT_OBSERVABLE" if family == "EAVESDROPPING" else
            "NO_EXTERNAL_RETRANSMISSION" if not external else
            "NO_TARGET_RECEPTION" if not owned else
            "NO_QUALIFIED_RFF_SAMPLE" if not qualified else None
        )
        if family == "EAVESDROPPING":
            qualified, confirmed, opportunities, blocked = [], [], [], []
        detection_time = min((float(event["sim_time_s"]) for event in confirmed), default=None)
        episodes.append({
            "attack_id": label.get("attack_id"), "attack_family": family,
            "observable": bool(qualified), "unavailable_reason": reason,
            "received_attack_samples": len(owned), "qualified_attack_samples": len(qualified),
            "detected": bool(confirmed), "confirmed_samples": len(confirmed),
            "defense_opportunities": len(opportunities), "blocked_samples": len(blocked),
            "detection_time_s": detection_time,
            "detection_delay_s": max(0.0, detection_time - float(label.get("impact_start_s", 0)))
                if detection_time is not None else None,
        })

    by_family = {}
    for family in FAMILIES:
        rows = [row for row in episodes if row["attack_family"] == family]
        observed = sum(row["observable"] for row in rows)
        detected = sum(row["detected"] for row in rows)
        opportunities = sum(row["defense_opportunities"] for row in rows)
        blocked = sum(row["blocked_samples"] for row in rows)
        delays = [row["detection_delay_s"] for row in rows if row["detection_delay_s"] is not None]
        by_family[family] = {
            "episodes": len(rows), "observable_episodes": observed,
            "detected_episodes": detected, "detection_rate": detected / observed if observed else None,
            "qualified_attack_samples": sum(row["qualified_attack_samples"] for row in rows),
            "confirmed_samples": sum(row["confirmed_samples"] for row in rows),
            "defense_opportunities": opportunities, "blocked_samples": blocked,
            "block_rate": blocked / opportunities if opportunities and policy_mode == "ENFORCE" else None,
            "mean_detection_delay_s": mean(delays) if delays else None,
        }
    normal = [event for event, emission in receives.values()
              if enabled and emission.get("attack_id") is None
              and emission.get("actual_sender_id") in legal
              and event.get("observer_node_id") in legal and _qualified(event)]
    false_positives = sum(event["extensions"]["rff_decision"].get("confirmed_identity_anomaly") is True
                          for event in normal)
    unverified_drops = sum(
        policy_mode == "ENFORCE" and event["extensions"]["rff_decision"].get("drop") is True
        and event["extensions"]["rff_decision"].get("confirmed_identity_anomaly") is not True
        for event, _ in receives.values() if event["event_type"] == "RX_SUCCESS"
    )
    return {
        "scope": "OFFLINE_CAUSAL_PHYSICAL_IDENTITY_EVALUATION", "enabled": enabled,
        "policy_mode": policy_mode, "classification": "GENERIC_PHYSICAL_IDENTITY_ONLY",
        "by_family": by_family, "episodes": episodes,
        "normal_qualified_samples": len(normal), "false_positive_samples": false_positives,
        "false_positive_rate": false_positives / len(normal) if normal else None,
        "protective_unverified_drops": unverified_drops,
    }
