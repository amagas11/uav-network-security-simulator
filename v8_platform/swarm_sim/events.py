"""Frozen schema-3 online event construction and truth-leak prevention."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .domain import EventType, Frame, Message, Node
from .packets import serialized_application_size
from .simulation import RunContext, SCHEMA_VERSION


FORBIDDEN_ONLINE_FIELDS = {
    "is_attacked",
    "attack_type",
    "attack_family",
    "attack_subtype",
    "attacker_node_id",
    "actual_src",
    "actual_transmitter_id",
    "original_command",
    "original_value",
    "modified_value",
    "attack_id",
    "contributing_attack_ids",
    "requested_plan",
    "resolved_plan",
    "attack_engine_jamming_power",
    "dos_jamming_power",
    "is_dos_attack",
    "attack_success",
    "detection_triggered",
    "detection_evidence",
    "defense_action",
    "defense_success",
    "future_event",
    "future_log",
    "offline_defense_success_truth",
    "normal_disturbance",
    "normal_disturbance_type",
    "true_device_id",
    "rff_ground_truth_id",
    "noiseless_rff_vector",
    "device_rff_baseline",
    "noiseless_baseline",
}

LABEL_PROXY_VALUES = {
    "FLOOD",
    "LEGITIMATE_BURST",
    "NORMAL_BURST",
    "SPOOFING",
    "EAVESDROPPING",
    "DOS",
    "FLOODING",
    "JAMMING",
    "FDI",
    "REPLAY",
    "NORMAL_LOW_SNR",
    "NORMAL_PACKET_LOSS",
    "NORMAL_TRAFFIC_BURST",
    "NORMAL_OUT_OF_ORDER",
    "NORMAL_STATE_CHANGE",
    "NORMAL_CONGESTION",
}


def _blank_packet() -> dict[str, Any]:
    return {
        "claimed_src_id": None,
        "claimed_link_sender_id": None,
        "claimed_dst_id": None,
        "packet_type": None,
        "packet_size_bytes": None,
        "sequence_no": None,
        "session_id": None,
        "key_epoch": None,
        "hop_index": None,
        "link_id": None,
        "inter_arrival_s": None,
        "encrypted": None,
        "payload_numeric": None,
        "command_type": None,
    }


def _blank_phy() -> dict[str, Any]:
    return {
        "rssi_dbm": None,
        "snr_db": None,
        "sinr_db": None,
        "noise_power_dbm": None,
        "interference_power_dbm": None,
        "per_estimate": None,
        "decode_success": None,
        "channel_busy_ratio": None,
        "frequency_hz": None,
        "bandwidth_hz": None,
        "channel_id": None,
        "measurement_quality": None,
        "csi_mag_db": None,
        "rf_sample_ref": None,
        "rff_observation": None,
    }


def _blank_traffic() -> dict[str, Any]:
    return {
        "packet_rate_pps": None,
        "total_packet_count": None,
        "statistics_window_s": None,
        "flooding_threshold_pps": None,
        "byte_rate_Bps": None,
        "duplicate_count": None,
        "sequence_gap_count": None,
        "rx_queue_length": None,
        "forward_queue_length": None,
        "drop_count": None,
        "latency_ms": None,
        "throughput_mbps": None,
    }


def _node_state(node: Node) -> dict[str, Any]:
    return {
        "battery_pct": node.battery_pct,
        "flight_state": node.flight_state,
        "network_slice": node.network_slice,
        "position_xyz_m": list(node.position_xyz_m),
        "target_position_xyz_m": list(node.target_position_xyz_m or node.position_xyz_m),
        "velocity_xyz_mps": None,
        "attitude_rpy_deg": None,
        "sensor_quality": None,
        "state_owner_node_id": node.node_id,
    }


def _topology_state(node: Node, leader_id: int | None) -> dict[str, Any]:
    return {
        "neighbor_ids": sorted(node.known_neighbor_ids),
        "neighbor_link_ids": sorted(node.known_neighbor_link_ids),
        "known_bad_link_ids": sorted(node.known_bad_link_ids),
        "local_degree": len(node.known_neighbor_ids),
        "leader_id": leader_id,
        "topology_version": node.known_topology_version,
    }


def _security_state(node: Node) -> dict[str, Any]:
    return {
        "auth_result": "UNAVAILABLE",
        "auth_failure_reason": None,
        "application_hmac_result": "UNAVAILABLE",
        "application_hmac_failure_reason": None,
        "application_hmac_key_id": None,
        "replay_check_result": "UNAVAILABLE",
        "key_state": "UNAVAILABLE",
        "rff_identity_result": node.rff_identity_result,
        "rff_identity_confidence": node.rff_identity_confidence,
        "rff_quality": node.rff_quality,
        "rff_last_update_s": node.rff_last_update_s,
        "rff_predicted_device_id": node.rff_predicted_device_id,
        "rff_claimed_link_sender_id": node.rff_claimed_link_sender_id,
        "rff_distance": node.rff_distance,
        "rff_threshold": node.rff_threshold,
        "rff_reason": node.rff_reason,
    }


def _blank_resource() -> dict[str, Any]:
    return {
        "cpu_pct": None,
        "memory_mb": None,
        "queue_processing_time_ms": None,
        "model_inference_time_ms": None,
    }


def packet_features(
    item: Message | Frame | None,
    *,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = _blank_packet()
    if item is None:
        return result
    result.update(
        {
            "claimed_src_id": item.claimed_src_id,
            "claimed_dst_id": item.claimed_dst_id,
            "packet_type": item.packet_type,
            "sequence_no": item.sequence_no,
            "session_id": getattr(item, "observable_session_id", None)
            or item.session_id,
            "key_epoch": item.key_epoch,
            "encrypted": getattr(item, "encrypted", getattr(item, "encrypt_requested", False)),
        }
    )
    if isinstance(item, Frame):
        result["claimed_link_sender_id"] = item.claimed_link_sender_id
        result["hop_index"] = item.hop_index
        result["link_id"] = item.observable_link_id or item.link_id
        result["packet_size_bytes"] = (
            item.application_size_bytes
            if item.application_size_bytes is not None
            else serialized_application_size(item.protected_payload)
        )
    else:
        result["packet_size_bytes"] = (
            item.application_size_bytes
            if item.application_size_bytes is not None
            else serialized_application_size(item.payload)
        )
    if payload is not None:
        numeric = {
            key: value
            for key, value in payload.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        result["payload_numeric"] = numeric or None
        result["command_type"] = payload.get("cmd") or payload.get("command_type")
    return result


def build_event(
    context: RunContext,
    event_type: EventType | str,
    observer: Node,
    *,
    message: Message | Frame | None = None,
    payload: dict[str, Any] | None = None,
    phy: dict[str, Any] | None = None,
    traffic: dict[str, Any] | None = None,
    security_state: dict[str, Any] | None = None,
    availability: dict[str, Any] | None = None,
    extensions: dict[str, Any] | None = None,
    leader_id: int | None = 1,
) -> dict[str, Any]:
    phy_features = _blank_phy()
    if phy:
        for key in phy_features:
            if key in phy:
                if key == "rff_observation" and isinstance(phy[key], dict):
                    phy_features[key] = {
                        name: deepcopy(phy[key][name])
                        for name in (
                            "sample_id", "feature_schema", "feature_vector", "quality",
                            "extraction_status", "missing_reason",
                        )
                        if name in phy[key]
                    }
                else:
                    phy_features[key] = phy[key]
    traffic_features = _blank_traffic()
    traffic_features.update(
        {
            "rx_queue_length": len(observer.rx_queue),
            "forward_queue_length": len(observer.forward_queue),
            "drop_count": observer.drop_count,
        }
    )
    if traffic:
        for key in traffic_features:
            if key in traffic:
                traffic_features[key] = traffic[key]
    security_features = _security_state(observer)
    if security_state:
        for key in security_features:
            if key in security_state:
                security_features[key] = security_state[key]
    event = {
        "schema_version": SCHEMA_VERSION,
        "run_id": context.run_id,
        "event_id": context.ids.next("evt"),
        "message_id": getattr(message, "message_id", None),
        "sim_time_s": context.clock.now_s,
        "event_type": EventType(event_type).value,
        "observer_node_id": observer.node_id,
        "observer_role": observer.role.value,
        "online_features": {
            "packet": packet_features(message, payload=payload),
            "phy": phy_features,
            "traffic": traffic_features,
            "node_state": _node_state(observer),
            "topology": _topology_state(observer, leader_id),
            "security_state": security_features,
            "resource_state": _blank_resource(),
        },
        "availability": {
            "payload_available": payload is not None,
            "phy_available": phy is not None,
            "sensor_available": False,
            "missing_reason": None if payload is not None or phy is not None else "NOT_APPLICABLE",
            **(availability or {}),
        },
        "extensions": deepcopy(extensions or {}),
    }
    assert_online_truth_free(event)
    return event


def find_forbidden_online_fields(value: Any, prefix: str = "online_features") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if key.lower() in FORBIDDEN_ONLINE_FIELDS:
                found.append(path)
            found.extend(find_forbidden_online_fields(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_forbidden_online_fields(child, f"{prefix}[{index}]"))
    return found


def assert_online_truth_free(event: dict[str, Any]) -> None:
    found = find_forbidden_online_fields(event.get("online_features", {}))
    if found:
        raise ValueError(f"forbidden simulator truth in online event: {', '.join(found)}")


def find_label_proxies(event: dict[str, Any]) -> list[str]:
    """Find scenario-answer literals in raw online observations.

    MODEL_RESULT predictions are deliberately excluded: a model is allowed to
    predict an attack name, while packet/PHY/traffic/node observations are not
    allowed to carry the simulator's answer.
    """

    found: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                normalized_key = str(key).upper()
                if normalized_key in {"NORMAL_DISTURBANCE", "NORMAL_DISTURBANCE_TYPE"}:
                    found.append(child_path)
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        elif isinstance(value, str):
            normalized = value.upper()
            if normalized in LABEL_PROXY_VALUES or normalized.startswith("ATTACK_"):
                found.append(path)

    visit(event.get("online_features", {}), "online_features")
    visit(event.get("availability", {}), "availability")
    if event.get("event_type") != "MODEL_RESULT":
        extensions = event.get("extensions", {})
        if isinstance(extensions, dict):
            raw_extensions = {
                key: value
                for key, value in extensions.items()
                if key
                not in {
                    "model_result",
                    "defense_result",
                    "decision_audit",
                    "redundancy_event",
                    "security_report",
                    "aggregated_report",
                }
            }
            visit(raw_extensions, "extensions")
    return sorted(set(found))
