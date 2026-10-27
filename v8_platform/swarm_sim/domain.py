"""Domain objects kept independent from simulator-global truth."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque


class NodeRole(str, Enum):
    GCS = "GCS"
    LEADER = "LEADER"
    FOLLOWER = "FOLLOWER"
    EXTERNAL = "EXTERNAL"


class RunState(str, Enum):
    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"


class EventType(str, Enum):
    TX = "TX"
    RX_SUCCESS = "RX_SUCCESS"
    RX_FAILURE = "RX_FAILURE"
    PHY_SAMPLE = "PHY_SAMPLE"
    QUEUE_SAMPLE = "QUEUE_SAMPLE"
    NODE_STATE = "NODE_STATE"
    TOPOLOGY_UPDATE = "TOPOLOGY_UPDATE"
    AUTH_RESULT = "AUTH_RESULT"
    MODEL_RESULT = "MODEL_RESULT"
    DEFENSE_RESULT = "DEFENSE_RESULT"


@dataclass(slots=True)
class Message:
    message_id: str
    origin_node_id: int
    final_dst_node_id: int
    claimed_src_id: int | None
    claimed_dst_id: int | None
    packet_type: str
    payload: dict[str, Any]
    sequence_no: int
    session_id: str
    key_epoch: int | str
    created_time_s: float
    route: list[int]
    application_size_bytes: int | None = None
    sensitive: bool = False
    encrypt_requested: bool = False
    extensions: dict[str, Any] = field(default_factory=dict)
    # Runtime-only provenance for a concrete malicious transmission.  It is
    # deliberately excluded from packet_features/events and labels remain the
    # sole offline truth store.
    runtime_attack_id: str | None = None
    # C-facing aliases are opaque and never used by crypto/replay semantics.
    observable_session_id: str | None = None
    # End-to-end application authentication.  This is deliberately separate
    # from Frame.auth_tag (hop crypto/AES authentication).
    application_direction: str | None = None
    app_hmac_tag: str | None = None
    app_hmac_key_id: str | None = None

    def clone(self) -> "Message":
        return deepcopy(self)


@dataclass(slots=True)
class TransmissionIntent:
    message: Message
    hop_index: int = 0
    replay_frame: "Frame | None" = None
    claimed_link_sender_id: int | None = None


@dataclass(slots=True)
class Frame:
    message_id: str
    claimed_src_id: int | None
    claimed_dst_id: int | None
    packet_type: str
    sequence_no: int
    session_id: str
    key_epoch: int | str
    hop_index: int
    link_id: str
    link_sender_id: int
    link_receiver_id: int
    protected_payload: dict[str, Any]
    encrypted: bool
    auth_tag: str | None
    nonce_b64: str | None
    sensitive: bool
    created_time_s: float
    route: list[int]
    application_size_bytes: int | None = None
    extensions: dict[str, Any] = field(default_factory=dict)
    runtime_attack_id: str | None = None
    observable_session_id: str | None = None
    observable_link_id: str | None = None
    application_direction: str | None = None
    app_hmac_tag: str | None = None
    app_hmac_key_id: str | None = None
    claimed_link_sender_id: int | None = None

    def clone_for_replay(self) -> "Frame":
        return deepcopy(self)


@dataclass(slots=True)
class ReceivedFrame:
    frame: Frame
    phy: dict[str, Any]
    received_time_s: float
    # Runtime-only cache for the plaintext pre-ingress HMAC gate.  Primitive
    # fields keep the domain layer independent from application_auth types and
    # prevent a PASS frame from being verified/emitted twice during RX service.
    application_hmac_checked: bool = False
    application_hmac_result: str | None = None
    application_hmac_failure_reason: str | None = None
    application_hmac_key_id: str | None = None
    rff_security_state: dict[str, Any] = field(default_factory=dict)
    rx_event_id: str | None = None
    air_emission_ref: str | None = None


@dataclass(frozen=True, slots=True)
class BusinessApplyResult:
    """Result returned by the target's actual business handler."""

    accepted: bool
    executed: bool
    state_changed: bool
    rejection_reason: str | None = None
    mission_effect: float | None = None


@dataclass(slots=True)
class Node:
    node_id: int
    role: NodeRole
    position_xyz_m: tuple[float, float, float]
    queue_capacity: int
    tx_queue: Deque[TransmissionIntent] = field(default_factory=deque)
    forward_queue: Deque[TransmissionIntent] = field(default_factory=deque)
    rx_queue: Deque[ReceivedFrame] = field(default_factory=deque)
    delivered_messages: list[Message] = field(default_factory=list)
    known_neighbor_ids: set[int] = field(default_factory=set)
    known_neighbor_link_ids: set[str] = field(default_factory=set)
    known_bad_link_ids: set[str] = field(default_factory=set)
    known_topology_version: int = 0
    local_security_cache: list[dict[str, Any]] = field(default_factory=list)
    sequence_counter: int = 0
    battery_pct: float = 100.0
    flight_state: str = "DISARMED"
    network_slice: str = "URLLC"
    target_position_xyz_m: tuple[float, float, float] | None = None
    monitoring_level: int = 0
    isolated_peer_ids: set[int] = field(default_factory=set)
    rate_limited_peer_ids: set[int] = field(default_factory=set)
    key_epoch: int | str = 1
    program_authorized: bool = False
    network_authorized: bool = False
    lifecycle_state: str = "INITIALIZED"
    drop_count: int = 0
    received_count: int = 0
    forwarded_count: int = 0
    rff_identity_result: str | None = None
    rff_identity_confidence: float | None = None
    rff_quality: float | None = None
    rff_last_update_s: float | None = None
    rff_predicted_device_id: int | None = None
    rff_claimed_link_sender_id: int | None = None
    rff_distance: float | None = None
    rff_threshold: float | None = None
    rff_reason: str | None = None
    rff_policy_state: str | None = None
    rff_strict_since_s: float | None = None
    rff_clear_since_s: float | None = None
    opaque_received_count: int = 0
    opaque_delivered_count: int = 0
    rff_anomaly_count: int = 0
    protected_sensitive_count: int = 0
    unprotected_sensitive_count: int = 0
    telemetry_by_source: dict[int, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.target_position_xyz_m is None:
            self.target_position_xyz_m = self.position_xyz_m

    def next_sequence(self) -> int:
        self.sequence_counter += 1
        return self.sequence_counter

    def enqueue_tx(self, intent: TransmissionIntent) -> bool:
        if len(self.tx_queue) >= self.queue_capacity:
            self.drop_count += 1
            return False
        self.tx_queue.append(intent)
        return True

    def enqueue_forward(self, intent: TransmissionIntent) -> bool:
        if len(self.forward_queue) >= self.queue_capacity:
            self.drop_count += 1
            return False
        self.forward_queue.append(intent)
        return True

    def enqueue_rx(self, received: ReceivedFrame) -> bool:
        if len(self.rx_queue) >= self.queue_capacity:
            self.drop_count += 1
            return False
        self.rx_queue.append(received)
        return True

    def reset_transient(self) -> None:
        self.tx_queue.clear()
        self.forward_queue.clear()
        self.rx_queue.clear()
        self.delivered_messages.clear()
        self.known_bad_link_ids.clear()
        self.local_security_cache.clear()
        self.sequence_counter = 0
        self.monitoring_level = 0
        self.isolated_peer_ids.clear()
        self.rate_limited_peer_ids.clear()
        self.program_authorized = False
        self.network_authorized = False
        self.lifecycle_state = "INITIALIZED"
        self.drop_count = 0
        self.received_count = 0
        self.forwarded_count = 0
        self.rff_identity_result = None
        self.rff_identity_confidence = None
        self.rff_quality = None
        self.rff_last_update_s = None
        self.rff_predicted_device_id = None
        self.rff_claimed_link_sender_id = None
        self.rff_distance = None
        self.rff_threshold = None
        self.rff_reason = None
        self.rff_policy_state = None
        self.rff_strict_since_s = None
        self.rff_clear_since_s = None
        self.opaque_received_count = 0
        self.opaque_delivered_count = 0
        self.rff_anomaly_count = 0
        self.protected_sensitive_count = 0
        self.unprotected_sensitive_count = 0
        self.telemetry_by_source.clear()
