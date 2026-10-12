"""Node-local deterministic rules and authorized defense execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .adapters import KeyProvider
from .domain import Frame, Node
from .flood_defense import AdmissionDecision, FloodDefenseController, FloodDefenseState
from .network import FormationTopology
from .phy import PersistentPhyModel


class DefenseAction(str, Enum):
    DROP_PACKET = "DROP_PACKET"
    RATE_LIMIT = "RATE_LIMIT"
    DATA_ISOLATION = "DATA_ISOLATION"
    TRUSTED_STATE_ROLLBACK = "TRUSTED_STATE_ROLLBACK"
    CHANNEL_SWITCH = "CHANNEL_SWITCH"
    REROUTE = "REROUTE"
    REAUTH_REKEY_REQUEST = "REAUTH_REKEY_REQUEST"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    NO_CHANGE = "NO_CHANGE"


@dataclass(slots=True)
class Detection:
    label: str
    confidence: float
    evidence: dict[str, Any]
    recommended_action: DefenseAction
    high_certainty: bool = False


@dataclass(slots=True)
class ReplayWindow:
    highest: int = -1
    seen: set[int] = field(default_factory=set)


class DeterministicRuleEngine:
    """Receiver-local HMAC, aggregate-rate, session, and replay rules."""

    def __init__(
        self,
        replay_window_size: int = 32,
        *,
        replay_timestamp_freshness_s: float = 2.0,
        traffic_window_s: float = 1.0,
        flooding_threshold_pps: float = 8.0,
        flooding_detection_enabled: bool = True,
        flooding_severe_rate_multiplier: float = 1.5,
        flooding_sustained_overload_s: float = 0.5,
        flooding_recovery_rate_multiplier: float = 0.7,
        flooding_recovery_hold_s: float = 2.0,
        flooding_token_refill_rate_pps: float = 8.0,
        flooding_token_bucket_capacity: float = 12.0,
    ) -> None:
        self.replay_window_size = replay_window_size
        self.replay_timestamp_freshness_s = float(replay_timestamp_freshness_s)
        self.traffic_window_s = float(traffic_window_s)
        self.flooding_threshold_pps = float(flooding_threshold_pps)
        self.flooding_detection_enabled = flooding_detection_enabled
        self._replay: dict[tuple[int, int, int, str, str], ReplayWindow] = {}
        self._active_sessions: dict[
            tuple[int, int, int], set[tuple[str, str]]
        ] = {}
        self._stale_sessions: set[tuple[int, int, int, str, str]] = set()
        self._flood_defense = FloodDefenseController(
            window_s=self.traffic_window_s,
            alert_threshold_pps=self.flooding_threshold_pps,
            severe_multiplier=flooding_severe_rate_multiplier,
            sustained_overload_s=flooding_sustained_overload_s,
            recovery_multiplier=flooding_recovery_rate_multiplier,
            recovery_hold_s=flooding_recovery_hold_s,
            token_refill_rate_pps=flooding_token_refill_rate_pps,
            token_bucket_capacity=flooding_token_bucket_capacity,
            enabled=self.flooding_detection_enabled,
        )
        self._observed_flood_state = FloodDefenseState.NORMAL.value

    def record_arrival(
        self, sim_time_s: float
    ) -> tuple[Detection | None, dict[str, object]]:
        """Count every successfully decoded arrival before application HMAC."""

        snapshot = self._flood_defense.record_arrival(sim_time_s)
        statistics = self._flood_statistics(snapshot)
        detection = self._flood_transition_detection(snapshot, statistics)
        self._observed_flood_state = str(snapshot["state"])
        return detection, statistics

    def _flood_statistics(self, snapshot: dict[str, object]) -> dict[str, object]:
        state = str(snapshot["state"])
        rate = float(snapshot["rate_pps"])
        return {
            "packet_rate_pps": round(rate, 6),
            "total_packet_count": int(snapshot["arrival_count"]),
            "statistics_window_s": self.traffic_window_s,
            "flooding_threshold_pps": self.flooding_threshold_pps,
            "dos_defense_state": state,
            "alert_threshold_pps": snapshot["alert_threshold_pps"],
            "severe_threshold_pps": snapshot["severe_threshold_pps"],
            "recovery_threshold_pps": snapshot["recovery_threshold_pps"],
            "rate_limit_active": state == FloodDefenseState.LIMITING.value,
        }

    def _flood_transition_detection(
        self, snapshot: dict[str, object], statistics: dict[str, object]
    ) -> Detection | None:
        state = str(snapshot["state"])
        if not self.flooding_detection_enabled or state == self._observed_flood_state:
            return None

        action_by_state = {
            FloodDefenseState.ALERT.value: DefenseAction.INCREASE_MONITORING,
            FloodDefenseState.LIMITING.value: DefenseAction.RATE_LIMIT,
        }
        action = action_by_state.get(state)
        if action is None:
            return None

        rate = float(snapshot["rate_pps"])
        evidence = {
            **snapshot,
            **statistics,
            "observable_subtype": "FLOODING",
            "window_s": self.traffic_window_s,
            "threshold_pps": self.flooding_threshold_pps,
            "scope": "RECEIVER_TOTAL_ARRIVALS",
        }
        return Detection(
            "DOS",
            min(1.0, 0.75 + 0.02 * max(0.0, rate - self.flooding_threshold_pps)),
            evidence,
            action,
        )

    def advance_flood_defense(
        self, sim_time_s: float
    ) -> tuple[Detection | None, dict[str, object]]:
        snapshot = self._flood_defense.advance(sim_time_s)
        previous = self._observed_flood_state
        current = str(snapshot["state"])
        detection = self._flood_transition_detection(
            snapshot, self._flood_statistics(snapshot)
        )
        self._observed_flood_state = current
        return detection, {
            **snapshot,
            "transitioned": current != previous,
            "transition_from": previous if current != previous else None,
            "transition_to": current if current != previous else None,
        }

    def admit_flood_pre_auth(
        self,
        sim_time_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str | None = None,
    ) -> AdmissionDecision:
        decision = self._flood_defense.admit_pre_auth(
            sim_time_s, link_sender_id, link_id, reservation_id
        )
        return decision

    def admit_flood_post_auth(
        self, sim_time_s: float, authenticated_device_id: int
    ) -> AdmissionDecision:
        decision = self._flood_defense.admit_post_auth(
            sim_time_s, authenticated_device_id
        )
        return decision

    def release_flood_pre_auth(
        self,
        sim_time_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str,
    ) -> None:
        self._flood_defense.release_pre_auth(
            sim_time_s, link_sender_id, link_id, reservation_id
        )

    def finalize_flood_pre_auth(
        self,
        sim_time_s: float,
        link_sender_id: int,
        link_id: str,
        reservation_id: str,
    ) -> None:
        self._flood_defense.finalize_pre_auth(
            sim_time_s, link_sender_id, link_id, reservation_id
        )

    def flood_defense_snapshot(self, sim_time_s: float) -> dict[str, object]:
        return self._flood_defense.snapshot(sim_time_s)

    def record_flood_hmac_rejection(self) -> None:
        self._flood_defense.record_hmac_rejection()

    def activate_session(
        self,
        sender_id: int,
        receiver_id: int,
        session_id: str,
        key_epoch: int | str,
        *,
        sequence_namespace: int | None = None,
    ) -> None:
        """Register a session established by the legitimate protocol path.

        Replay transmissions never call this method, so a stale frame cannot
        turn its own session into the receiver's current session.
        """

        namespace = int(
            sender_id if sequence_namespace is None else sequence_namespace
        )
        direction = (int(sender_id), int(receiver_id), namespace)
        current = (str(session_id), str(key_epoch))
        active = self._active_sessions.setdefault(direction, set())

        # Several end-to-end business sessions may legitimately share one
        # immediate hop.  They remain active together while they use the same
        # hop key epoch.  A key epoch transition, however, retires every old
        # cryptographic context in this sequence namespace.
        for previous in tuple(active):
            if previous[1] == current[1]:
                continue
            active.remove(previous)
            self._stale_sessions.add((*direction, previous[0], previous[1]))
        active.add(current)
        self._stale_sessions.discard((*direction, current[0], current[1]))
        self._replay.setdefault(
            (*direction, current[0], current[1]), ReplayWindow()
        )

    def expire_session(
        self,
        sender_id: int,
        receiver_id: int,
        session_id: str,
        key_epoch: int | str,
        *,
        sequence_namespace: int | None = None,
    ) -> None:
        """Mark a receiver-known security context stale.

        This method is a receiver-side lifecycle primitive.  It is called by
        legitimate session rotation/expiration paths, never by attack replay
        injection.  Replay traffic cannot activate or silently retire context.
        """

        namespace = int(
            sender_id if sequence_namespace is None else sequence_namespace
        )
        direction = (int(sender_id), int(receiver_id), namespace)
        session = (str(session_id), str(key_epoch))
        self._active_sessions.setdefault(direction, set()).discard(session)
        self._stale_sessions.add((*direction, session[0], session[1]))

    def inspect(
        self,
        frame: Frame,
        payload: dict[str, Any] | None,
        phy: dict[str, Any],
        node: Node,
        sim_time_s: float,
        *,
        auth_result: str,
        auth_failure_reason: str | None,
        key_state: str,
        application_hmac_result: str,
        application_hmac_failure_reason: str | None,
        application_hmac_key_id: str | None,
    ) -> tuple[Detection | None, dict[str, Any]]:
        security_state = {
            "auth_result": auth_result,
            "auth_failure_reason": auth_failure_reason,
            "replay_check_result": "UNAVAILABLE",
            "key_state": key_state,
            "application_hmac_result": application_hmac_result,
            "application_hmac_failure_reason": application_hmac_failure_reason,
            "application_hmac_key_id": application_hmac_key_id,
        }
        if auth_result == "FAIL":
            return (
                Detection(
                    "AUTH_FAILURE",
                    1.0,
                    {
                        "auth_result": "FAIL",
                        "reason": auth_failure_reason,
                        "authentication_layer": "CRYPTO",
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )
        if auth_result != "PASS":
            return None, security_state
        if application_hmac_result == "NOT_APPLICABLE":
            # SKG control has its own Ed25519 identity signature and internal
            # handshake replay/scope checks. It must reach that handler rather
            # than being interpreted as ordinary replay-window traffic.
            return None, security_state
        if application_hmac_result != "PASS":
            security_state["auth_result"] = "FAIL"
            security_state["auth_failure_reason"] = application_hmac_failure_reason
            return (
                Detection(
                    "AUTH_FAILURE",
                    1.0,
                    {
                        "application_hmac_result": application_hmac_result,
                        "reason": application_hmac_failure_reason,
                        "authentication_layer": "APPLICATION_HMAC",
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )

        # Presentation evidence only: reaching any Replay decision below
        # proves that the online Application HMAC verifier returned PASS.
        # Keeping the already-observed sequence alongside that result lets the
        # GCS report explain the decision without consulting attack truth or
        # offline evaluation.  Neither value changes the decision path.
        replay_evidence = {
            "application_hmac_result": application_hmac_result,
            "sequence_no": frame.sequence_no,
        }
        age_s = float(sim_time_s) - float(frame.created_time_s)
        if age_s < -1e-9:
            security_state["replay_check_result"] = "INVALID_TIMESTAMP"
            return (
                Detection(
                    "REPLAY",
                    1.0,
                    {
                        **replay_evidence,
                        "replay_check_result": "INVALID_TIMESTAMP",
                        "age_s": age_s,
                        "freshness_s": self.replay_timestamp_freshness_s,
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )
        if age_s > self.replay_timestamp_freshness_s + 1e-12:
            security_state["replay_check_result"] = "STALE_TIMESTAMP"
            return (
                Detection(
                    "REPLAY",
                    1.0,
                    {
                        **replay_evidence,
                        "replay_check_result": "STALE_TIMESTAMP",
                        "age_s": round(age_s, 9),
                        "freshness_s": self.replay_timestamp_freshness_s,
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )

        sequence_namespace = int(
            frame.claimed_src_id
            if frame.claimed_src_id is not None
            else frame.link_sender_id
        )
        direction = (frame.link_sender_id, node.node_id, sequence_namespace)
        frame_session = (str(frame.session_id), str(frame.key_epoch))
        replay_key = (*direction, frame_session[0], frame_session[1])
        active_sessions = self._active_sessions.get(direction)
        if replay_key in self._stale_sessions:
            security_state["replay_check_result"] = "WRONG_SESSION"
            return (
                Detection(
                    "REPLAY",
                    1.0,
                    {
                        **replay_evidence,
                        "replay_check_result": "WRONG_SESSION",
                        "presented_session_id": frame.session_id,
                        "active_session_ids": sorted(
                            session_id
                            for session_id, _ in (active_sessions or set())
                        ),
                        "sequence_namespace": sequence_namespace,
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )
        if active_sessions is None:
            # Compatibility for direct callers: the first authenticated frame
            # establishes the initial session. Runtime traffic registers it
            # before transmission through ``activate_session``.
            active_sessions = {frame_session}
            self._active_sessions[direction] = active_sessions
        if frame_session not in active_sessions:
            security_state["replay_check_result"] = "WRONG_SESSION"
            return (
                Detection(
                    "REPLAY",
                    1.0,
                    {
                        **replay_evidence,
                        "replay_check_result": "WRONG_SESSION",
                        "presented_session_id": frame.session_id,
                        "active_session_ids": sorted(
                            session_id for session_id, _ in active_sessions
                        ),
                        "sequence_namespace": sequence_namespace,
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )

        window = self._replay.setdefault(replay_key, ReplayWindow())
        sequence = frame.sequence_no
        if sequence in window.seen:
            security_state["replay_check_result"] = "DUPLICATE"
            return (
                Detection(
                    "REPLAY",
                    1.0,
                    {
                        **replay_evidence,
                        "replay_check_result": "DUPLICATE",
                    },
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )
        if window.highest >= 0 and sequence < window.highest - self.replay_window_size:
            security_state["replay_check_result"] = "STALE"
            return (
                Detection(
                    "REPLAY",
                    0.98,
                    {**replay_evidence, "replay_check_result": "STALE"},
                    DefenseAction.DROP_PACKET,
                    high_certainty=True,
                ),
                security_state,
            )
        window.seen.add(sequence)
        window.highest = max(window.highest, sequence)
        cutoff = window.highest - self.replay_window_size
        window.seen = {value for value in window.seen if value >= cutoff}
        security_state["replay_check_result"] = "PASS"

        return None, security_state

    @staticmethod
    def inspect_phy_sample(phy: dict[str, Any]) -> Detection | None:
        """PHY remains observable, but no PHY condition is a DoS attack label."""
        return None

    def reset(self) -> None:
        self._replay.clear()
        self._active_sessions.clear()
        self._stale_sessions.clear()
        self._flood_defense.reset()
        self._observed_flood_state = FloodDefenseState.NORMAL.value


@dataclass(slots=True)
class DefenseRequest:
    request_id: str
    action: DefenseAction
    requester_node_id: int
    target_node_id: int | None = None
    target_link_id: str | None = None
    peer_id: int | None = None
    session_id: str | None = None
    requested_time_s: float = 0.0
    reason: str | None = None
    outcome_scope: str | None = None


@dataclass(slots=True)
class DefenseResult:
    request: dict[str, Any]
    permission: str
    target: dict[str, Any]
    requested_time_s: float
    executed_time_s: float | None
    allowed: bool
    executed: bool
    failure_reason: str | None
    outcome: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DefenseExecutor:
    def __init__(
        self,
        topology: FormationTopology,
        phy: PersistentPhyModel,
        key_provider: KeyProvider,
    ) -> None:
        self.topology = topology
        self.phy = phy
        self.key_provider = key_provider

    def execute(
        self,
        request: DefenseRequest,
        node: Node,
        sim_time_s: float,
    ) -> DefenseResult:
        allowed = request.requester_node_id == node.node_id
        failure: str | None = None
        executed = False
        action = request.action
        if not allowed:
            failure = "REQUESTER_NOT_AUTHORIZED_FOR_NODE"
        elif action == DefenseAction.NO_CHANGE:
            executed = True
        elif action == DefenseAction.DROP_PACKET:
            executed = True
        elif action == DefenseAction.RATE_LIMIT:
            if (
                request.outcome_scope == "RECEIVER_FLOOD_GUARD"
                or (request.reason or "").casefold() == "dos"
            ):
                executed = True
            elif request.peer_id is None:
                failure = "PEER_REQUIRED"
            else:
                node.rate_limited_peer_ids.add(request.peer_id)
                executed = True
        elif action == DefenseAction.DATA_ISOLATION:
            if request.peer_id is None:
                failure = "PEER_REQUIRED"
            else:
                node.isolated_peer_ids.add(request.peer_id)
                executed = True
        elif action == DefenseAction.TRUSTED_STATE_ROLLBACK:
            node.flight_state = "HOVERING"
            node.target_position_xyz_m = node.position_xyz_m
            executed = True
        elif action == DefenseAction.CHANNEL_SWITCH:
            if not request.target_link_id or request.target_link_id not in self.phy.states:
                failure = "VALID_LINK_REQUIRED"
            else:
                self.phy.switch_channel(request.target_link_id)
                executed = True
        elif action == DefenseAction.REROUTE:
            if not request.target_link_id or request.target_link_id not in self.topology.links:
                failure = "VALID_LINK_REQUIRED"
            else:
                node.known_bad_link_ids.add(request.target_link_id)
                self.topology.set_link_active(request.target_link_id, False)
                executed = True
        elif action == DefenseAction.REAUTH_REKEY_REQUEST:
            if request.peer_id is None:
                failure = "PEER_REQUIRED"
            else:
                rekey = self.key_provider.request_rekey(
                    node.node_id,
                    request.peer_id,
                    request.session_id
                    or f"session-{node.node_id}-{request.peer_id}-1",
                    node.key_epoch,
                )
                if rekey.success:
                    # A synchronous test provider may return the completed
                    # epoch. A real SKG provider returns accepted/UPDATING and
                    # updates the node epoch only after networked confirmation.
                    if rekey.new_key_epoch is not None:
                        node.key_epoch = int(rekey.new_key_epoch) if isinstance(rekey.new_key_epoch, int) else rekey.new_key_epoch
                    executed = True
                else:
                    failure = rekey.failure_reason or "REKEY_FAILED"
        elif action == DefenseAction.INCREASE_MONITORING:
            node.monitoring_level += 1
            executed = True
        else:  # pragma: no cover - enum keeps this unreachable
            failure = "UNSUPPORTED_ACTION"

        return DefenseResult(
            request={
                "request_id": request.request_id,
                "action": action.value,
                "requester_node_id": request.requester_node_id,
                "reason": request.reason,
                "session_id": request.session_id,
            },
            permission="LOCAL_NODE_POLICY" if allowed else "DENIED",
            target={
                "node_id": request.target_node_id,
                "link_id": request.target_link_id,
                "peer_id": request.peer_id,
            },
            requested_time_s=request.requested_time_s,
            executed_time_s=sim_time_s if executed else None,
            allowed=allowed,
            executed=executed,
            failure_reason=failure,
            outcome={
                "scope": request.outcome_scope,
                "attack_impact": None,
                "malicious_traffic_blocked": None,
                "legitimate_traffic_harmed": None,
                "time_to_action_s": (
                    max(0.0, sim_time_s - request.requested_time_s) if executed else None
                ),
                "throughput_mbps": None,
                "latency_ms": None,
                "mission_impact": None,
                "communication_overhead_bytes": None,
                "compute_overhead_ms": None,
                "availability": {
                    "attack_impact": False,
                    "malicious_traffic_blocked": False,
                    "legitimate_traffic_harmed": False,
                    "throughput_mbps": False,
                    "latency_ms": False,
                    "mission_impact": False,
                    "communication_overhead_bytes": False,
                    "compute_overhead_ms": False,
                    "missing_reason": "RUNTIME_OUTCOME_NOT_ATTACHED",
                },
                **(
                    {
                        "key_state_transitions": rekey.state_transitions,
                        "previous_key_epoch": rekey.previous_key_epoch,
                        "new_key_epoch": rekey.new_key_epoch,
                        "key_provider_status": rekey.implementation_status,
                        "rekey_failure_reason": rekey.failure_reason,
                    }
                    if action == DefenseAction.REAUTH_REKEY_REQUEST
                    and request.peer_id is not None
                    else {}
                ),
            },
        )
