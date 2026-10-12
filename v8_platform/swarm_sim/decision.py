"""B-side policy boundary for model recommendations.

Adapters only return observations and recommendations.  This module converts a
recommendation into an authorized request; it never mutates the simulator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adapters import ModelResult
from .domain import Node
from .network import FormationTopology
from .security import DefenseAction


RECOMMENDATION_ACTIONS = {
    "RECOMMEND_DROP_PACKET": DefenseAction.DROP_PACKET,
    "RECOMMEND_RATE_LIMIT": DefenseAction.RATE_LIMIT,
    "RECOMMEND_DATA_ISOLATION": DefenseAction.DATA_ISOLATION,
    "RECOMMEND_TRUSTED_STATE_ROLLBACK": DefenseAction.TRUSTED_STATE_ROLLBACK,
    "RECOMMEND_CHANNEL_SWITCH": DefenseAction.CHANNEL_SWITCH,
    "RECOMMEND_REROUTE": DefenseAction.REROUTE,
    "RECOMMEND_REAUTH_REKEY": DefenseAction.REAUTH_REKEY_REQUEST,
    "RECOMMEND_REAUTH_REKEY_REQUEST": DefenseAction.REAUTH_REKEY_REQUEST,
    "RECOMMEND_INCREASE_MONITORING": DefenseAction.INCREASE_MONITORING,
}


@dataclass(frozen=True, slots=True)
class FusionDecision:
    allowed: bool
    action: DefenseAction | None
    reason: str


@dataclass(frozen=True, slots=True)
class DefenseTargetResolution:
    """Trusted, action-specific target derived from local observable evidence."""

    allowed: bool
    action: DefenseAction
    target_node_id: int | None
    target_link_id: str | None
    peer_id: int | None
    session_id: str | None
    reason: str
    authentication_state: str
    logical_claimed_source: int | None
    immediate_hop_peer: int | None


class DefenseTargetResolver:
    """Resolve defense targets without trusting an unauthenticated claim.

    The resolver consumes only the evidence event and direct topology.  It is
    intentionally unaware of AttackPlan/labels, so simulator truth can never
    influence a model-triggered action target.
    """

    IDENTITY_SENSITIVE_ACTIONS = {
        DefenseAction.DATA_ISOLATION,
        DefenseAction.RATE_LIMIT,
        DefenseAction.REAUTH_REKEY_REQUEST,
    }
    LINK_ACTIONS = {DefenseAction.CHANNEL_SWITCH, DefenseAction.REROUTE}

    def __init__(
        self,
        topology: FormationTopology,
        *,
        observable_to_internal_links: dict[str, str] | None = None,
        observable_to_internal_sessions: dict[str, str] | None = None,
    ) -> None:
        self.topology = topology
        self.observable_to_internal_links = (
            observable_to_internal_links
            if observable_to_internal_links is not None
            else {}
        )
        self.observable_to_internal_sessions = (
            observable_to_internal_sessions
            if observable_to_internal_sessions is not None
            else {}
        )

    def _direct_link_id(self, event: dict[str, Any]) -> str | None:
        packet = event.get("online_features", {}).get("packet", {})
        candidates = (
            event.get("direct_link_id"),
            packet.get("link_id") if isinstance(packet, dict) else None,
            event.get("extensions", {}).get("sample_link_id"),
        )
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            internal = self.observable_to_internal_links.get(candidate, candidate)
            if internal in self.topology.links:
                return internal
        return None

    def resolve(
        self,
        action: DefenseAction,
        evidence: dict[str, Any],
        observer: Node,
    ) -> DefenseTargetResolution:
        features = evidence.get("online_features", {})
        packet = features.get("packet", {}) if isinstance(features, dict) else {}
        security = (
            features.get("security_state", {}) if isinstance(features, dict) else {}
        )
        claimed = packet.get("claimed_src_id") if isinstance(packet, dict) else None
        claimed = claimed if isinstance(claimed, int) and not isinstance(claimed, bool) else None
        session = packet.get("session_id") if isinstance(packet, dict) else None
        session = (
            self.observable_to_internal_sessions.get(session, session)
            if isinstance(session, str)
            else None
        )
        auth = str(security.get("auth_result") or "UNAVAILABLE").upper()
        link_id = self._direct_link_id(evidence)
        link = self.topology.links.get(link_id or "")
        peer: int | None = None
        if link is not None:
            if link.dst_id == observer.node_id:
                peer = link.src_id
            elif link.src_id == observer.node_id:
                peer = link.dst_id

        allowed = True
        reason = "TARGET_RESOLVED_FROM_LOCAL_EVIDENCE"
        target_link: str | None = None
        target_peer: int | None = None

        if action in self.LINK_ACTIONS:
            target_link = link_id
            if target_link is None:
                allowed = False
                reason = "DIRECT_LINK_EVIDENCE_REQUIRED"
        elif action in self.IDENTITY_SENSITIVE_ACTIONS:
            # A pre-auth RX event says only which physical peer sent a frame;
            # it does not authenticate the logical claimed source.
            if auth in {"UNAVAILABLE", "PENDING", "AUTH_PENDING"}:
                allowed = False
                reason = "AUTHENTICATION_PENDING"
            elif auth != "PASS":
                allowed = False
                reason = "UNTRUSTED_IDENTITY_ACTION_DENIED"
            elif peer is None:
                allowed = False
                reason = "DIRECT_PEER_EVIDENCE_REQUIRED"
            else:
                target_peer = peer
                target_link = link_id
                reason = "AUTHENTICATED_DIRECT_PEER_RESOLVED"

        return DefenseTargetResolution(
            allowed=allowed,
            action=action,
            target_node_id=observer.node_id,
            target_link_id=target_link,
            peer_id=target_peer,
            session_id=session,
            reason=reason,
            authentication_state=auth,
            logical_claimed_source=claimed,
            immediate_hop_peer=peer,
        )


class DecisionFusion:
    """Apply B-owned confidence, quality, permission and rule-priority policy."""

    def __init__(self, confidence_threshold: float, quality_threshold: float) -> None:
        self.confidence_threshold = float(confidence_threshold)
        self.quality_threshold = float(quality_threshold)

    def decide(
        self, result: ModelResult, *, rule_high_certainty: bool = False
    ) -> FusionDecision:
        if result.status != "OK":
            return FusionDecision(False, None, "MODEL_STATUS_NOT_OK")
        if not result.recommended_action:
            return FusionDecision(False, None, "NO_RECOMMENDATION")
        action = RECOMMENDATION_ACTIONS.get(str(result.recommended_action).upper())
        if action is None:
            try:
                action = DefenseAction(str(result.recommended_action).upper())
            except ValueError:
                return FusionDecision(False, None, "UNSUPPORTED_RECOMMENDATION")
        if rule_high_certainty:
            return FusionDecision(False, action, "RULE_HIGH_CERTAINTY_PRIORITY")
        if result.confidence is None or result.confidence < self.confidence_threshold:
            return FusionDecision(False, action, "MODEL_CONFIDENCE_BELOW_THRESHOLD")
        if result.quality is None or result.quality < self.quality_threshold:
            return FusionDecision(False, action, "MODEL_QUALITY_BELOW_THRESHOLD")
        return FusionDecision(True, action, "MODEL_POLICY_ACCEPTED")
