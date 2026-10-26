"""End-to-end deterministic platform runtime."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import math
from pathlib import Path
from typing import Any

from .adapters import (
    CryptoOpenResult,
    CryptoProtectionError,
    CryptoProvider,
    KeyProvider,
    MockKeyProvider,
    ModelAdapter,
    ModelResult,
    TestOnlyAeadCryptoProvider,
    default_model_adapters,
)
from .attacks import (
    AttackOutcomePolicy,
    AttackPlan,
    AttackRuntimeRecord,
    AttackScheduler,
)
from .application_auth import (
    ApplicationHmacService,
    ApplicationHmacVerification,
)
from .calibration import CalibrationProfile
from .dataset import DatasetExporter
from .decision import DefenseTargetResolver, DecisionFusion, FusionDecision
from .dispatch import OnlineEventDispatcher
from .domain import (
    BusinessApplyResult,
    EventType,
    Frame,
    Message,
    Node,
    NodeRole,
    ReceivedFrame,
    RunState,
    TransmissionIntent,
)
from .evaluation import ExperimentEvaluator
from .receiver_observations import ReceiverRateObservations
from .telemetry_measurement import measured_payload
from .events import build_event
from .network import DirectedLink, FormationTopology
from .rff import RFF_FEATURE_SCHEMA, RffService
from .rff_evaluation import evaluate_rff
from .normal import (
    NormalDisturbancePlan,
    NormalDisturbanceRecord,
    NormalDisturbanceScheduler,
)
from .mission import MissionImpactEvaluator
from .model_runtime import ModelExecutionSupervisor, SafeModelAdapterRunner
from .packets import BusinessPacketTemplate, serialized_application_size
from .phy import PersistentPhyModel
from .probe import ProbeService, V8_DEFAULT_PROBE_PROFILE
from .redundancy import RedundantExecutor, Replica, SwitchRecovery
from .reporting import ReportingService, SecurityReport
from .scenario import ScenarioOrchestrator
from .packet_accounting import PacketAccounting
from .security import (
    DefenseAction,
    DefenseExecutor,
    DefenseRequest,
    Detection,
    DeterministicRuleEngine,
)
from .simulation import (
    RunConfig,
    RunContext,
    SCHEMA_VERSION,
    runtime_semantic_fingerprint,
)
from .terminal import TerminalAuthorizer, TerminalProfile
from .traffic import LocalTrafficAccumulator


class PlatformRuntime:
    """Coordinates online components while keeping attack truth in labels only."""

    def __init__(
        self,
        config: RunConfig | dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        key_provider: KeyProvider | None = None,
        crypto_provider: CryptoProvider | None = None,
        model_adapters: dict[str, ModelAdapter] | None = None,
        calibration_profile: CalibrationProfile | None = None,
        terminal_authorizer: TerminalAuthorizer | None = None,
        terminal_profiles: dict[int, TerminalProfile] | None = None,
        terminal_credentials: dict[int, str] | None = None,
        security_coordinator: Any | None = None,
    ) -> None:
        self.config = deepcopy(
            config if isinstance(config, RunConfig) else RunConfig.from_dict(config)
        )
        if self.config.rff_policy_mode == "ENFORCE":
            if not self.config.rff_enabled:
                raise ValueError("RFF_ENFORCEMENT_REQUIRES_RFF")
            if "rff" in (model_adapters or {}):
                raise ValueError("RFF_ENFORCEMENT_REQUIRES_SYNCHRONOUS_IDENTIFIER")
        self._calibration_profile = calibration_profile
        if calibration_profile is None and (
            self.config.data_source_kind != "simulation"
            or self.config.calibration_status != "UNCALIBRATED_BASELINE"
        ):
            raise ValueError("NON_SIMULATION_SOURCE_REQUIRES_CALIBRATION_PROFILE")
        if calibration_profile is not None:
            self.config.channel_profile_id = calibration_profile.profile_id
            self.config.calibration_status = calibration_profile.calibration_status
            self.config.data_source_kind = calibration_profile.data_source_kind
            self.config.calibration_version = calibration_profile.calibration_version
            self.config.source_dataset_version = (
                calibration_profile.dataset_manifest.version
                if calibration_profile.dataset_manifest is not None
                else None
            )
            calibrated_values = {
                item.parameter: item.value for item in calibration_profile.parameters
            }
            self.config.frequency_hz = float(
                calibrated_values.get("frequency_hz", self.config.frequency_hz)
            )
            self.config.bandwidth_hz = float(
                calibrated_values.get("bandwidth_hz", self.config.bandwidth_hz)
            )
        self.context = RunContext.create(self.config, run_id=run_id)
        self.roles = self.config.resolved_roles()
        self.gcs_node_id = min(
            node_id for node_id, role in self.roles.items() if role == NodeRole.GCS
        )
        self.leader_node_id = min(
            node_id for node_id, role in self.roles.items() if role == NodeRole.LEADER
        )
        self.nodes = self._create_nodes()
        self.application_auth = ApplicationHmacService(
            self.config.seed, self.roles.keys()
        )
        self.topology = FormationTopology(self.roles)
        self._rff_template_identifier_enabled = "rff" not in (model_adapters or {})
        self.rff_service = None
        if self.config.rff_enabled:
            self.rff_service = RffService(
                self.context.rng,
                enrollment_samples=self.config.rff_enrollment_samples,
                quality_threshold=self.config.rff_quality_threshold,
                distance_threshold=self.config.rff_distance_threshold,
                min_identity_margin=self.config.rff_min_identity_margin,
            )
            for node in self.nodes.values():
                self.rff_service.register_device(node.node_id)
            for link in self.topology.links.values():
                if (
                    link.active
                    and self.nodes[link.src_id].role != NodeRole.EXTERNAL
                    and self.nodes[link.dst_id].role != NodeRole.EXTERNAL
                ):
                    self.rff_service.enroll(receiver_id=link.dst_id, device_id=link.src_id)
        self._observable_link_ids: dict[str, str] = {}
        self._internal_link_ids: dict[str, str] = {}
        self._observable_session_ids: dict[str, str] = {}
        self._internal_session_ids: dict[str, str] = {}
        self._register_link_identifiers()
        self.events: list[dict[str, Any]] = []
        self._refresh_local_topology(emit=False)
        self.phy = PersistentPhyModel(
            self.topology,
            self.context.rng,
            profile_id=self.config.channel_profile_id,
            calibration_status=self.config.calibration_status,
            calibration_profile=calibration_profile,
            frequency_hz=self.config.frequency_hz,
            bandwidth_hz=self.config.bandwidth_hz,
        )
        self.probes = ProbeService(
            self.context,
            self.topology,
            self.phy,
            self.nodes,
            profile=str(
                getattr(
                    security_coordinator,
                    "probe_profile",
                    V8_DEFAULT_PROBE_PROFILE,
                )
            ),
        )
        self._key_provider_injected = key_provider is not None
        self._crypto_provider_injected = crypto_provider is not None
        self.key_provider = key_provider or MockKeyProvider(self.config.seed)
        self.key_provider.reset(self.context.run_record())
        self.crypto = crypto_provider or TestOnlyAeadCryptoProvider(self.key_provider)
        self.security_coordinator = security_coordinator
        if self.security_coordinator is not None:
            self.security_coordinator.attach_runtime(self)
        self.packet_accounting = PacketAccounting(self.config)
        self._spoof_original_frames = {}
        self._spoof_used_originals = set()
        self.attack_scheduler = AttackScheduler(self.context)
        self.attack_scheduler.accounting = self.packet_accounting
        self.receiver_rate_observations = ReceiverRateObservations(
            {node for spec in self.config.attack_specs for node in spec.get('target_node_ids', [])},
            self.config.traffic_statistics_window_s, self.config.flooding_packet_rate_threshold_pps)
        self.normal_disturbances = NormalDisturbanceScheduler(self.context)
        self._load_configured_episode_plans()
        self.scenario = ScenarioOrchestrator(self.context)
        self._load_configured_scenario()
        self.rules = {
            node_id: DeterministicRuleEngine(
                self.config.replay_reorder_window_size,
                replay_timestamp_freshness_s=self.config.replay_timestamp_freshness_s,
                traffic_window_s=self.config.traffic_statistics_window_s,
                flooding_threshold_pps=self.config.flooding_packet_rate_threshold_pps,
                flooding_detection_enabled=self.config.flooding_detection_enabled,
            )
            for node_id in self.nodes
        }
        self.defense = DefenseExecutor(self.topology, self.phy, self.key_provider)
        self.decision_fusion = DecisionFusion(
            self.config.model_recommendation_confidence_threshold,
            self.config.model_recommendation_quality_threshold,
        )
        self.defense_target_resolver = DefenseTargetResolver(
            self.topology,
            observable_to_internal_links=self._internal_link_ids,
            observable_to_internal_sessions=self._internal_session_ids,
        )
        self.reporting = ReportingService(
            self.context,
            self.gcs_node_id,
            self.leader_node_id,
            summary_window_s=self.config.security_summary_window_s,
        )
        self.traffic_statistics = LocalTrafficAccumulator(
            self.config.traffic_statistics_window_s
        )
        self._provided_model_adapters = dict(model_adapters or {})
        self._model_execution_supervisor = (
            ModelExecutionSupervisor(
                workers=max(1, len(self._provided_model_adapters))
            )
            if self._provided_model_adapters
            else None
        )
        self.model_adapters = default_model_adapters(self.context)
        self.model_adapters.update(
            {
                name: SafeModelAdapterRunner(
                    name,
                    adapter,
                    self.context,
                    timeout_ms=self.config.model_inference_timeout_ms,
                    supervisor=self._model_execution_supervisor,
                )
                for name, adapter in self._provided_model_adapters.items()
            }
        )
        self.event_dispatcher = OnlineEventDispatcher(
            self.model_adapters,
            allow_external_observer=self.config.allow_external_model_observer,
        )
        self._model_provenance_at_start: dict[str, dict[str, Any]] = {}
        self.rf_manifest: list[dict[str, Any]] = []
        self._rf_sample_bindings: dict[tuple[str, str], str] = {}
        self._terminal_authorizer_injected = terminal_authorizer is not None
        self.terminal_authorizer = terminal_authorizer or TerminalAuthorizer()
        self.terminal_profiles = self._build_terminal_profiles(terminal_profiles or {})
        self.terminal_credentials = self._build_terminal_credentials(
            terminal_credentials or {}
        )
        if self.config.require_formal_security or self.config.dataset_maturity == "FORMAL":
            provider_statuses = {
                str(getattr(self.key_provider, "implementation_status", "UNKNOWN")),
                str(getattr(self.crypto, "implementation_status", "UNKNOWN")),
                str(getattr(self.terminal_authorizer, "implementation_status", "UNKNOWN")),
            }
            if any("FORMAL" not in status.upper() for status in provider_statuses):
                raise ValueError("FORMAL_SECURITY_REQUIRED_BUT_PROVIDER_IS_NOT_FORMAL")
        for name in self._provided_model_adapters:
            adapter = self.model_adapters[name]
            adapter.reset(self.run_record())
        self._model_provenance_at_start = self._collect_model_provenance()
        self._redundancy_fault_modes: dict[str, str] = {}
        self.security_redundancy = RedundantExecutor(
            [
                Replica(
                    f"security-replica-{index}",
                    lambda value, replica_id=f"security-replica-{index}": self._run_security_replica(
                        replica_id, value
                    ),
                )
                for index in range(1, 4)
            ]
        )
        self.state = RunState.INITIALIZED
        self._tick_index = 0
        self._last_phy_sample_s = -math.inf
        self._message_attack_ids: dict[str, str] = {}
        self._last_queue_attempt_message_id: str | None = None
        self._attack_event_ids: set[str] = set()
        self._rule_high_certainty_evidence_ids: set[str] = set()
        self._handled_model_result_ids: set[str] = set()
        self._pending_model_recommendations: dict[str, tuple[ModelResult, dict[str, Any]]] = {}
        self._model_fusion_in_progress = False
        self._metric_totals = {
            "tx": 0,
            "rx_success": 0,
            "rx_failure": 0,
            "delivered": 0,
            "queue_drops": 0,
            "latency_ms_sum": 0.0,
            "throughput_mbps_sum": 0.0,
        }
        self.rff_policies = {}
        self._rff_report_times: dict[tuple[int, str], float] = {}
        if self.rff_service is not None and self._rff_template_identifier_enabled:
            from .rff_policy import RffIngressPolicy

            for node_id in self.roles:
                if self.nodes[node_id].role == NodeRole.EXTERNAL:
                    continue
                self.rff_policies[node_id] = RffIngressPolicy(
                    policy_mode=self.config.rff_policy_mode,
                    quality_threshold=self.config.rff_quality_threshold,
                    queue_pressure_ratio=self.config.rff_queue_pressure_ratio,
                    strict_hold_s=self.config.rff_strict_hold_s,
                    strict_on_rate_alarm=self.config.rff_strict_on_rate_alarm,
                    rate_threshold_pps=self.config.flooding_packet_rate_threshold_pps,
                )
                self.nodes[node_id].rff_policy_state = "NORMAL"
        self._emit_initial_state()
        self._initialize_terminal_authorization()

    def _create_nodes(self) -> dict[int, Node]:
        nodes: dict[int, Node] = {}
        position_rng = self.context.rng.python("node-position")
        for node_id, role in sorted(self.roles.items()):
            if role == NodeRole.GCS:
                position = (0.0, 0.0, 20.0)
            elif role == NodeRole.LEADER:
                position = (120.0, 0.0, 100.0)
            else:
                angle = (node_id - 2) * 2.0 * math.pi / max(1, self.config.node_count - 2)
                radius = 90.0 + position_rng.uniform(-8.0, 8.0)
                position = (
                    120.0 + radius * math.cos(angle),
                    radius * math.sin(angle),
                    95.0 + position_rng.uniform(-8.0, 8.0),
                )
            nodes[node_id] = Node(
                node_id=node_id,
                role=role,
                position_xyz_m=tuple(round(value, 6) for value in position),
                queue_capacity=self.config.queue_capacity,
            )
        return nodes

    def _register_link_identifiers(self) -> None:
        """Assign stable run-scoped public aliases to simulator-private links."""

        for internal_id in sorted(self.topology.links):
            if internal_id in self._observable_link_ids:
                continue
            observable = self.context.ids.next("lnk")
            self._observable_link_ids[internal_id] = observable
            self._internal_link_ids[observable] = internal_id

    def observable_link_id(self, internal_or_observable: str | None) -> str | None:
        if internal_or_observable is None:
            return None
        value = str(internal_or_observable)
        if value in self._internal_link_ids:
            return value
        if value in self.topology.links:
            self._register_link_identifiers()
            return self._observable_link_ids[value]
        return value

    def internal_link_id(self, internal_or_observable: str | None) -> str | None:
        if internal_or_observable is None:
            return None
        value = str(internal_or_observable)
        return self._internal_link_ids.get(value, value)

    def observable_session_id(self, internal_or_observable: str | None) -> str | None:
        if internal_or_observable is None:
            return None
        value = str(internal_or_observable)
        if value in self._internal_session_ids:
            return value
        if value not in self._observable_session_ids:
            observable = self.context.ids.next("sess")
            self._observable_session_ids[value] = observable
            self._internal_session_ids[observable] = value
        return self._observable_session_ids[value]

    def _sanitize_online_identifiers(self, value: Any, key: str | None = None) -> Any:
        """Translate internal identifiers before an object enters the event store."""

        if isinstance(value, dict):
            return {
                child_key: self._sanitize_online_identifiers(child, str(child_key))
                for child_key, child in value.items()
            }
        if isinstance(value, list):
            if key and (key.endswith("link_ids") or key == "affected_link_ids"):
                return [self.observable_link_id(item) for item in value]
            if key and key.endswith("session_ids"):
                return [self.observable_session_id(item) for item in value]
            return [self._sanitize_online_identifiers(item, key) for item in value]
        if isinstance(value, str):
            if key and (key.endswith("link_id") or key == "sample_link_id"):
                return self.observable_link_id(value)
            if key and key.endswith("session_id"):
                return self.observable_session_id(value)
        return value

    def _external_node(self, node_id: int = -1) -> Node:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(
                node_id=node_id,
                role=NodeRole.EXTERNAL,
                position_xyz_m=(110.0, 35.0, 90.0),
                queue_capacity=self.config.queue_capacity,
            )
            if self.rff_service is not None:
                self.rff_service.register_device(node_id)
            self.rules[node_id] = DeterministicRuleEngine(
                self.config.replay_reorder_window_size,
                replay_timestamp_freshness_s=self.config.replay_timestamp_freshness_s,
                traffic_window_s=self.config.traffic_statistics_window_s,
                flooding_threshold_pps=self.config.flooding_packet_rate_threshold_pps,
                flooding_detection_enabled=self.config.flooding_detection_enabled,
            )
        return self.nodes[node_id]

    def _application_direction(self, src_id: int, dst_id: int) -> str:
        """Return the stable end-to-end business direction, never a hop role."""

        src_role = self.nodes[src_id].role
        dst_role = self.nodes[dst_id].role
        if dst_role == NodeRole.GCS or (
            src_role in {NodeRole.FOLLOWER, NodeRole.EXTERNAL}
            and dst_role == NodeRole.LEADER
        ):
            return "UPLINK"
        return "DOWNLINK"

    def _refresh_local_topology(
        self, *, emit: bool = True, reason: str | None = None
    ) -> list[int]:
        """Refresh only the incident-link view available to each node.

        The simulator-global topology version is deliberately not broadcast to
        unrelated nodes.  A node advances its local version only when one of
        its own outgoing neighbor/link facts changed.
        """

        changed: list[int] = []
        for node_id, node in sorted(self.nodes.items()):
            if node_id not in self.roles:
                continue
            all_neighbors = {
                neighbor_id
                for neighbor_id in self.topology.direct_neighbors(
                    node_id, active_only=False
                )
                if neighbor_id in self.roles
            }
            active_neighbors = {
                neighbor_id
                for neighbor_id in self.topology.direct_neighbors(node_id)
                if neighbor_id in self.roles
            }
            active_links = {
                self.topology.link_id(node_id, neighbor_id)
                for neighbor_id in active_neighbors
            }
            bad_links = {
                self.topology.link_id(node_id, neighbor_id)
                for neighbor_id in all_neighbors
                if not self.topology.links[
                    self.topology.link_id(node_id, neighbor_id)
                ].active
            }
            local_changed = (
                active_neighbors != node.known_neighbor_ids
                or active_links != node.known_neighbor_link_ids
                or bad_links != node.known_bad_link_ids
            )
            node.known_neighbor_ids = active_neighbors
            node.known_neighbor_link_ids = active_links
            node.known_bad_link_ids = bad_links
            if node.known_topology_version == 0 or local_changed:
                node.known_topology_version = self.topology.version
            if local_changed:
                changed.append(node_id)
                if emit:
                    self._append_event(
                        build_event(
                            self.context,
                            EventType.TOPOLOGY_UPDATE,
                            node,
                            availability={
                                "payload_available": False,
                                "phy_available": False,
                                "missing_reason": reason or "LOCAL_TOPOLOGY_CHANGED",
                            },
                            extensions={
                                "topology_change": {
                                    "reason": reason or "LOCAL_TOPOLOGY_CHANGED",
                                    "local_only": True,
                                }
                            },
                            leader_id=self.leader_node_id,
                        )
                    )
                    # A normal physical/mission state transition must also be
                    # reflected by subsequent legitimate telemetry.  This
                    # creates the required state->telemetry hard negative for
                    # FDI without putting the disturbance name online.
                    destination_id = (
                        self.leader_node_id
                        if node.node_id != self.leader_node_id
                        else self.gcs_node_id
                    )
                    if destination_id != node.node_id:
                        self.queue_message(
                            node.node_id,
                            destination_id,
                            "TELEMETRY",
                            {
                                "battery_pct": node.battery_pct,
                                "position_x_m": node.position_xyz_m[0],
                                "position_y_m": node.position_xyz_m[1],
                                "altitude_m": node.position_xyz_m[2],
                                "flight_state": node.flight_state,
                            },
                            sensitive=True,
                        )
        return changed

    def set_link_active(
        self, link_id: str, active: bool, *, reason: str = "LINK_STATE_CHANGED"
    ) -> None:
        current = self.topology.links.get(link_id)
        if current is None:
            raise KeyError(f"unknown link: {link_id}")
        if current.active == bool(active):
            return
        self.topology.set_link_active(link_id, active)
        self._refresh_local_topology(reason=reason)

    def set_bidirectional_link_active(
        self,
        first: int,
        second: int,
        active: bool,
        *,
        reason: str = "LINK_STATE_CHANGED",
    ) -> None:
        changed = False
        for src_id, dst_id in ((first, second), (second, first)):
            link = self.topology.get_link(src_id, dst_id)
            if link is not None and link.active != bool(active):
                self.topology.set_link_active(link.link_id, active)
                changed = True
        if changed:
            self._refresh_local_topology(reason=reason)

    def add_bidirectional_link(
        self,
        first: int,
        second: int,
        *,
        active: bool = True,
        reason: str = "NEIGHBOR_DISCOVERED",
    ) -> None:
        self.topology.add_bidirectional(first, second, active=active)
        self.phy._ensure_states()
        self._refresh_local_topology(reason=reason)

    def _build_terminal_profiles(
        self, overrides: dict[int, TerminalProfile]
    ) -> dict[int, TerminalProfile]:
        profiles: dict[int, TerminalProfile] = {}
        for node_id in self.roles:
            profiles[node_id] = overrides.get(
                node_id,
                TerminalProfile(
                    terminal_id=f"uav-{node_id}",
                    hardware_fingerprint_attributes={
                        "board": "simulation-board-v1",
                        "radio": f"radio-{node_id}",
                    },
                    software_environment={"app": self.config.software_version},
                    os_environment={"os": "sim-os-v1"},
                ),
            )
        return profiles

    def _build_terminal_credentials(
        self, overrides: dict[int, str]
    ) -> dict[int, str]:
        return {
            node_id: overrides.get(node_id, f"opaque-sim-handle-{node_id}")
            for node_id in self.roles
        }

    def _emit_terminal_authorization(
        self, node: Node, result: dict[str, Any]
    ) -> None:
        self._append_event(
            build_event(
                self.context,
                EventType.AUTH_RESULT,
                node,
                security_state={
                    "auth_result": "PASS" if result["allowed"] else "FAIL",
                    "auth_failure_reason": result.get("failure_reason"),
                    "replay_check_result": "UNAVAILABLE",
                    "key_state": "AVAILABLE" if result["allowed"] else "MISSING",
                },
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": result.get("failure_reason"),
                },
                extensions={"terminal_authorization": deepcopy(result)},
                leader_id=self.leader_node_id,
            )
        )

    def _authorize_terminal_event(self, node_id: int, event: str) -> bool:
        profile = self.terminal_profiles[node_id]
        credential = self.terminal_credentials[node_id]
        result = self.terminal_authorizer.authorize(event, profile, credential)
        self._emit_terminal_authorization(self.nodes[node_id], result)
        return bool(result["allowed"])

    def _initialize_terminal_authorization(self) -> None:
        for node_id, profile in sorted(self.terminal_profiles.items()):
            if not self.terminal_authorizer.is_enrolled(profile.terminal_id):
                self.terminal_authorizer.enroll(
                    profile, self.terminal_credentials[node_id]
                )
            node = self.nodes[node_id]
            node.program_authorized = self._authorize_terminal_event(
                node_id, "PROGRAM_START"
            )
            node.network_authorized = (
                self._authorize_terminal_event(node_id, "NETWORK_JOIN")
                if node.program_authorized
                else False
            )
            if not node.program_authorized:
                # A denied start also has an explicit denied join event.
                self._authorize_terminal_event(node_id, "NETWORK_JOIN")
            node.lifecycle_state = (
                "ACTIVE"
                if node.program_authorized and node.network_authorized
                else "AUTHORIZATION_DENIED"
            )

    def set_presented_terminal_identity(
        self, node_id: int, profile: TerminalProfile, credential_handle: str
    ) -> None:
        if node_id not in self.roles:
            raise KeyError(f"unknown node: {node_id}")
        self.terminal_profiles[node_id] = profile
        self.terminal_credentials[node_id] = credential_handle

    def _emit_initial_state(self) -> None:
        for node in self.nodes.values():
            self._append_event(
                build_event(
                    self.context,
                    EventType.NODE_STATE,
                    node,
                    availability={
                        "payload_available": False,
                        "phy_available": False,
                        "missing_reason": "INITIAL_STATE",
                    },
                    leader_id=self.leader_node_id,
                )
            )
            self._append_event(
                build_event(
                    self.context,
                    EventType.TOPOLOGY_UPDATE,
                    node,
                    availability={
                        "payload_available": False,
                        "phy_available": False,
                        "missing_reason": "LOCAL_NEIGHBOR_DISCOVERY",
                    },
                    leader_id=self.leader_node_id,
                )
            )

    @property
    def run_id(self) -> str:
        return self.context.run_id

    @property
    def is_terminated(self) -> bool:
        return self.state in {RunState.STOPPED, RunState.COMPLETED}

    def start(self) -> dict[str, Any]:
        if self.state == RunState.COMPLETED:
            return {"status": "COMPLETED", "run_id": self.run_id}
        self.state = RunState.RUNNING
        return self.status()

    def pause(self) -> dict[str, Any]:
        if self.state == RunState.RUNNING:
            self.state = RunState.PAUSED
        return self.status()

    def resume(self) -> dict[str, Any]:
        if self.state in {RunState.PAUSED, RunState.INITIALIZED}:
            self.state = RunState.RUNNING
        return self.status()

    def stop(self) -> dict[str, Any]:
        self.state = RunState.STOPPED
        self._close_model_supervisor()
        return self.status()

    def close(self) -> None:
        """Release run-scoped software resources without mutating evidence."""

        self._close_model_supervisor()

    def reset(self) -> dict[str, Any]:
        self._close_model_supervisor()
        config = self.config
        fresh_security = None
        coordinator = getattr(self, "security_coordinator", None)
        bundle_factory = getattr(coordinator, "_bundle_factory", None)
        if callable(bundle_factory):
            fresh_security = dict(bundle_factory(config))
        key_provider = (
            fresh_security.get("key_provider")
            if fresh_security is not None
            else (self.key_provider if self._key_provider_injected else None)
        )
        crypto_provider = (
            fresh_security.get("crypto_provider")
            if fresh_security is not None
            else (self.crypto if self._crypto_provider_injected else None)
        )
        model_adapters = self._provided_model_adapters or None
        terminal_authorizer = (
            fresh_security.get("terminal_authorizer")
            if fresh_security is not None
            else (self.terminal_authorizer if self._terminal_authorizer_injected else None)
        )
        terminal_profiles = (
            fresh_security.get("terminal_profiles")
            if fresh_security is not None
            else (
                deepcopy(self.terminal_profiles)
                if self._terminal_authorizer_injected
                else None
            )
        )
        terminal_credentials = (
            fresh_security.get("terminal_credentials")
            if fresh_security is not None
            else (
                dict(self.terminal_credentials)
                if self._terminal_authorizer_injected
                else None
            )
        )
        self.__init__(
            config,
            key_provider=key_provider,
            crypto_provider=crypto_provider,
            model_adapters=model_adapters,
            calibration_profile=self._calibration_profile,
            terminal_authorizer=terminal_authorizer,
            terminal_profiles=terminal_profiles,
            terminal_credentials=terminal_credentials,
            security_coordinator=(
                fresh_security.get("security_coordinator")
                if fresh_security is not None
                else coordinator
            ),
        )
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "software_version": self.config.software_version,
            "run_id": self.run_id,
            "state": self.state.value,
            "sim_time_s": self.context.clock.now_s,
            "duration_s": self.config.duration_s,
            "seed": self.config.seed,
            "event_count": len(self.events),
            "pending_attacks": sum(
                1
                for record in self.attack_scheduler.records.values()
                if record.status != "ENDED"
            ),
            "calibration_status": self.config.calibration_status,
            "dataset_maturity": self.config.dataset_maturity,
        }

    def episode_phase(self, at_s: float | None = None) -> str:
        """Return evaluator metadata without exposing it in online observation."""

        now_s = self.context.clock.now_s if at_s is None else float(at_s)
        intervals = [
            (record.plan.impact_start_s, record.plan.end_s)
            for record in self.attack_scheduler.records.values()
        ] + [
            (record.plan.start_s, record.plan.end_s)
            for record in self.normal_disturbances.records.values()
        ]
        if any(start <= now_s < end for start, end in intervals):
            return "ATTACK_OR_DISTURBANCE"
        if intervals and now_s >= max(end for _, end in intervals):
            return "RECOVERY"
        return "NORMAL"

    def episode_metadata(self) -> dict[str, Any]:
        return {
            "current_phase": self.episode_phase(),
            "phase_semantics": {
                "NORMAL": "No attack impact or configured normal disturbance is active.",
                "ATTACK_OR_DISTURBANCE": "At least one configured impact/disturbance interval is active.",
                "RECOVERY": "All configured impact/disturbance intervals have ended.",
            },
            "attack_intervals": [
                {
                    "start_s": record.plan.impact_start_s,
                    "end_s": record.plan.end_s,
                }
                for record in self.attack_scheduler.records.values()
            ],
            "normal_disturbance_intervals": [
                {"start_s": record.plan.start_s, "end_s": record.plan.end_s}
                for record in self.normal_disturbances.records.values()
            ],
        }

    def debug_step(self) -> list[dict[str, Any]]:
        if self.is_terminated:
            return []
        previous = self.state
        created = self._advance_one()
        if self.state != RunState.COMPLETED and previous != RunState.RUNNING:
            self.state = previous
        return created

    def step(self) -> list[dict[str, Any]]:
        if self.state != RunState.RUNNING:
            return []
        return self._advance_one()

    def run_to_completion(self, max_steps: int | None = None) -> dict[str, Any]:
        self.start()
        steps = 0
        while self.state == RunState.RUNNING:
            self._advance_one()
            steps += 1
            if max_steps is not None and steps >= max_steps:
                break
        return self.status()

    def _advance_one(self) -> list[dict[str, Any]]:
        if self.context.clock.now_s >= self.config.duration_s - 1e-12:
            self.state = RunState.COMPLETED
            self._close_model_supervisor()
            return []
        start_index = len(self.events)
        self.context.clock.advance_to(
            min(
                self.config.duration_s,
                self.context.clock.now_s + self.config.step_s,
            )
        )
        self._tick_index += 1
        now_s = self.context.clock.now_s
        if self.security_coordinator is not None:
            self.security_coordinator.advance(now_s)
        self.attack_scheduler.update(now_s)
        self.normal_disturbances.update(now_s)
        for node_id in self.rff_policies:
            self._refresh_rff_receiver(self.nodes[node_id])

        self._process_scenario_schedule()
        if self.config.auto_traffic:
            self._generate_role_traffic()
        self._inject_normal_disturbances()
        self._inject_active_attacks()

        rx_budgets = {
            node_id: min(len(node.rx_queue), self.config.rx_service_per_step)
            for node_id, node in self.nodes.items()
        }
        tx_budgets = {
            node_id: min(
                len(node.tx_queue) + len(node.forward_queue),
                self.config.tx_service_per_step,
            )
            for node_id, node in self.nodes.items()
        }
        for node_id in sorted(self.nodes):
            self._service_rx(self.nodes[node_id], rx_budgets[node_id])
        self.reporting.flush_sources(self._can_route, self._enqueue_source_report)
        self.reporting.prepare_due_summaries(now_s)
        self.reporting.flush_gcs(self._can_route, self._enqueue_gcs_payload)
        for node_id in sorted(self.nodes):
            self._service_tx(self.nodes[node_id], tx_budgets[node_id])

        if now_s - self._last_phy_sample_s >= self.config.phy_sample_interval_s - 1e-12:
            self._emit_periodic_phy_samples()
            self._last_phy_sample_s = now_s
        self._emit_queue_samples()
        self.receiver_rate_observations.sample(now_s)

        self._metric_totals["queue_drops"] = sum(node.drop_count for node in self.nodes.values())
        if now_s >= self.config.duration_s - 1e-12:
            self.state = RunState.COMPLETED
            self._close_model_supervisor()
        return self.events[start_index:]

    def schedule_normal_disturbance(
        self, plan: NormalDisturbancePlan | dict[str, Any]
    ) -> dict[str, Any]:
        actual = plan if isinstance(plan, NormalDisturbancePlan) else NormalDisturbancePlan(**plan)
        if actual.end_s > self.config.duration_s + 1e-9:
            raise ValueError("NORMAL_DISTURBANCE_OUTSIDE_RUN_DURATION")
        unknown_nodes = [node_id for node_id in actual.target_node_ids if node_id not in self.roles]
        if unknown_nodes:
            raise ValueError(f"UNKNOWN_NORMAL_TARGET_NODES:{unknown_nodes}")
        unknown_links = [link_id for link_id in actual.target_link_ids if link_id not in self.topology.links]
        if unknown_links:
            raise ValueError(f"UNKNOWN_NORMAL_TARGET_LINKS:{unknown_links}")
        return self.normal_disturbances.schedule(actual)

    def rotate_security_session(
        self,
        sender_id: int,
        receiver_id: int,
        *,
        old_session_id: str,
        new_session_id: str,
        key_epoch: int | str | None = None,
        sequence_namespace: int | None = None,
    ) -> None:
        """Apply a legitimate receiver-known session lifecycle transition.

        Attack injection deliberately has no access to this method.  Tests and
        scenario orchestration establish the new session before an attacker
        retransmits a captured stale frame.
        """

        if sender_id not in self.nodes or receiver_id not in self.rules:
            raise KeyError("unknown session endpoint")
        epoch = self.nodes[sender_id].key_epoch if key_epoch is None else key_epoch
        namespace = sender_id if sequence_namespace is None else sequence_namespace
        detector = self.rules[receiver_id]
        detector.expire_session(
            sender_id,
            receiver_id,
            old_session_id,
            epoch,
            sequence_namespace=namespace,
        )
        detector.activate_session(
            sender_id,
            receiver_id,
            new_session_id,
            epoch,
            sequence_namespace=namespace,
        )
        self._append_event(
            build_event(
                self.context,
                EventType.AUTH_RESULT,
                self.nodes[receiver_id],
                security_state={
                    "auth_result": "PASS",
                    "auth_failure_reason": None,
                    "replay_check_result": "UNAVAILABLE",
                    "key_state": "AVAILABLE",
                },
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": "SESSION_LIFECYCLE_EVENT",
                },
                extensions={
                    "session_lifecycle": {
                        "state": "ACTIVE",
                        "previous_state": "STALE",
                    }
                },
                leader_id=self.leader_node_id,
            )
        )

    def _load_configured_episode_plans(self) -> None:
        """Load attack and normal plans carried by the public RunConfig."""

        from hashlib import sha256
        import json

        for index, raw in enumerate(self.config.attack_specs):
            value = deepcopy(raw)
            if not value.get("attack_id"):
                canonical = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                value["attack_id"] = (
                    f"attack-spec-{index + 1:03d}-{sha256(canonical).hexdigest()[:12]}"
                )
            self.schedule_attack(value)
        for index, raw in enumerate(self.config.normal_disturbance_specs):
            value = deepcopy(raw)
            if not value.get("profile_id"):
                canonical = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                value["profile_id"] = (
                    f"normal-spec-{index + 1:03d}-{sha256(canonical).hexdigest()[:12]}"
                )
            self.schedule_normal_disturbance(value)

    def _load_configured_scenario(self) -> None:
        self.scenario.load(
            deepcopy(self.config.traffic_specs),
            deepcopy(self.config.session_lifecycle_specs),
        )
        for spec in self.scenario.traffic_specs:
            if spec.source_node_id not in self.nodes or spec.target_node_id not in self.nodes:
                raise ValueError("TRAFFIC_SPEC_REFERENCES_UNKNOWN_NODE")
        for spec in self.scenario.session_lifecycle_specs:
            if spec.sender_node_id not in self.nodes or spec.receiver_node_id not in self.nodes:
                raise ValueError("SESSION_LIFECYCLE_REFERENCES_UNKNOWN_NODE")

    def _process_scenario_schedule(self) -> None:
        for item in self.context.scheduler.pop_due(self.context.clock.now_s):
            if item.kind == "SESSION_ROTATION":
                spec = self.scenario.lifecycle(str(item.payload["lifecycle_id"]))
                self.rotate_security_session(
                    spec.sender_node_id,
                    spec.receiver_node_id,
                    old_session_id=spec.old_session_id,
                    new_session_id=spec.new_session_id,
                    key_epoch=spec.key_epoch,
                    sequence_namespace=spec.sequence_namespace,
                )
                self.scenario.executed_session_lifecycle.append(
                    {
                        "lifecycle_id": spec.lifecycle_id,
                        "sim_time_s": self.context.clock.now_s,
                        "state_transition": "ACTIVE_TO_STALE_AND_NEW_ACTIVE",
                        "old_session_id": self.observable_session_id(
                            spec.old_session_id
                        ),
                        "new_session_id": self.observable_session_id(
                            spec.new_session_id
                        ),
                    }
                )
            elif item.kind == "BUSINESS_TRAFFIC":
                spec = self.scenario.traffic(str(item.payload["traffic_id"]))
                occurrence = int(item.payload["occurrence"])
                message_id = self.queue_message(
                    spec.source_node_id,
                    spec.target_node_id,
                    spec.packet_type,
                    measured_payload(deepcopy(spec.payload), spec.measurement_model,
                                     self.nodes[spec.source_node_id], self.context.clock.now_s, self.config.seed),
                    _account_business=True,
                    sensitive=spec.sensitive,
                    encrypt=spec.encrypt,
                    session_id=spec.session_id,
                    sequence_no=(
                        spec.sequence_start + occurrence
                        if spec.sequence_start is not None
                        else None
                    ),
                )
                self.scenario.executed_traffic.append(
                    {
                        "traffic_id": spec.traffic_id,
                        "occurrence": occurrence,
                        "sim_time_s": self.context.clock.now_s,
                        "message_id": message_id,
                        "queued": message_id is not None,
                    }
                )

    def _inject_normal_disturbances(self) -> None:
        for record in self.normal_disturbances.active(self.context.clock.now_s):
            plan = record.plan
            if plan.disturbance_type in {
                "NORMAL_TRAFFIC_BURST",
                "NORMAL_CONGESTION",
            }:
                if not self.normal_disturbances.effect_once(
                    record, "traffic", self._tick_index
                ):
                    continue
                source_id = int(plan.parameters.get("source_node_id", self.leader_node_id))
                target_id = (
                    plan.target_node_ids[0]
                    if plan.target_node_ids
                    else self.gcs_node_id
                )
                rate = float(plan.parameters.get("packet_rate_pps", 20.0))
                count = max(1, int(round(rate * self.config.step_s)))
                packet_size = int(
                    plan.parameters.get(
                        "target_packet_size_bytes",
                        plan.parameters.get("packet_size_bytes", 256),
                    )
                )
                packet_type = str(plan.parameters.get("packet_type", "STATUS")).upper()
                queued_ids: list[str] = []
                for index in range(count):
                    message_id = self.queue_message(
                        source_id,
                        target_id,
                        packet_type,
                        BusinessPacketTemplate.build(
                            sequence_value=(self._tick_index * 1000) + index,
                            target_size_bytes=packet_size,
                        ),
                        sensitive=False,
                    )
                    if message_id is not None:
                        queued_ids.append(message_id)
                record.evidence["generated_count"] = int(
                    record.evidence.get("generated_count", 0)
                ) + count
                record.evidence["queued_message_ids"] = [
                    *record.evidence.get("queued_message_ids", []),
                    *queued_ids,
                ]
                record.evidence["max_source_queue_length"] = max(
                    int(record.evidence.get("max_source_queue_length", 0)),
                    len(self.nodes[source_id].tx_queue),
                )
            elif plan.disturbance_type == "NORMAL_OUT_OF_ORDER":
                if not self.normal_disturbances.effect_once(record, "reorder"):
                    continue
                source_id = int(plan.parameters.get("source_node_id", self.leader_node_id))
                target_id = (
                    plan.target_node_ids[0]
                    if plan.target_node_ids
                    else self.gcs_node_id
                )
                session_id = str(
                    plan.parameters.get(
                        "session_id", f"normal-reorder-{plan.profile_id}"
                    )
                )
                sequences = list(
                    plan.parameters.get("sequence_numbers", [100, 102, 101])
                )
                packet_type = str(
                    plan.parameters.get("packet_type", "TELEMETRY")
                ).upper()
                for sequence in sequences:
                    message_id = self.queue_message(
                        source_id,
                        target_id,
                        packet_type,
                        {"altitude_m": 100.0},
                        session_id=session_id,
                        sequence_no=int(sequence),
                    )
                    if message_id is not None:
                        record.evidence.setdefault("queued_message_ids", []).append(
                            message_id
                        )
                record.evidence["sequence_numbers"] = [
                    int(sequence) for sequence in sequences
                ]
            elif plan.disturbance_type == "NORMAL_STATE_CHANGE":
                if not self.normal_disturbances.effect_once(record, "state"):
                    continue
                for node_id in plan.target_node_ids:
                    node = self.nodes[node_id]
                    if "battery_pct" in plan.parameters:
                        node.battery_pct = float(plan.parameters["battery_pct"])
                    if "flight_state" in plan.parameters:
                        node.flight_state = str(plan.parameters["flight_state"])
                    if "position_xyz_m" in plan.parameters:
                        node.position_xyz_m = tuple(
                            float(value)
                            for value in plan.parameters["position_xyz_m"]
                        )
                    self._append_event(
                        build_event(
                            self.context,
                            EventType.NODE_STATE,
                            node,
                            availability={
                                "payload_available": False,
                                "phy_available": False,
                                "missing_reason": "STATE_SAMPLE",
                            },
                            leader_id=self.leader_node_id,
                        )
                    )
                    telemetry_target = (
                        self.leader_node_id
                        if node.role == NodeRole.FOLLOWER
                        else (
                            self.gcs_node_id
                            if node.role == NodeRole.LEADER
                            else self.leader_node_id
                        )
                    )
                    message_id = self.queue_message(
                        node_id,
                        telemetry_target,
                        "TELEMETRY",
                        {
                            "altitude_m": float(node.position_xyz_m[2]),
                            "battery_pct": float(node.battery_pct),
                            "flight_state": str(node.flight_state),
                        },
                    )
                    record.evidence.setdefault("state_changes", []).append(
                        {
                            "node_id": node_id,
                            "battery_pct": node.battery_pct,
                            "flight_state": node.flight_state,
                            "position_xyz_m": list(node.position_xyz_m),
                            "consistent_telemetry_message_id": message_id,
                        }
                    )

    def _authorized_business_flow(self, src_id: int, dst_id: int) -> bool:
        source = self.nodes[src_id]
        destination = self.nodes[dst_id]
        src_role = source.role
        dst_role = destination.role
        if src_role == NodeRole.EXTERNAL:
            return False
        if not source.network_authorized or not destination.network_authorized:
            return False
        if src_role == NodeRole.GCS:
            return dst_role in {NodeRole.LEADER, NodeRole.FOLLOWER}
        if src_role == NodeRole.LEADER:
            return dst_role in {NodeRole.GCS, NodeRole.FOLLOWER}
        if src_role == NodeRole.FOLLOWER:
            return dst_role in {NodeRole.LEADER, NodeRole.GCS}
        return False

    def queue_message(
        self,
        src_id: int,
        dst_id: int,
        packet_type: str,
        payload: dict[str, Any],
        *,
        sensitive: bool = False,
        encrypt: bool | None = None,
        claimed_src_id: int | None = None,
        session_id: str | None = None,
        sequence_no: int | None = None,
        extensions: dict[str, Any] | None = None,
        bypass_authorization: bool = False,
        _immediate_attack_record: AttackRuntimeRecord | None = None,
        _account_business: bool = False,
    ) -> str | None:
        self._last_queue_attempt_message_id = None
        if src_id not in self.nodes or dst_id not in self.nodes:
            return None
        if not bypass_authorization and not self._authorized_business_flow(src_id, dst_id):
            return None
        route = self.topology.route(src_id, dst_id)
        if not route or len(route) < 2:
            return None
        source = self.nodes[src_id]
        sequence = sequence_no if sequence_no is not None else source.next_sequence()
        internal_session_id = session_id or f"session-{src_id}-{dst_id}-1"
        message = Message(
            message_id=self.context.ids.next("msg"),
            origin_node_id=src_id,
            final_dst_node_id=dst_id,
            claimed_src_id=src_id if claimed_src_id is None else claimed_src_id,
            claimed_dst_id=dst_id,
            packet_type=packet_type,
            payload=deepcopy(payload),
            sequence_no=sequence,
            session_id=internal_session_id,
            key_epoch=source.key_epoch,
            created_time_s=self.context.clock.now_s,
            route=route,
            sensitive=sensitive,
            encrypt_requested=(
                self.config.encrypt_sensitive and sensitive if encrypt is None else bool(encrypt)
            ),
            extensions=deepcopy(extensions or {}),
            observable_session_id=self.observable_session_id(internal_session_id),
            application_direction=self._application_direction(src_id, dst_id),
        )
        self._last_queue_attempt_message_id = message.message_id
        if _account_business:
            self.packet_accounting.business_generated(message)
        if _immediate_attack_record is not None:
            self.packet_accounting.attack_generated(message, _immediate_attack_record)
        message.application_size_bytes = serialized_application_size(message.payload)
        self.application_auth.sign(message)
        self.packet_accounting.signed(message, self.context.clock.now_s)
        signed_tag = message.app_hmac_tag
        message, attack_record = self.attack_scheduler.mutate_post_hmac(
            message, self.context.clock.now_s
        )
        message.application_size_bytes = serialized_application_size(message.payload)
        if attack_record is not None:
            attack_record.truth["application_hmac_generated_before_mutation"] = True
            attack_record.truth["application_hmac_preserved_after_mutation"] = (
                message.app_hmac_tag == signed_tag
            )
        if attack_record and attack_record.plan.attack_id:
            message.runtime_attack_id = attack_record.plan.attack_id
            self._record_attack_message_generated(
                attack_record, message.message_id
            )
        if _immediate_attack_record is not None:
            # Flooding uses a dedicated attack emission path: it keeps normal
            # Message/Frame/PHY semantics but does not consume the legitimate
            # application TX queue service budget or create post-attack
            # backlog. Bind offline provenance before the synchronous TX.
            message.runtime_attack_id = _immediate_attack_record.plan.attack_id
            self._message_attack_ids[message.message_id] = (
                _immediate_attack_record.plan.attack_id or ""
            )
            self._record_attack_message_generated(
                _immediate_attack_record, message.message_id
            )
            self._record_local_plaintext_protection(
                source,
                sensitive=message.sensitive,
                encrypted=message.encrypt_requested,
            )
            self._transmit_intent(source, TransmissionIntent(message=message))
            return message.message_id
        if not source.enqueue_tx(TransmissionIntent(message=message)):
            return None
        self._record_local_plaintext_protection(
            source, sensitive=message.sensitive, encrypted=message.encrypt_requested
        )
        if attack_record and attack_record.plan.attack_id:
            self._bind_attack_message(attack_record, message.message_id)
        return message.message_id

    def _generate_role_traffic(self) -> None:
        followers = sorted(
            node_id for node_id, role in self.roles.items() if role == NodeRole.FOLLOWER
        )
        target = followers[(self._tick_index - 1) % len(followers)] if followers else self.leader_node_id
        rng = self.context.rng.python("traffic")
        if self._tick_index % 5 == 0:
            self.queue_message(
                self.gcs_node_id,
                target,
                "MISSION_COMMAND",
                {
                    "cmd": "FLY_TO",
                    "position_x_m": round(150.0 + rng.uniform(-25, 25), 3),
                    "position_y_m": round(rng.uniform(-40, 40), 3),
                    "altitude_m": round(100.0 + rng.uniform(-10, 10), 3),
                },
                sensitive=True,
                _account_business=True,
            )

        else:
            follower = self.nodes[target]
            self.queue_message(
                target,
                self.gcs_node_id,
                "TELEMETRY",
                {
                    "battery_pct": round(max(0.0, follower.battery_pct - 0.01), 3),
                    "position_x_m": follower.position_xyz_m[0],
                    "position_y_m": follower.position_xyz_m[1],
                    "altitude_m": follower.position_xyz_m[2],
                    "flight_state": follower.flight_state,
                },
                sensitive=True,
                _account_business=True,
            )

    @staticmethod
    def _record_local_plaintext_protection(
        node: Node, *, sensitive: bool, encrypted: bool
    ) -> None:
        """Track locally knowable protection state, never eavesdropper truth."""

        if not sensitive:
            return
        if encrypted:
            node.protected_sensitive_count += 1
        else:
            node.unprotected_sensitive_count += 1

    def schedule_attack(self, plan: AttackPlan | dict[str, Any]) -> dict[str, Any]:
        requested = asdict(plan) if isinstance(plan, AttackPlan) else deepcopy(plan)
        actual = AttackPlan(**deepcopy(requested))
        # Resolve defaults once, before scheduling.  The resolved plan is the
        # one executed and exported; the untouched request remains in label
        # truth for auditability.
        if not actual.target_node_ids:
            if (
                actual.target_link_ids
                and actual.target_link_ids[0] in self.topology.links
            ):
                actual.target_node_ids = [
                    self.topology.links[actual.target_link_ids[0]].dst_id
                ]
            else:
                actual.target_node_ids = [self.leader_node_id]
        if actual.attacker_node_id is None:
            if actual.attack_family == "FDI":
                followers = sorted(
                    node_id
                    for node_id, role in self.roles.items()
                    if role == NodeRole.FOLLOWER
                )
                actual.attacker_node_id = (
                    followers[0] if followers else self.gcs_node_id
                )
            else:
                actual.attacker_node_id = -1
        if actual.impact_start_s >= self.config.duration_s or actual.end_s > self.config.duration_s + 1e-9:
            raise ValueError("ATTACK_INTERVAL_OUTSIDE_RUN_DURATION")
        unknown_nodes = [
            node_id for node_id in actual.target_node_ids if node_id not in self.nodes
        ]
        if unknown_nodes:
            raise ValueError(f"UNKNOWN_ATTACK_TARGET_NODES:{unknown_nodes}")
        unknown_links = [
            link_id for link_id in actual.target_link_ids if link_id not in self.topology.links
        ]
        if unknown_links:
            raise ValueError(f"UNKNOWN_ATTACK_TARGET_LINKS:{unknown_links}")
        if actual.attack_family == "FDI":
            attacker_id = actual.attacker_node_id
            if actual.parameters.get('injection_mode') in {'ON_PATH_INTERCEPTION_REPLACEMENT', 'CAPTURE_MODIFY_INJECT'}:
                source = actual.parameters['legitimate_source_id']
                target = actual.target_node_ids[0]
                if source not in self.roles or source == target:
                    raise ValueError('FDI_ON_PATH_SOURCE_MUST_BE_LEGITIMATE')
                if attacker_id is None or attacker_id in self.roles:
                    raise ValueError('FDI_ON_PATH_ATTACKER_MUST_BE_EXTERNAL')
                original_link = self.topology.get_link(source, target)
                if original_link is None or not original_link.active or actual.target_link_ids != [original_link.link_id]:
                    raise ValueError('FDI_ON_PATH_REQUIRES_EXPLICIT_SINGLE_LINK')
            else:
                if attacker_id is None or attacker_id not in self.nodes:
                    raise ValueError("FDI_REQUIRES_EXISTING_COMPROMISED_NODE")
                if self.nodes[attacker_id].role == NodeRole.EXTERNAL:
                    raise ValueError("FDI_ATTACKER_MUST_BE_A_LEGITIMATE_NODE")
            # `attacker_node_id` is the compromised legitimate origin;
            # `target_node_ids` are affected business receivers.  They are
            # intentionally not required to overlap.
        # Single-attack demonstrations use confidentiality only for passive
        # eavesdropping.  The four active attack families are authenticated
        # plaintext so their HMAC/replay semantics remain directly visible.
        if not self.attack_scheduler.records:
            self.config.encrypt_sensitive = actual.attack_family == "EAVESDROPPING"
        scheduled = self.attack_scheduler.schedule(actual, requested_plan=requested)
        self.packet_accounting.register_attack(scheduled)
        scheduled_record = self.attack_scheduler.records[scheduled.attack_id or ""]
        scheduled_record.truth["observable_target_link_ids"] = [
            self.observable_link_id(link_id) for link_id in scheduled.target_link_ids
        ]
        return asdict(scheduled)

    def _inject_active_attacks(self) -> None:
        now_s = self.context.clock.now_s
        for record in self.attack_scheduler.active(now_s):
            plan = record.plan
            if plan.attack_family == "SPOOFING":
                self._inject_spoofing(record)
            elif plan.attack_family == "DOS" and plan.attack_subtype == "FLOODING":
                self._inject_flooding(record)
            elif plan.attack_family == "REPLAY":
                self._inject_replay(record)
            elif plan.attack_family == "FDI" and plan.parameters.get('injection_mode') == 'CAPTURE_MODIFY_INJECT':
                self._inject_derived_fdi(record)

    def _inject_spoofing(self, record: AttackRuntimeRecord) -> None:
        if record.plan.parameters.get("source_copy_mode") == "LEGITIMATE_FRAME_COPY":
            self._inject_derived_spoofing(record)
            return
        if not self.attack_scheduler.effect_once_per_tick(
            record, "spoof", self._tick_index
        ):
            return
        target = record.plan.target_node_ids[0]
        attacker_id = int(record.plan.attacker_node_id)
        AttackOutcomePolicy.attempted(record)
        self._external_node(attacker_id)
        self.packet_accounting.attempt(record, self._tick_index)
        self.topology.ensure_external_ingress(attacker_id, [target])
        self._register_link_identifiers()
        self.phy._ensure_states()
        claimed = record.plan.parameters.get("claimed_src_id")
        if claimed is None:
            claimed = 999 if "UNKNOWN" in record.plan.attack_subtype else self.gcs_node_id
        original_claimed = attacker_id
        message_id = self.queue_message(
            attacker_id,
            target,
            "MISSION_COMMAND",
            {"cmd": "HOVER", "mode": "hold"},
            sensitive=False,
            encrypt=False,
            claimed_src_id=original_claimed,
            bypass_authorization=True,
        )
        if message_id:
            queued = next(
                intent.message
                for intent in reversed(self.nodes[attacker_id].tx_queue)
                if intent.message.message_id == message_id
            )
            original_fields = {
                "claimed_src_id": queued.claimed_src_id,
                "payload": deepcopy(queued.payload),
                "packet_type": queued.packet_type,
                "sequence_no": queued.sequence_no,
                "created_time_s": queued.created_time_s,
            }
            # The attack changes exactly one application identity field after
            # the sender's (untrusted) tag was generated.
            queued.claimed_src_id = int(claimed)
            self.packet_accounting.attack_generated(queued, record)
            self._bind_attack_message(record, message_id)
            record.truth.update(
                {
                    "actual_transmitter_id": attacker_id,
                    "original_application_fields": original_fields,
                    "claimed_src_id": int(claimed),
                    "identity_conflict": int(claimed) in self.nodes,
                    "modified_fields": ["claimed_src_id"],
                    "application_hmac_recomputed": False,
                }
            )
            AttackOutcomePolicy.injected(record)

    def _capture_spoof_original(self, frame: Frame) -> None:
        """Explicit attacker observation capability: copy actual source TX frames.

        This is simulator truth, never an authentication or detector input.
        Only scheduled business first hops qualify; no synthetic source/tag.
        """
        info = self.packet_accounting.messages.get(frame.message_id, {})
        if not info.get("business") or frame.runtime_attack_id or frame.hop_index != 0:
            return
        for record in self.attack_scheduler.records.values():
            plan = record.plan
            copy_spoof = plan.attack_family == 'SPOOFING' and plan.parameters.get('source_copy_mode') == 'LEGITIMATE_FRAME_COPY'
            copy_fdi = plan.attack_family == 'FDI' and plan.parameters.get('injection_mode') == 'CAPTURE_MODIFY_INJECT'
            capture_start = plan.impact_start_s if copy_fdi else plan.scheduled_start_s
            if (not (copy_spoof or copy_fdi)
                    or frame.link_sender_id != plan.parameters.get("legitimate_source_id")
                    or frame.link_receiver_id not in plan.target_node_ids
                    or (copy_fdi and frame.encrypted)
                    or not capture_start <= self.context.clock.now_s < plan.end_s):
                continue
            token = (plan.attack_id, frame.message_id)
            if token not in self._spoof_original_frames:
                self._external_node(int(plan.attacker_node_id))
                self._spoof_original_frames[token] = (frame.clone_for_replay(), self.context.clock.now_s)
                self.packet_accounting.capture_record(record, frame, self.context.clock.now_s)

    def _inject_derived_spoofing(self, record: AttackRuntimeRecord) -> None:
        candidates = [(key, value) for key, value in self._spoof_original_frames.items()
                      if key[0] == record.plan.attack_id and key not in self._spoof_used_originals
                      and value[1] < self.context.clock.now_s]
        if not candidates:
            return
        key, (original, captured_s) = candidates[0]
        self._spoof_used_originals.add(key)
        AttackOutcomePolicy.attempted(record)
        self.packet_accounting.attempt(record, original.message_id)
        attacker_id = int(record.plan.attacker_node_id)
        target = original.link_receiver_id
        attacker = self._external_node(attacker_id)
        self.topology.ensure_external_ingress(attacker_id, [target])
        self._register_link_identifiers()
        self.phy._ensure_states()
        link = next(link for link in self.topology.links.values()
                    if link.src_id == attacker_id and link.dst_id == target)
        frame = original.clone_for_replay()
        frame.message_id = self.context.ids.next("msg")  # simulator ID, not an authenticated wire field
        frame.claimed_src_id = int(record.plan.parameters["claimed_src_id"])
        frame.link_id, frame.link_sender_id, frame.link_receiver_id = link.link_id, attacker_id, target
        frame.route = [attacker_id, target]
        frame.runtime_attack_id = record.plan.attack_id
        self.packet_accounting.derived_spoof(record, original, frame, captured_s, self.context.clock.now_s)
        self._bind_attack_message(record, frame.message_id)
        record.truth.update({"actual_transmitter_id": attacker_id,
                            "original_sender_id": original.claimed_src_id,
                            "original_message_id": original.message_id,
                            "original_capture_time_s": captured_s,
                            "claimed_src_id": frame.claimed_src_id,
                            "modified_fields": ["claimed_src_id"],
                            "application_hmac_recomputed": False})
        AttackOutcomePolicy.injected(record)
        self._perform_air_transmission(frame, attacker, self.nodes[target], link)

    def _inject_derived_fdi(self, record: AttackRuntimeRecord) -> None:
        """Additional malicious copy of an actual transmitted, signed source frame.

        Does not route, suppress or mutate the original. Capture capability is
        the same explicit simulator observation capability used for Spoofing.
        """
        candidates = [(key, value) for key, value in self._spoof_original_frames.items()
                      if key[0] == record.plan.attack_id and key not in self._spoof_used_originals
                      and value[1] < self.context.clock.now_s]
        if not candidates:
            return
        key, (original, captured_s) = candidates[0]
        self._spoof_used_originals.add(key)
        attacker_id = int(record.plan.attacker_node_id)
        target = original.link_receiver_id
        copy_id = self.context.ids.next('msg')
        message = Message(message_id=copy_id, origin_node_id=original.link_sender_id,
            final_dst_node_id=target, claimed_src_id=original.claimed_src_id, claimed_dst_id=original.claimed_dst_id,
            packet_type=original.packet_type, payload=deepcopy(original.protected_payload),
            sequence_no=original.sequence_no, session_id=original.session_id, key_epoch=original.key_epoch,
            created_time_s=original.created_time_s, route=list(original.route), sensitive=original.sensitive,
            application_direction=original.application_direction, app_hmac_tag=original.app_hmac_tag,
            app_hmac_key_id=original.app_hmac_key_id, observable_session_id=original.observable_session_id)
        self.packet_accounting.attempt(record, original.message_id)
        message, modified = self.attack_scheduler.mutate_post_hmac(message, self.context.clock.now_s, on_path_record=record)
        if modified is None:
            return
        attacker = self._external_node(attacker_id)
        self.topology.ensure_external_ingress(attacker_id, [target])
        self._register_link_identifiers()
        self.phy._ensure_states()
        link = self.topology.get_link(attacker_id, target)
        # Build the additional plaintext air envelope normally. This does NOT
        # sign Application HMAC: the captured end-to-end tag remains unchanged.
        # Test-only link checksum must describe the actual emitted payload too.
        message.route = [attacker_id, target]
        message.runtime_attack_id = record.plan.attack_id
        message.application_size_bytes = serialized_application_size(message.payload)
        frame = self.crypto.protect(message, attacker_id, target, link.link_id, 0)
        frame.claimed_link_sender_id = original.claimed_link_sender_id
        frame.observable_link_id = self.observable_link_id(link.link_id)
        frame.observable_session_id = original.observable_session_id
        frame.runtime_attack_id = record.plan.attack_id
        mutation = self.packet_accounting.causal['mutations'][-1]
        mutation.update(original_message_id=original.message_id, capture_time_s=captured_s)
        self.packet_accounting.causal['derivations'].append({
            'original': self.packet_accounting.frame_identity(original), 'copy': self.packet_accounting.frame_identity(frame),
            'capture_time_s': captured_s, 'modified_time_s': self.context.clock.now_s,
            'attacker_id': attacker_id, 'modified_fields': mutation['changed_fields']})
        self._bind_attack_message(record, copy_id)
        record.truth.update(actual_transmitter_id=attacker_id, original_sender_id=original.claimed_src_id,
                            original_message_id=original.message_id, original_capture_time_s=captured_s)
        self._perform_air_transmission(frame, attacker, self.nodes[target], link)

    def _inject_flooding(self, record: AttackRuntimeRecord) -> None:
        target = record.plan.target_node_ids[0]
        attacker_id = int(record.plan.attacker_node_id)
        AttackOutcomePolicy.attempted(record)
        if attacker_id not in self.nodes:
            self._external_node(attacker_id)
            self.topology.ensure_external_ingress(attacker_id, [target])
            self._register_link_identifiers()
            self.phy._ensure_states()
        pps = float(record.plan.intensity.get("value", 60.0))
        # Integer cumulative quota: no per-tick minimum-one bias.
        ticks = int(record.truth.get("emission_tick_count", 0)) + 1
        total_quota = math.floor(ticks * pps * self.config.step_s + 1e-9)
        burst = total_quota - int(record.truth.get("emission_quota", 0))
        record.truth["emission_tick_count"] = ticks
        record.truth["emission_quota"] = total_quota
        self.packet_accounting.attempt(record, self._tick_index)
        transmitted = 0
        generated = 0
        packet_type = str(record.plan.parameters.get("packet_type", "STATUS")).upper()
        packet_size = int(
            record.plan.parameters.get(
                "target_packet_size_bytes",
                record.plan.parameters.get("packet_size_bytes", 256),
            )
        )
        for index in range(burst):
            message_id = self.queue_message(
                attacker_id,
                target,
                packet_type,
                BusinessPacketTemplate.build(
                    sequence_value=(self._tick_index * 1000) + index,
                    target_size_bytes=packet_size,
                ),
                sensitive=False,
                encrypt=False,
                bypass_authorization=True,
                _immediate_attack_record=record,
            )
            generated_id = self._last_queue_attempt_message_id
            if generated_id is not None:
                generated += 1
                self._record_attack_message_generated(record, generated_id)
            if message_id:
                transmitted += 1
        record.truth["generated_packets"] = int(record.truth.get("generated_packets", 0)) + generated
        record.truth["transmitted_packets"] = int(
            record.truth.get("transmitted_packets", 0)
        ) + transmitted
        # Explicitly distinguish the dedicated emitter from the normal TX
        # queue.  Historical readers may still inspect this compatibility key.
        record.truth["queued_packets"] = int(record.truth.get("queued_packets", 0))
        record.truth["backlogged_message_ids"] = []
        record.outcome["queued_backlog_count"] = 0
        if generated:
            AttackOutcomePolicy.injected(record)

    def _inject_replay(self, record: AttackRuntimeRecord) -> None:
        if record.truth.get("replay_count", 0) and not bool(
            record.plan.parameters.get("repeat", False)
        ):
            return
        if not self.attack_scheduler.effect_once_per_tick(
            record, "replay", self._tick_index
        ):
            return
        AttackOutcomePolicy.attempted(record)
        candidate = self.attack_scheduler.replay_candidate(
            record, self.context.clock.now_s
        )
        self.packet_accounting.add(self.packet_accounting.attack(record.plan.attack_id), 'candidate_check_count', self._tick_index)
        if candidate is None:
            return
        self.packet_accounting.attempt(record, self._tick_index)
        frame, capture_time_s = candidate
        record.outcome.pop("failure_reason", None)
        self._transmit_replay_frame(frame, capture_time_s, record)

    def _service_tx(self, node: Node, budget: int) -> None:
        for _ in range(budget):
            intent = None
            if node.forward_queue and node.tx_queue:
                # Preserve forwarding service without starving locally queued
                # control/security traffic under a continuous relay stream.
                # Creation time is deterministic SimulationClock time; ties
                # keep the historical forwarding-first behavior.
                if (
                    node.tx_queue[0].message.created_time_s
                    < node.forward_queue[0].message.created_time_s
                ):
                    intent = node.tx_queue.popleft()
                else:
                    intent = node.forward_queue.popleft()
            elif node.forward_queue:
                intent = node.forward_queue.popleft()
            elif node.tx_queue:
                intent = node.tx_queue.popleft()
            if intent is None:
                return
            self._transmit_intent(node, intent)

    def _transmit_intent(self, sender: Node, intent: TransmissionIntent) -> None:
        message = intent.message
        hop_index = intent.hop_index
        interception_record = None
        if hop_index == 0 and self.packet_accounting.messages.get(message.message_id, {}).get('business'):
            for record in self.attack_scheduler.active(self.context.clock.now_s, 'FDI'):
                plan = record.plan
                if (plan.parameters.get('injection_mode') == 'ON_PATH_INTERCEPTION_REPLACEMENT'
                        and sender.node_id == plan.parameters['legitimate_source_id']
                        and message.final_dst_node_id in plan.target_node_ids
                        and len(message.route) == 2 and not message.encrypt_requested):
                    # Configured controlled relay replaces the direct delivery path.
                    # It is NOT the ability of an ordinary passive wireless listener.
                    self._external_node(plan.attacker_node_id)
                    self.topology.ensure_external_ingress(plan.attacker_node_id, [sender.node_id, message.final_dst_node_id])
                    self._register_link_identifiers()
                    self.phy._ensure_states()
                    message.route = [sender.node_id, plan.attacker_node_id, message.final_dst_node_id]
                    interception_record = record
                    break
        if hop_index >= len(message.route) - 1:
            return
        receiver_id = message.route[hop_index + 1]
        receiver = self.nodes[receiver_id]
        link = self.topology.get_link(sender.node_id, receiver_id)
        if link is None or not link.active:
            self._mark_report_failed(message)
            return
        if intent.replay_frame is not None and not self.config.application_layer_available:
            frame = intent.replay_frame.clone_for_replay()
            frame.hop_index = hop_index
            frame.link_id = link.link_id
            frame.link_sender_id = sender.node_id
            frame.link_receiver_id = receiver_id
            frame.claimed_link_sender_id = sender.node_id
            frame.observable_link_id = self.observable_link_id(link.link_id)
            self._perform_air_transmission(frame, sender, receiver, link)
            return
        try:
            frame = self.crypto.protect(
                message, sender.node_id, receiver_id, link.link_id, hop_index
            )
        except CryptoProtectionError as exc:
            # Required encryption never degrades to plaintext. The packet is
            # withheld, the failure is observable, and PERSON_A mode may start
            # an in-band SKG exchange for this exact business session.
            sender.drop_count += 1
            self._mark_report_failed(message)
            self._append_event(
                build_event(
                    self.context,
                    EventType.AUTH_RESULT,
                    sender,
                    security_state={
                        "auth_result": "UNAVAILABLE",
                        "auth_failure_reason": exc.error_code,
                        "replay_check_result": "UNAVAILABLE",
                        "key_state": exc.key_state,
                    },
                    availability={
                        "payload_available": False,
                        "phy_available": False,
                        "missing_reason": exc.error_code,
                    },
                    extensions={
                        "crypto_send_failure": {
                            "withheld_message_ref": message.message_id,
                            "status": exc.status,
                            "error_code": exc.error_code,
                            "key_state": exc.key_state,
                            "skg_required": exc.key_state in {"MISSING", "EXPIRED"},
                        }
                    },
                    leader_id=self.leader_node_id,
                )
            )
            if self.security_coordinator is not None and sender.role != NodeRole.EXTERNAL:
                self.security_coordinator.ensure_session(
                    sender.node_id,
                    receiver_id,
                    message.session_id,
                    message.key_epoch,
                )
            return
        if intent.claimed_link_sender_id is not None:
            frame.claimed_link_sender_id = intent.claimed_link_sender_id
        if sender.role != NodeRole.EXTERNAL:
            self.rules[receiver_id].activate_session(
                sender.node_id,
                receiver_id,
                message.session_id,
                frame.key_epoch,
                sequence_namespace=message.origin_node_id,
            )
        frame.observable_link_id = self.observable_link_id(link.link_id)
        frame.observable_session_id = (
            message.observable_session_id
            or self.observable_session_id(message.session_id)
        )
        self._perform_air_transmission(frame, sender, receiver, link,
            fdi_interception=(interception_record, message) if interception_record else None)

    def _perform_air_transmission(
        self,
        frame: Frame,
        sender: Node,
        receiver: Node,
        link: DirectedLink,
        *,
        replay_record: AttackRuntimeRecord | None = None,
        fdi_interception: tuple[AttackRuntimeRecord, Message] | None = None,
    ) -> None:
        if replay_record is not None:
            frame.runtime_attack_id = replay_record.plan.attack_id
        elif frame.runtime_attack_id is None:
            frame.runtime_attack_id = self._message_attack_ids.get(frame.message_id)
        contributing_records = self._contributing_attack_records(
            frame, link.link_id, self.phy.states[link.link_id].channel_id
        )
        normal = self.normal_disturbances.link_modifiers(
            link.link_id, self.context.clock.now_s
        )
        packet_size = (
            frame.application_size_bytes
            if frame.application_size_bytes is not None
            else serialized_application_size(frame.protected_payload)
        )
        outcome = self.phy.sample(
            link,
            sender,
            receiver,
            self.context.clock.now_s,
            interference_power_dbm=None,
            packet_size_bytes=packet_size,
            natural_attenuation_db=normal["attenuation_db"],
            natural_loss_probability=normal["loss_probability"],
            natural_busy_ratio_addition=normal["busy_ratio_addition"],
        )
        observation = deepcopy(outcome.observation)
        observation["rf_sample_ref"] = self._rf_sample_bindings.get(
            (frame.message_id, link.link_id)
        )
        rff_security_state = {}
        rff_result = None
        if self.rff_service is not None:
            rff_observation = self.rff_service.observe(
                actual_device_id=sender.node_id,
                receiver_id=receiver.node_id,
                sim_time_s=self.context.clock.now_s,
                sinr_db=observation.get("sinr_db"),
                measurement_quality=observation.get("measurement_quality"),
                sample_id=self.context.ids.next("rff"),
            )
            observation["rff_observation"] = rff_observation.to_online_dict()
            # A configured RFF adapter replaces the baseline identifier; its
            # asynchronous result retains the existing model-state semantics.
            if self._rff_template_identifier_enabled:
                rff_result = self.rff_service.identify(
                    receiver.node_id, frame.claimed_link_sender_id, rff_observation,
                )
                rff_security_state = rff_result.to_security_state()
                rff_security_state["rff_last_update_s"] = self.context.clock.now_s
                for name, value in rff_security_state.items():
                    setattr(receiver, name, value)
        observable_extensions = deepcopy(frame.extensions)
        tx_event = build_event(
            self.context,
            EventType.TX,
            sender,
            message=frame,
            traffic={
                "latency_ms": outcome.latency_ms,
                "throughput_mbps": outcome.throughput_mbps,
            },
            availability={
                "payload_available": not frame.encrypted,
                "phy_available": False,
                "missing_reason": None,
            },
            extensions=observable_extensions,
            leader_id=self.leader_node_id,
        )
        self._append_event(tx_event)
        emission = tx_event["event_id"]
        observable_extensions["air_emission_ref"] = emission
        self.packet_accounting.air_sent(frame, replay_record, emission)
        self.packet_accounting.transmission(frame, sender.node_id, self.context.clock.now_s, emission, outcome.decode_success)
        if frame.runtime_attack_id:
            self._attack_event_ids.add(tx_event["event_id"])
            self._mark_attack_message_observable(frame, tx_event["event_id"])
        self._metric_totals["tx"] += 1
        self._metric_totals["latency_ms_sum"] += outcome.latency_ms
        self._metric_totals["throughput_mbps_sum"] += outcome.throughput_mbps
        if replay_record is None:
            self.attack_scheduler.capture(frame, self.context.clock.now_s)
            self._capture_spoof_original(frame)
        self._evaluate_eavesdroppers(frame, sender, observation)

        if fdi_interception is not None:
            record, source_message = fdi_interception
            if outcome.decode_success:
                self._metric_totals['rx_success'] += 1
                capture_event = build_event(self.context, EventType.RX_SUCCESS, receiver,
                    message=frame, phy=observation,
                    security_state=rff_security_state,
                    availability={'payload_available': True, 'phy_available': True, 'missing_reason': None},
                    leader_id=self.leader_node_id)
                self._append_event(capture_event)
                self.packet_accounting.capture_record(record, frame, self.context.clock.now_s)
                replacement = deepcopy(source_message)
                replacement, modified_record = self.attack_scheduler.mutate_post_hmac(
                    replacement, self.context.clock.now_s, on_path_record=record)
                replacement.application_size_bytes = serialized_application_size(replacement.payload)
                if modified_record is not None:
                    replacement.runtime_attack_id = record.plan.attack_id
                    self._bind_attack_message(record, replacement.message_id)
                    replacement_status = receiver.enqueue_forward(TransmissionIntent(
                        replacement, 1, claimed_link_sender_id=frame.claimed_link_sender_id,
                    ))
                    self.packet_accounting.causal['interceptions'].append({
                        'message_id': replacement.message_id, 'attack_id': record.plan.attack_id,
                        'attacker_id': receiver.node_id, 'source_id': sender.node_id,
                        'target_id': replacement.final_dst_node_id, 'original_frame': self.packet_accounting.frame_identity(frame),
                        'original_emission_id': emission, 'capture_event_id': capture_event['event_id'],
                        'capture_time_s': self.context.clock.now_s, 'replacement_queued': replacement_status,
                        'mode': 'ON_PATH_INTERCEPTION_REPLACEMENT', 'original_target_delivery_suppressed': True,
                        'replacement_emission_id': None, 'replacement_sent_time_s': None})
                else:
                    receiver.enqueue_forward(TransmissionIntent(
                        replacement, 1, claimed_link_sender_id=frame.claimed_link_sender_id,
                    ))
            # Original can only arrive at the controlled relay, never at target.
            return

        if outcome.decode_success:
            self.packet_accounting.arrived(frame, replay_record, emission)
            arrival_detection, arrival_statistics = self.rules[
                receiver.node_id
            ].record_arrival(self.context.clock.now_s)
            self.receiver_rate_observations.arrival(receiver.node_id, self.context.clock.now_s, arrival_statistics)
            rff_decision = self._rff_admission(receiver, rff_result, arrival_statistics)
            if rff_decision is not None:
                observable_extensions["rff_decision"] = rff_decision
                rff_security_state.update(self._rff_policy_snapshot(receiver))
            rx_event = build_event(
                self.context,
                EventType.RX_SUCCESS,
                receiver,
                message=frame,
                phy=observation,
                security_state=rff_security_state,
                traffic={
                    "latency_ms": outcome.latency_ms,
                    "throughput_mbps": outcome.throughput_mbps,
                    **arrival_statistics,
                },
                availability={
                    "payload_available": False,
                    "phy_available": True,
                    "missing_reason": "PAYLOAD_REQUIRES_AUTHENTICATION",
                },
                extensions=observable_extensions,
                leader_id=self.leader_node_id,
            )
            self._append_event(rx_event)
            if frame.runtime_attack_id:
                self._attack_event_ids.add(rx_event["event_id"])
            self._metric_totals["rx_success"] += 1
            if arrival_detection is not None and self.config.application_layer_available:
                self._handle_detection(
                    receiver, frame, arrival_detection, rx_event["event_id"]
                )
            received = ReceivedFrame(
                frame, observation, self.context.clock.now_s,
                rff_security_state=deepcopy(rff_security_state),
            )
            rejected_at_ingress = self._apply_rff_admission(
                receiver, frame, rx_event, rff_decision,
            )
            if (
                not rejected_at_ingress
                and self._can_parse_application(frame)
                and not frame.encrypted
                and self.application_auth.applies_to(frame.packet_type)
            ):
                # Receiver-total arrival accounting above deliberately sees
                # every decoded frame.  Plaintext business traffic is then
                # authenticated before it can consume the normal RX queue.
                opened = self.crypto.open(frame, receiver.node_id)
                application_verification = self._application_verification(
                    frame, opened
                )
                if (
                    opened.auth_result != "PASS"
                    or not application_verification.passed
                ):
                    if not application_verification.passed:
                        self._record_application_hmac_rejection(
                            frame, application_verification
                        )
                    self._inspect_received_security(
                        receiver, received, opened, application_verification
                    )
                    receiver.drop_count += 1
                    self._record_attack_blocked(frame)
                    self._mark_report_failed_from_frame(frame)
                    rejected_at_ingress = True
                else:
                    received.application_hmac_checked = True
                    received.application_hmac_result = application_verification.result
                    received.application_hmac_failure_reason = (
                        application_verification.failure_reason
                    )
                    received.application_hmac_key_id = application_verification.key_id
            if not rejected_at_ingress and not receiver.enqueue_rx(received):
                self._mark_report_failed_from_frame(frame)
        else:
            rff_decision = self._rff_admission(
                receiver, rff_result,
                self.rules[receiver.node_id].arrival_statistics(self.context.clock.now_s),
            )
            if rff_decision is not None:
                # A failed decode already has no packet to admit or drop.
                rff_decision["drop"] = False
                observable_extensions["rff_decision"] = rff_decision
                rff_security_state.update(self._rff_policy_snapshot(receiver))
            rx_event = build_event(
                self.context,
                EventType.RX_FAILURE,
                receiver,
                message=frame,
                phy=observation,
                security_state=rff_security_state,
                availability={
                    "payload_available": False,
                    "phy_available": True,
                    "missing_reason": "DECODE_FAILED",
                },
                extensions=observable_extensions,
                leader_id=self.leader_node_id,
            )
            self._append_event(rx_event)
            if frame.runtime_attack_id:
                self._attack_event_ids.add(rx_event["event_id"])
            self._metric_totals["rx_failure"] += 1
            self._apply_rff_admission(receiver, frame, rx_event, rff_decision)
            if self.config.application_layer_available:
                self._handle_phy_detection(receiver, frame, observation, rx_event)
            self._mark_report_failed_from_frame(frame)
        self._record_compound_attribution(
            contributing_records,
            frame,
            link.link_id,
            [tx_event["event_id"], rx_event["event_id"]],
        )
        if replay_record is not None:
            replay_record.truth.update(
                {
                    "actual_transmitter_id": replay_record.plan.attacker_node_id,
                    "replayed_message_id": frame.message_id,
                    "replayed_sequence_no": frame.sequence_no,
                    "replay_mode": replay_record.plan.attack_subtype,
                }
            )
            # Decode only means the replay reached the receiver.  Whether it
            # became effective depends on the receiver accepting/acting on it.
            if outcome.decode_success:
                AttackOutcomePolicy.reached_target(replay_record)
            else:
                AttackOutcomePolicy.injected(replay_record)
            AttackOutcomePolicy.refresh(replay_record)
        self._record_attack_air_outcome(frame, outcome.decode_success)

    @staticmethod
    def _rff_policy_snapshot(node: Node) -> dict[str, Any]:
        return {
            "rff_policy_state": node.rff_policy_state,
            "rff_strict_since_s": node.rff_strict_since_s,
            "rff_clear_since_s": node.rff_clear_since_s,
        }

    def _sync_rff_policy(self, node: Node) -> None:
        policy = self.rff_policies[node.node_id]
        node.rff_policy_state = policy.state
        node.rff_strict_since_s = policy.strict_since_s
        node.rff_clear_since_s = policy.clear_since_s

    def _refresh_rff_receiver(self, node: Node) -> None:
        policy = self.rff_policies.get(node.node_id)
        if policy is None:
            return
        statistics = self.rules[node.node_id].arrival_statistics(self.context.clock.now_s)
        transition = policy.refresh(
            sim_time_s=self.context.clock.now_s,
            queue_ratio=len(node.rx_queue) / node.queue_capacity,
            packet_rate_pps=float(statistics["packet_rate_pps"]),
        )
        self._sync_rff_policy(node)
        if transition and self.config.rff_policy_mode == "ENFORCE":
            event = build_event(
                self.context, EventType.NODE_STATE, node,
                extensions={"rff_policy_transition": {
                    "transition": transition, **self._rff_policy_snapshot(node),
                    "packet_rate_pps": statistics["packet_rate_pps"],
                    "queue_ratio": len(node.rx_queue) / node.queue_capacity,
                }}, leader_id=self.leader_node_id,
            )
            self._append_event(event)
            self._report_rff(node, "RFF_STRICT_WHITELIST",
                event["extensions"]["rff_policy_transition"], [event["event_id"]])

    def _rff_admission(self, receiver: Node, identification: Any,
                       statistics: dict[str, Any]) -> dict[str, Any] | None:
        policy = self.rff_policies.get(receiver.node_id)
        if policy is None or identification is None:
            return None
        store = self.rff_service.template_store
        decision = policy.evaluate(
            sim_time_s=self.context.clock.now_s, identification=identification,
            claimed_is_whitelisted=store.is_whitelisted(receiver.node_id, identification.claimed_link_sender_id),
            predicted_is_whitelisted=store.is_whitelisted(receiver.node_id, identification.predicted_device_id),
            queue_ratio=len(receiver.rx_queue) / receiver.queue_capacity,
            packet_rate_pps=float(statistics["packet_rate_pps"]),
        )
        self._sync_rff_policy(receiver)
        return {
            **asdict(decision), "decision_time_s": self.context.clock.now_s,
            "quality": identification.quality,
            "packet_rate_pps": statistics["packet_rate_pps"],
            "queue_ratio": len(receiver.rx_queue) / receiver.queue_capacity,
        }

    def _apply_rff_admission(self, receiver: Node, frame: Frame,
                             event: dict[str, Any], decision: dict[str, Any] | None) -> bool:
        if decision is None or self.config.rff_policy_mode != "ENFORCE":
            return False
        if decision.get("transition"):
            self._report_rff(receiver, "RFF_STRICT_WHITELIST",
                {**decision, **self._rff_policy_snapshot(receiver)}, [event["event_id"]])
        result = None
        evidence_ids = [event["event_id"]]
        if decision["drop"]:
            request = DefenseRequest(
                request_id=self.context.ids.next("defense-request"),
                action=DefenseAction.DROP_PACKET,
                requester_node_id=receiver.node_id, target_node_id=receiver.node_id,
                requested_time_s=self.context.clock.now_s, reason=decision["reason"],
            )
            result = self.defense.execute(request, receiver, self.context.clock.now_s).to_dict()
            if result["executed"]:
                receiver.drop_count += 1
                self._record_attack_blocked(frame)
                self._mark_report_failed_from_frame(frame)
            else:
                decision["drop"] = False
                event["extensions"]["rff_decision"]["drop"] = False
            audit = build_event(
                self.context, EventType.DEFENSE_RESULT, receiver, message=frame,
                security_state=event["online_features"]["security_state"],
                extensions={"defense_result": result, "rff_decision": deepcopy(decision),
                    "source_event_ids": [event["event_id"]],
                    "air_emission_ref": event["extensions"]["air_emission_ref"]},
                leader_id=self.leader_node_id,
            )
            self._append_event(audit)
            evidence_ids.append(audit["event_id"])
            self.packet_accounting.detection(receiver.node_id, frame, decision["reason"], result)
        if decision["confirmed_identity_anomaly"] or decision["drop"]:
            category = ("RFF_IDENTITY_MISMATCH" if decision["confirmed_identity_anomaly"]
                        else "RFF_IDENTITY_UNVERIFIED")
            self._report_rff(receiver, category,
                {**event["online_features"]["security_state"], **decision}, evidence_ids, result)
        return bool(decision["drop"])

    def _report_rff(self, node: Node, category: str, evidence: dict[str, Any],
                    evidence_ids: list[str], action_result: dict[str, Any] | None = None) -> None:
        now_s = self.context.clock.now_s
        key = (node.node_id, category)
        previous = self._rff_report_times.get(key)
        if (not evidence.get("transition") and previous is not None
                and now_s - previous < self.config.security_summary_window_s - 1e-12):
            return
        self._rff_report_times[key] = now_s
        report = self.reporting.create(
            node.node_id, event_time_s=now_s, detection_time_s=now_s,
            action_time_s=action_result.get("executed_time_s") if action_result else None,
            category=category, evidence=evidence, action_result=action_result,
            severity="MEDIUM", source_event_ids=evidence_ids,
            decision_source="PHYSICAL_RFF",
        )
        node.local_security_cache.append(report.to_dict())

    def _transmit_replay_frame(
        self,
        frame: Frame,
        capture_time_s: float,
        record: AttackRuntimeRecord,
    ) -> None:
        receiver = self.nodes.get(frame.link_receiver_id)
        link = self.topology.links.get(frame.link_id)
        if receiver is None or link is None:
            record.outcome["attack_effective"] = False
            record.outcome["failure_reason"] = "CAPTURED_LINK_UNAVAILABLE"
            return
        attacker_id = record.plan.attacker_node_id if record.plan.attacker_node_id is not None else -1
        attacker = self._external_node(attacker_id)
        record.truth.setdefault("capture_time_s", float(capture_time_s))
        record.truth.setdefault("replay_time_s", self.context.clock.now_s)
        record.truth["replay_mode"] = record.plan.attack_subtype
        record.truth["replay_count"] = int(record.truth.get("replay_count", 0)) + 1
        self._perform_air_transmission(
            frame.clone_for_replay(), attacker, receiver, link, replay_record=record
        )

    def _application_verification(
        self, frame: Frame, opened: CryptoOpenResult
    ) -> ApplicationHmacVerification:
        if opened.auth_result == "PASS" and opened.payload is not None:
            return self.application_auth.verify(frame, opened.payload)
        return ApplicationHmacVerification(
            "UNAVAILABLE",
            "CRYPTO_PAYLOAD_UNAVAILABLE",
            None,
        )

    def _inspect_received_security(
        self,
        node: Node,
        received: ReceivedFrame,
        opened: CryptoOpenResult,
        application_verification: ApplicationHmacVerification,
    ) -> tuple[bool, bool]:
        """Emit one auth decision and execute at most one matching defense."""

        frame = received.frame
        detection, security_state = self.rules[node.node_id].inspect(
            frame,
            opened.payload,
            received.phy,
            node,
            self.context.clock.now_s,
            auth_result=opened.auth_result,
            auth_failure_reason=opened.error_code,
            key_state=opened.key_state,
            application_hmac_result=application_verification.result,
            application_hmac_failure_reason=(
                application_verification.failure_reason
            ),
            application_hmac_key_id=application_verification.key_id,
        )
        application_authenticated = application_verification.passed
        security_state.update(received.rff_security_state)
        fully_authenticated = (
            security_state["auth_result"] == "PASS"
            and application_authenticated
        )
        auth_event = build_event(
            self.context,
            EventType.AUTH_RESULT,
            node,
            message=frame,
            payload=opened.payload if fully_authenticated else None,
            phy=received.phy,
            security_state=security_state,
            availability={
                "payload_available": fully_authenticated,
                "phy_available": True,
                "missing_reason": opened.error_code,
            },
            extensions={
                "crypto_result": {
                    "status": opened.status,
                    "auth_result": opened.auth_result,
                    "key_id": opened.key_id,
                    "key_epoch": opened.key_epoch,
                    "algorithm": opened.algorithm,
                    "key_state": opened.key_state,
                    "error_code": opened.error_code,
                },
                "application_hmac": {
                    "algorithm": self.application_auth.algorithm,
                    "result": application_verification.result,
                    "failure_reason": application_verification.failure_reason,
                    "key_id": application_verification.key_id,
                },
            },
            leader_id=self.leader_node_id,
        )
        if detection is not None and detection.high_certainty:
            # Reserve rule priority before the event is dispatched to external
            # adapters, preventing a low-authority recommendation race.
            self._rule_high_certainty_evidence_ids.add(auth_event["event_id"])
        self._append_event(auth_event)
        self._resume_pending_model_recommendations(auth_event)
        blocked = frame.link_sender_id in node.isolated_peer_ids
        if (
            frame.link_sender_id in node.rate_limited_peer_ids
            and frame.sequence_no % 4 != 0
        ):
            blocked = True
        if detection:
            defense_result = self._handle_detection(
                node, frame, detection, auth_event["event_id"]
            )
            blocked = blocked or (
                defense_result.get("executed", False)
                and defense_result["request"]["action"]
                in {
                    DefenseAction.DROP_PACKET.value,
                    DefenseAction.RATE_LIMIT.value,
                    DefenseAction.DATA_ISOLATION.value,
                }
            )
        return fully_authenticated, blocked

    def _can_parse_application(self, frame: Frame) -> bool:
        return self.config.application_layer_available or frame.packet_type in {
            "SECURITY_REPORT", "SECURITY_SUMMARY", "SKG_CONTROL",
        }

    def _accept_opaque_frame(self, node: Node, frame: Frame) -> None:
        """Forward unknown business bytes without decoding or executing them."""
        node.received_count += 1
        node.opaque_received_count += 1
        if frame.hop_index + 1 >= len(frame.route) - 1:
            node.opaque_delivered_count += 1
            return
        envelope = Message(
            message_id=frame.message_id, origin_node_id=frame.route[0],
            final_dst_node_id=frame.route[-1], claimed_src_id=frame.claimed_src_id,
            claimed_dst_id=frame.claimed_dst_id, packet_type=frame.packet_type,
            payload={}, sequence_no=frame.sequence_no, session_id=frame.session_id,
            key_epoch=frame.key_epoch, created_time_s=frame.created_time_s,
            route=list(frame.route), runtime_attack_id=frame.runtime_attack_id,
        )
        if node.enqueue_forward(TransmissionIntent(
            envelope, frame.hop_index + 1, replay_frame=frame.clone_for_replay(),
        )):
            node.forwarded_count += 1

    def _service_rx(self, node: Node, budget: int) -> None:
        for _ in range(budget):
            if not node.rx_queue:
                return
            received = node.rx_queue.popleft()
            frame = received.frame
            if not self._can_parse_application(frame):
                self._accept_opaque_frame(node, frame)
                continue
            opened = self.crypto.open(frame, node.node_id)
            if received.application_hmac_checked:
                application_verification = ApplicationHmacVerification(
                    str(received.application_hmac_result),
                    received.application_hmac_failure_reason,
                    received.application_hmac_key_id,
                )
            else:
                application_verification = self._application_verification(
                    frame, opened
                )
            fully_authenticated, blocked = self._inspect_received_security(
                node, received, opened, application_verification
            )
            if not fully_authenticated or opened.payload is None or blocked:
                node.drop_count += 1
                self._record_attack_blocked(frame)
                self._mark_report_failed_from_frame(frame)
                continue
            self._record_local_plaintext_protection(
                node, sensitive=frame.sensitive, encrypted=frame.encrypted
            )
            node.received_count += 1
            message = Message(
                message_id=frame.message_id,
                origin_node_id=frame.route[0],
                final_dst_node_id=frame.route[-1],
                claimed_src_id=frame.claimed_src_id,
                claimed_dst_id=frame.claimed_dst_id,
                packet_type=frame.packet_type,
                payload=opened.payload,
                sequence_no=frame.sequence_no,
                session_id=frame.session_id,
                key_epoch=frame.key_epoch,
                created_time_s=frame.created_time_s,
                route=list(frame.route),
                application_size_bytes=frame.application_size_bytes,
                sensitive=frame.sensitive,
                encrypt_requested=frame.encrypted,
                extensions=deepcopy(frame.extensions),
                runtime_attack_id=frame.runtime_attack_id,
                observable_session_id=frame.observable_session_id,
                application_direction=frame.application_direction,
                app_hmac_tag=frame.app_hmac_tag,
                app_hmac_key_id=frame.app_hmac_key_id,
            )
            if frame.hop_index + 1 < len(frame.route) - 1:
                if node.enqueue_forward(
                    TransmissionIntent(message=message, hop_index=frame.hop_index + 1)
                ):
                    node.forwarded_count += 1
                else:
                    self._mark_report_failed_from_frame(frame)
            else:
                if message.sensitive and message.packet_type == "MISSION_COMMAND":
                    if not self._authorize_terminal_event(
                        node.node_id, "SENSITIVE_COMMAND"
                    ):
                        node.drop_count += 1
                        self._record_attack_blocked(frame)
                        self._mark_report_failed_from_frame(frame)
                        continue
                self._metric_totals["delivered"] += 1
                if message.packet_type == "SKG_CONTROL":
                    apply_result = self._apply_security_control(node, message)
                    self._record_attack_delivered(frame, apply_result)
                    continue
                node.delivered_messages.append(message)
                apply_result = self._apply_business_payload(node, message)
                self._record_attack_delivered(frame, apply_result)

    def _apply_security_control(
        self, node: Node, message: Message
    ) -> BusinessApplyResult:
        """Terminate security-control traffic before the business handler."""

        if self.security_coordinator is None:
            return BusinessApplyResult(
                False, False, False, rejection_reason="SKG_COORDINATOR_UNAVAILABLE"
            )
        result = self.security_coordinator.handle_control(node.node_id, message.payload)
        return BusinessApplyResult(
            bool(result.get("accepted")),
            bool(result.get("accepted")),
            bool(result.get("state") == "AVAILABLE"),
            rejection_reason=result.get("failure_reason"),
        )

    def _apply_business_payload(
        self, node: Node, message: Message
    ) -> BusinessApplyResult:
        payload = message.payload
        if message.packet_type in {"SECURITY_REPORT", "SECURITY_SUMMARY"}:
            delivery_id = str(
                message.extensions.get("delivery_id")
                or message.extensions.get("report_id")
                or payload.get("report_id")
                or payload.get("summary_id")
            )
            if node.node_id == self.leader_node_id:
                self.reporting.receive_at_leader(
                    delivery_id, self.context.clock.now_s
                )
            elif node.node_id == self.gcs_node_id:
                self.reporting.receive_at_gcs(
                    delivery_id, self.context.clock.now_s
                )
            return BusinessApplyResult(True, True, True)
        command = payload.get("cmd")
        if command == "FLY_TO" and node.role == NodeRole.FOLLOWER:
            before = (node.flight_state, node.target_position_xyz_m)
            node.flight_state = "FLYING"
            node.target_position_xyz_m = (
                float(payload.get("position_x_m", node.position_xyz_m[0])),
                float(payload.get("position_y_m", node.position_xyz_m[1])),
                float(payload.get("altitude_m", node.position_xyz_m[2])),
            )
            changed = before != (node.flight_state, node.target_position_xyz_m)
            return BusinessApplyResult(True, True, changed, mission_effect=1.0)
        if message.packet_type == "MISSION_COMMAND":
            return BusinessApplyResult(
                False,
                False,
                False,
                rejection_reason="UNSUPPORTED_COMMAND_OR_ROLE",
                mission_effect=0.0,
            )
        if message.packet_type == "TELEMETRY":
            source_id = (
                message.claimed_src_id
                if isinstance(message.claimed_src_id, int)
                else message.origin_node_id
            )
            previous = node.telemetry_by_source.get(source_id)
            node.telemetry_by_source[source_id] = deepcopy(payload)
            return BusinessApplyResult(
                True,
                True,
                previous != payload,
                mission_effect=0.5 if previous != payload else 0.25,
            )
        return BusinessApplyResult(
            True,
            False,
            False,
            rejection_reason="NO_STATEFUL_BUSINESS_HANDLER",
        )

    def _handle_phy_detection(
        self,
        node: Node,
        frame: Frame,
        phy: dict[str, Any],
        evidence_event: dict[str, Any],
    ) -> None:
        detection = self.rules[node.node_id].inspect_phy_sample(phy)
        if detection:
            self._handle_detection(node, frame, detection, evidence_event["event_id"])

    def _handle_detection(
        self,
        node: Node,
        frame: Frame | None,
        detection: Detection,
        evidence_event_id: str,
    ) -> dict[str, Any]:
        if (
            node.role == NodeRole.EXTERNAL
            and not self.config.allow_external_model_observer
        ):
            return {}
        detection = self._adjudicate_detection(node, detection)
        if detection.high_certainty:
            self._rule_high_certainty_evidence_ids.add(evidence_event_id)
        evidence = next(
            (event for event in reversed(self.events) if event["event_id"] == evidence_event_id),
            None,
        )
        rff_security_state = {
            name: value
            for name, value in (
                evidence["online_features"]["security_state"].items() if evidence else ()
            )
            if name.startswith("rff_")
        }
        result = ModelResult(
            schema_version=SCHEMA_VERSION,
            run_id=self.run_id,
            result_id=self.context.ids.next("result"),
            observer_node_id=node.node_id,
            decision_time_s=self.context.clock.now_s,
            model_name="deterministic-rule",
            model_version="1.0.0",
            status="OK",
            predicted_label=detection.label,
            scores={detection.label: detection.confidence},
            confidence=detection.confidence,
            quality=1.0,
            recommended_action=detection.recommended_action.value,
            evidence_event_ids=[evidence_event_id],
            inference_time_ms=0.0,
            error_code=None,
        )
        model_event = build_event(
            self.context,
            EventType.MODEL_RESULT,
            node,
            message=frame,
            security_state=rff_security_state,
            availability={
                "payload_available": False,
                "phy_available": False,
                "missing_reason": "RESULT_EVENT",
            },
            extensions={"model_result": result.to_dict(), "source": "DETERMINISTIC_RULE"},
            leader_id=self.leader_node_id,
        )
        self._append_event(model_event)
        peer_id = frame.link_sender_id if frame else None
        link_id = frame.link_id if frame else None
        request = DefenseRequest(
            request_id=self.context.ids.next("defense-request"),
            action=detection.recommended_action,
            requester_node_id=node.node_id,
            target_node_id=node.node_id,
            target_link_id=link_id,
            peer_id=peer_id,
            session_id=frame.session_id if frame else None,
            requested_time_s=self.context.clock.now_s,
            reason=detection.label,
        )
        defense_result = self.defense.execute(request, node, self.context.clock.now_s)
        result_dict = defense_result.to_dict()
        self.packet_accounting.detection(node.node_id, frame, detection.label, result_dict)
        self._attach_runtime_outcome(result_dict, node.node_id)
        if (
            result_dict["executed"]
            and result_dict["request"]["action"] == DefenseAction.REROUTE.value
        ):
            self._refresh_local_topology(reason="DEFENSE_REROUTE")
        self._record_offline_detection_outcome(
            node, frame, detection, result_dict, evidence_event_id
        )
        defense_event = build_event(
            self.context,
            EventType.DEFENSE_RESULT,
            node,
            message=frame,
            security_state=rff_security_state,
            availability={
                "payload_available": False,
                "phy_available": False,
                "missing_reason": "RESULT_EVENT",
            },
            extensions={
                "defense_result": result_dict,
                "decision_audit": {
                    "source": "RULE",
                    "model_result_id": result.result_id,
                    "decision_reason": (
                        "HIGH_CERTAINTY_RULE"
                        if detection.high_certainty
                        else "DETERMINISTIC_RULE"
                    ),
                },
            },
            leader_id=self.leader_node_id,
        )
        self._append_event(defense_event)
        self._report_security_outcome(
            node,
            result=result,
            decision_source="RULE",
            action_result=result_dict,
            evidence=detection.evidence,
            event_time_s=(
                frame.created_time_s if frame else self.context.clock.now_s
            ),
            source_event_ids=[
                evidence_event_id,
                model_event["event_id"],
                defense_event["event_id"],
            ],
            severity="HIGH" if detection.high_certainty else "MEDIUM",
        )
        return result_dict

    def _report_security_outcome(
        self,
        node: Node,
        *,
        result: ModelResult,
        decision_source: str,
        action_result: dict[str, Any] | None,
        evidence: dict[str, Any] | None,
        event_time_s: float,
        source_event_ids: list[str],
        severity: str | None = None,
    ) -> SecurityReport:
        """Create one correlated local report for rule/model/fusion outcomes."""

        confidence = result.confidence
        actual_severity = severity or (
            "HIGH"
            if isinstance(confidence, (int, float)) and confidence >= 0.95
            else "MEDIUM"
            if isinstance(confidence, (int, float)) and confidence >= 0.8
            else "LOW"
        )
        report = self.reporting.create(
            node.node_id,
            event_time_s=float(event_time_s),
            detection_time_s=float(result.decision_time_s),
            action_time_s=(
                action_result.get("executed_time_s")
                if isinstance(action_result, dict)
                else None
            ),
            category=result.predicted_label or "MODEL_RECOMMENDATION",
            evidence=deepcopy(evidence or {}),
            action_result=deepcopy(action_result),
            severity=actual_severity,
            source_event_ids=list(dict.fromkeys(source_event_ids)),
            decision_source=decision_source,
            correlation_id=result.result_id,
            model_result_id=result.result_id,
            model_name=result.model_name,
            model_version=result.model_version,
            predicted_label=result.predicted_label,
            confidence=result.confidence,
            quality=result.quality,
            decision_time_s=result.decision_time_s,
        )
        if not any(
            item.get("report_id") == report.report_id
            for item in node.local_security_cache
        ):
            node.local_security_cache.append(report.to_dict())
        return report

    def inject_redundancy_fault(self, replica_id: str, *, mode: str) -> None:
        known = {replica.replica_id for replica in self.security_redundancy.replicas}
        if replica_id not in known:
            raise KeyError(f"unknown replica: {replica_id}")
        normalized = str(mode).upper()
        if normalized not in {"INCONSISTENT_ONCE", "FAIL_ONCE"}:
            raise ValueError(f"unsupported redundancy fault mode: {mode}")
        self._redundancy_fault_modes[replica_id] = normalized

    def _run_security_replica(
        self, replica_id: str, value: dict[str, Any]
    ) -> dict[str, Any]:
        mode = self._redundancy_fault_modes.pop(replica_id, None)
        if mode == "FAIL_ONCE":
            raise RuntimeError("INJECTED_LOGICAL_REPLICA_FAILURE")
        output = deepcopy(value)
        if mode == "INCONSISTENT_ONCE":
            output["label"] = "NORMAL"
            output["recommended_action"] = DefenseAction.NO_CHANGE.value
        return output

    def _emit_redundancy_event(
        self, node: Node, payload: dict[str, Any]
    ) -> None:
        self._append_event(
            build_event(
                self.context,
                EventType.NODE_STATE,
                node,
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": "LOGICAL_REDUNDANCY_STATUS",
                },
                extensions={"redundancy_event": deepcopy(payload)},
                leader_id=self.leader_node_id,
            )
        )

    def _adjudicate_detection(
        self, node: Node, detection: Detection
    ) -> Detection:
        value = {
            "label": detection.label,
            "confidence": detection.confidence,
            "evidence": deepcopy(detection.evidence),
            "recommended_action": detection.recommended_action.value,
            "high_certainty": detection.high_certainty,
        }
        execution = self.security_redundancy.execute(value)
        self._emit_redundancy_event(
            node,
            {
                "event": "SECURITY_DECISION_ADJUDICATED",
                **deepcopy(execution),
            },
        )
        winning = execution["adjudication"].get("output") or value
        agreeing = set(execution["adjudication"].get("agreeing_replicas", []))
        for replica, result in zip(
            self.security_redundancy.replicas, execution["replica_results"]
        ):
            inconsistent = result["status"] == "OK" and replica.replica_id not in agreeing
            failed = result["status"] == "FAILED"
            if not (inconsistent or failed):
                continue
            if inconsistent:
                replica.healthy = False
                replica.failure_reason = "INCONSISTENT_RESULT"
            self._emit_redundancy_event(
                node,
                {
                    "event": "REPLICA_DEGRADED",
                    "replica_id": replica.replica_id,
                    "failure_reason": replica.failure_reason,
                },
            )
            self._emit_redundancy_event(node, SwitchRecovery.recover(replica))
        return Detection(
            label=str(winning["label"]),
            confidence=float(winning["confidence"]),
            evidence=deepcopy(winning["evidence"]),
            recommended_action=DefenseAction(winning["recommended_action"]),
            high_certainty=bool(winning.get("high_certainty", False)),
        )

    def _record_offline_detection_outcome(
        self,
        node: Node,
        frame: Frame | None,
        detection: Detection,
        defense_result: dict[str, Any],
        evidence_event_id: str,
    ) -> None:
        """Join decisions to truth only in the isolated label store."""
        if detection.label == "AUTH_FAILURE" and frame is not None:
            bound = self._attack_record_for_frame(frame)
            records = (
                [bound]
                if bound is not None
                and bound.plan.attack_family in {"SPOOFING", "FDI"}
                else []
            )
        else:
            records = self.attack_scheduler.active(
                self.context.clock.now_s, detection.label
            )
        for record in records:
            plan = record.plan
            bound_application_failure = (
                detection.label == "AUTH_FAILURE"
                and frame is not None
                and record is self._attack_record_for_frame(frame)
            )
            if (
                not bound_application_failure
                and plan.target_node_ids
                and node.node_id not in plan.target_node_ids
            ):
                if frame is None or frame.link_receiver_id not in plan.target_node_ids:
                    continue
            if plan.target_link_ids and (
                frame is None or frame.link_id not in plan.target_link_ids
            ):
                continue
            record.outcome["detected"] = True
            if detection.label == "AUTH_FAILURE":
                record.outcome["application_hmac_rejected"] = True
                record.outcome["application_hmac_failure_reason"] = (
                    detection.evidence.get("reason")
                )
            elif detection.label == "DOS":
                record.outcome["receiver_total_rate_exceeded"] = True
                record.outcome["observed_packet_rate_pps"] = (
                    detection.evidence.get("packet_rate_pps")
                )
                record.outcome["observed_total_packet_count"] = (
                    detection.evidence.get("total_packet_count")
                )
            elif detection.label == "REPLAY":
                record.outcome["application_hmac_passed_before_replay_check"] = True
                record.outcome["replay_rejection_reason"] = (
                    detection.evidence.get("replay_check_result")
                )
            record.outcome.setdefault("detection_time_s", self.context.clock.now_s)
            evidence_ids = record.truth.setdefault(
                "relevant_evidence_event_ids", []
            )
            if evidence_event_id not in evidence_ids:
                evidence_ids.append(evidence_event_id)
            record.outcome["alarm_count"] = int(
                record.outcome.get("alarm_count", 0)
            ) + 1
            if defense_result["executed"]:
                record.outcome.setdefault(
                    "action_time_s", defense_result.get("executed_time_s")
                )
                record.outcome["defense_action"] = defense_result["request"][
                    "action"
                ]
                record.outcome["action_executed"] = True
                record.outcome["defense_executed"] = True
                record.outcome["time_to_action_s"] = max(
                    0.0, self.context.clock.now_s - plan.impact_start_s
                )

    def _attack_record_for_message(
        self, message_id: str
    ) -> AttackRuntimeRecord | None:
        attack_id = self._message_attack_ids.get(message_id)
        return self.attack_scheduler.records.get(attack_id or "")

    def _bind_attack_message(
        self, record: AttackRuntimeRecord, message_id: str
    ) -> None:
        self._message_attack_ids[message_id] = record.plan.attack_id or ""
        self._record_attack_message_generated(record, message_id)
        queued = record.truth.setdefault("queued_message_ids", [])
        if message_id not in queued:
            queued.append(message_id)

    @staticmethod
    def _record_attack_message_generated(
        record: AttackRuntimeRecord, message_id: str
    ) -> None:
        generated = record.truth.setdefault("generated_message_ids", [])
        if message_id not in generated:
            generated.append(message_id)

    def _mark_attack_message_observable(
        self, frame: Frame, evidence_event_id: str
    ) -> None:
        """Promote a queued attack message only after a real observable event."""

        record = self._attack_record_for_frame(frame)
        if record is None:
            return
        affected = record.truth.setdefault("affected_message_ids", [])
        if frame.message_id not in affected:
            affected.append(frame.message_id)
        evidence = record.truth.setdefault("relevant_evidence_event_ids", [])
        if evidence_event_id not in evidence:
            evidence.append(evidence_event_id)

    def _refresh_attack_backlog_truth(self) -> None:
        queued_ids = {
            intent.message.message_id
            for node in self.nodes.values()
            for queue in (node.tx_queue, node.forward_queue)
            for intent in queue
        }
        for record in self.attack_scheduler.records.values():
            bound = set(record.truth.get("queued_message_ids", []))
            backlog = sorted(bound & queued_ids)
            record.truth["backlogged_message_ids"] = backlog
            record.outcome["queued_backlog_count"] = len(backlog)
            if backlog:
                record.outcome["queue_pressure_observed"] = True
            AttackOutcomePolicy.refresh(record)

    def _attack_record_for_frame(self, frame: Frame) -> AttackRuntimeRecord | None:
        attack_id = frame.runtime_attack_id or self._message_attack_ids.get(
            frame.message_id
        )
        return self.attack_scheduler.records.get(attack_id or "")

    def _contributing_attack_records(
        self, frame: Frame, link_id: str, channel_id: str
    ) -> list[AttackRuntimeRecord]:
        records: list[AttackRuntimeRecord] = []
        primary = self._attack_record_for_frame(frame)
        if primary is not None:
            records.append(primary)
        return records

    @staticmethod
    def _record_compound_attribution(
        records: list[AttackRuntimeRecord],
        frame: Frame,
        link_id: str,
        event_ids: list[str],
    ) -> None:
        attack_ids = sorted(
            str(record.plan.attack_id)
            for record in records
            if record.plan.attack_id is not None
        )
        if not attack_ids:
            return
        for record in records:
            current = record.truth.setdefault("contributing_attack_ids", [])
            for attack_id in attack_ids:
                if attack_id not in current:
                    current.append(attack_id)
            affected = record.truth.setdefault("affected_message_ids", [])
            if frame.message_id not in affected:
                affected.append(frame.message_id)
            evidence = record.truth.setdefault("relevant_evidence_event_ids", [])
            for event_id in event_ids:
                if event_id not in evidence:
                    evidence.append(event_id)
            attribution = record.truth.setdefault("compound_attribution", [])
            row = {
                "message_id": frame.message_id,
                "link_id": link_id,
                "contributing_attack_ids": attack_ids,
                "evidence_event_ids": list(event_ids),
            }
            if row not in attribution:
                attribution.append(row)

    def _record_attack_air_outcome(
        self, frame: Frame, decode_success: bool
    ) -> None:
        record = self._attack_record_for_frame(frame)
        if record is None:
            return
        record.outcome["affected_transmissions"] = int(
            record.outcome.get("affected_transmissions", 0)
        ) + 1
        is_target_receiver = (
            not record.plan.target_node_ids
            or frame.link_receiver_id in record.plan.target_node_ids
        )
        if decode_success:
            record.outcome["decoded_transmissions"] = int(
                record.outcome.get("decoded_transmissions", 0)
            ) + 1
            if is_target_receiver:
                AttackOutcomePolicy.reached_target(record)
        else:
            record.outcome["phy_decode_failures"] = int(
                record.outcome.get("phy_decode_failures", 0)
            ) + 1
        AttackOutcomePolicy.refresh(record)

    def _record_attack_blocked(self, frame: Frame) -> None:
        record = self._attack_record_for_frame(frame)
        if record is None:
            return
        record.outcome["malicious_traffic_blocked"] = int(
            record.outcome.get("malicious_traffic_blocked", 0)
        ) + 1
        AttackOutcomePolicy.refresh(record)

    def _record_application_hmac_rejection(
        self,
        frame: Frame,
        verification: ApplicationHmacVerification,
    ) -> None:
        """Record secret-free offline rejection evidence for a bound frame.

        This does not label the online failure as Spoofing, FDI, or DoS.  It
        only joins a generic HMAC result to an already-known offline episode.
        """

        record = self._attack_record_for_frame(frame)
        if record is None:
            return
        record.outcome["application_hmac_rejected"] = True
        record.outcome["application_hmac_rejected_count"] = int(
            record.outcome.get("application_hmac_rejected_count", 0)
        ) + 1
        record.outcome["application_hmac_failure_reason"] = (
            verification.failure_reason
        )

    def _record_attack_delivered(
        self, frame: Frame, apply_result: BusinessApplyResult
    ) -> None:
        record = self._attack_record_for_frame(frame)
        if record is None:
            return
        record.outcome["malicious_traffic_delivered"] = int(
            record.outcome.get("malicious_traffic_delivered", 0)
        ) + 1
        if (
            record.plan.attack_family in {"FDI", "REPLAY", "SPOOFING"}
            and apply_result.executed
        ):
            AttackOutcomePolicy.malicious_content_executed(record)
        else:
            AttackOutcomePolicy.reached_target(record)
        record.outcome["business_apply_result"] = {
            "accepted": apply_result.accepted,
            "executed": apply_result.executed,
            "state_changed": apply_result.state_changed,
            "rejection_reason": apply_result.rejection_reason,
        }
        mission = MissionImpactEvaluator.from_business_apply(
            packet_type=frame.packet_type,
            executed=apply_result.executed,
            state_changed=apply_result.state_changed,
            mission_effect=apply_result.mission_effect,
        )
        record.outcome["mission_impact"] = mission.score
        record.outcome["mission_impact_available"] = mission.available
        record.outcome["mission_impact_missing_reason"] = mission.missing_reason
        record.outcome["mission_impact_components"] = mission.components
        action_time = record.outcome.get("action_time_s")
        if isinstance(action_time, (int, float)) and self.context.clock.now_s >= float(
            action_time
        ):
            record.outcome["malicious_traffic_delivered_after_action"] = int(
                record.outcome.get("malicious_traffic_delivered_after_action", 0)
            ) + 1
        AttackOutcomePolicy.refresh(record)

    def _attach_runtime_outcome(
        self, result: dict[str, Any], observer_node_id: int
    ) -> None:
        snapshot = self.local_traffic_snapshot(
            observer_node_id, self.config.traffic_statistics_window_s
        )
        outcome = result["outcome"]
        outcome["throughput_mbps"] = snapshot["throughput_mbps"]
        outcome["latency_ms"] = snapshot["latency_ms"]
        outcome["communication_overhead"] = outcome.get(
            "communication_overhead_bytes"
        )
        outcome["compute_overhead_ms"] = None
        availability = outcome.setdefault("availability", {})
        availability.update(
            {
                "throughput_mbps": True,
                "latency_ms": snapshot["latency_ms"] is not None,
                "communication_overhead": False,
                "communication_overhead_bytes": False,
                "compute_overhead_ms": False,
                "missing_reason": (
                    None
                    if snapshot["latency_ms"] is not None
                    else "NO_LOCAL_SUCCESSFUL_PACKET_IN_WINDOW"
                ),
            }
        )

    def _emit_periodic_phy_samples(self) -> None:
        for link in sorted(self.topology.links.values(), key=lambda item: item.link_id):
            if not link.active or link.src_id not in self.nodes or link.dst_id not in self.nodes:
                continue
            sender = self.nodes[link.src_id]
            receiver = self.nodes[link.dst_id]
            normal = self.normal_disturbances.link_modifiers(
                link.link_id, self.context.clock.now_s
            )
            observation = self.phy.passive_sample(
                link,
                sender,
                receiver,
                self.context.clock.now_s,
                interference_power_dbm=None,
                natural_attenuation_db=normal["attenuation_db"],
                natural_loss_probability=normal["loss_probability"],
                natural_busy_ratio_addition=normal["busy_ratio_addition"],
            )
            event = build_event(
                self.context,
                EventType.PHY_SAMPLE,
                receiver,
                phy=observation,
                availability={
                    "payload_available": False,
                    "phy_available": True,
                    "missing_reason": "NO_PACKET_FOR_PERIODIC_SAMPLE",
                },
                extensions={"sample_link_id": link.link_id},
                leader_id=self.leader_node_id,
            )
            self._append_event(event)
            detection = self.rules[receiver.node_id].inspect_phy_sample(observation)
            if detection:
                synthetic = Frame(
                    message_id="",
                    claimed_src_id=None,
                    claimed_dst_id=receiver.node_id,
                    packet_type="PHY_SAMPLE",
                    sequence_no=-1,
                    session_id=f"phy-{link.link_id}",
                    key_epoch=0,
                    hop_index=0,
                    link_id=link.link_id,
                    link_sender_id=link.src_id,
                    link_receiver_id=link.dst_id,
                    protected_payload={},
                    encrypted=False,
                    auth_tag=None,
                    nonce_b64=None,
                    sensitive=False,
                    created_time_s=self.context.clock.now_s,
                    route=[link.src_id, link.dst_id],
                    observable_session_id=self.observable_session_id(
                        f"phy-{link.link_id}"
                    ),
                    observable_link_id=self.observable_link_id(link.link_id),
                )
                self._handle_detection(receiver, synthetic, detection, event["event_id"])

    def _emit_queue_samples(self) -> None:
        for node in self.nodes.values():
            self._append_event(
                build_event(
                    self.context,
                    EventType.QUEUE_SAMPLE,
                    node,
                    traffic={
                        "packet_rate_pps": None,
                        "rx_queue_length": len(node.rx_queue),
                        "forward_queue_length": len(node.forward_queue),
                        "drop_count": node.drop_count,
                    },
                    availability={
                        "payload_available": False,
                        "phy_available": False,
                        "missing_reason": "QUEUE_SAMPLE",
                    },
                    leader_id=self.leader_node_id,
                ),
            )

    def _append_event(self, event: dict[str, Any]) -> None:
        sanitized = self._sanitize_online_identifiers(event)
        event.clear()
        event.update(sanitized)
        self.traffic_statistics.enrich(event)
        self.events.append(event)
        self.packet_accounting.observe_event(event)
        if event.get("event_type") == EventType.MODEL_RESULT.value:
            self._apply_model_result_side_effects(event)
        for dispatched in self.event_dispatcher.dispatch(event):
            result = dispatched.result
            observer = self.nodes.get(result.observer_node_id)
            if observer is None:
                observer = self.nodes[event["observer_node_id"]]
            model_event = build_event(
                    self.context,
                    EventType.MODEL_RESULT,
                    observer,
                    availability={
                        "payload_available": False,
                        "phy_available": False,
                        "missing_reason": "MODEL_RESULT_EVENT",
                    },
                    extensions={
                        "model_result": result.to_dict(),
                        "source_adapter": dispatched.adapter_name,
                    },
                    leader_id=self.leader_node_id,
                )
            self._append_event(model_event)

    def _apply_model_result_side_effects(self, event: dict[str, Any]) -> None:
        raw = event.get("extensions", {}).get("model_result")
        if not isinstance(raw, dict):
            return
        try:
            result = ModelResult(**raw)
        except (TypeError, ValueError):
            return
        if result.result_id in self._handled_model_result_ids:
            return
        self._handled_model_result_ids.add(result.result_id)
        observer = self.nodes.get(result.observer_node_id)
        if observer is None:
            return
        model_key = str(event.get("extensions", {}).get("source_adapter", "")).lower()
        model_name = result.model_name.lower()
        if model_key == "rff" or model_name.startswith("rff"):
            observer.rff_identity_result = (
                result.predicted_label
                if result.status == "OK"
                else str(result.status).upper()
            )
            observer.rff_identity_confidence = result.confidence
            observer.rff_quality = result.quality
            observer.rff_last_update_s = self.context.clock.now_s
            if result.status == "OK" and result.predicted_label not in {
                None,
                "PASS",
                "MATCH",
                "KNOWN",
                "AUTHORIZED",
                "NORMAL",
            }:
                observer.rff_anomaly_count += 1
            security = event["online_features"]["security_state"]
            security["rff_identity_result"] = observer.rff_identity_result
            security["rff_identity_confidence"] = observer.rff_identity_confidence
            security["rff_quality"] = observer.rff_quality
            security["rff_last_update_s"] = observer.rff_last_update_s

        if model_name == "deterministic-rule" or self._model_fusion_in_progress:
            return
        evidence = next(
            (
                candidate
                for candidate in reversed(self.events)
                if candidate.get("event_id") in set(result.evidence_event_ids)
            ),
            None,
        )
        if result.recommended_action:
            self._process_model_recommendation(result, evidence, observer)
        elif (
            result.status == "OK"
            and result.predicted_label
            and result.predicted_label.upper() != "NORMAL"
        ):
            self._report_security_outcome(
                observer,
                result=result,
                decision_source="MODEL",
                action_result=None,
                evidence={"model_detection": True},
                event_time_s=(
                    float(evidence.get("sim_time_s"))
                    if evidence is not None
                    else result.decision_time_s
                ),
                source_event_ids=[
                    *result.evidence_event_ids,
                    str(event["event_id"]),
                ],
            )

    def process_action_recommendation(
        self,
        *,
        source: str,
        observer_node_id: int,
        recommended_action: str,
        evidence_event_ids: list[str] | None = None,
        confidence: float = 1.0,
        quality: float = 1.0,
        predicted_label: str | None = None,
        target_hint: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """The sole B-policy entry for deployed models and RL training agents.

        Target hints are retained for audit only.  The resolver derives the
        executable target from observer-local authenticated/physical evidence,
        so an RL caller never gains the direct-executor privilege.
        """

        if observer_node_id not in self.nodes:
            raise KeyError(f"unknown node: {observer_node_id}")
        observer = self.nodes[observer_node_id]
        ids = list(evidence_event_ids or [])
        evidence = next(
            (
                event
                for event in reversed(self.events)
                if event.get("event_id") in set(ids)
                and event.get("observer_node_id") == observer_node_id
            ),
            None,
        )
        result = ModelResult(
            schema_version=SCHEMA_VERSION,
            run_id=self.run_id,
            result_id=self.context.ids.next("result"),
            observer_node_id=observer_node_id,
            decision_time_s=self.context.clock.now_s,
            model_name=str(source).lower(),
            model_version="b-policy-recommendation-v1",
            status="OK",
            predicted_label=predicted_label,
            scores=(
                {predicted_label: float(confidence)} if predicted_label else None
            ),
            confidence=float(confidence),
            quality=float(quality),
            recommended_action=str(recommended_action).upper(),
            evidence_event_ids=ids,
            inference_time_ms=None,
            error_code=None,
        )
        # Record exactly one recommendation event, while suppressing the
        # automatic side-effect hook so the call below remains the one policy
        # evaluation for this recommendation.
        self._handled_model_result_ids.add(result.result_id)
        self._append_event(
            build_event(
                self.context,
                EventType.MODEL_RESULT,
                observer,
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": "ACTION_RECOMMENDATION",
                },
                extensions={
                    "model_result": result.to_dict(),
                    "source_adapter": "dueling_q",
                    "recommendation_context": {
                        "source": str(source).upper(),
                        "target_hint": deepcopy(target_hint or {}),
                    },
                },
                leader_id=self.leader_node_id,
            )
        )
        return self._process_model_recommendation(
            result,
            evidence,
            observer,
            recommendation_source=str(source).upper(),
            target_hint=target_hint,
        )

    def select_recommendation_evidence(
        self, observer_node_id: int, recommended_action: str
    ) -> dict[str, Any] | None:
        """Select causal local evidence for an RL recommendation.

        Deployment adapters naturally attach the event that triggered their
        recommendation.  An RL action arrives at a decision epoch, so B selects
        the latest event of the same evidence class.  Identity-sensitive
        actions never borrow an unrelated PHY/queue snapshot whose auth state
        is unknown.
        """

        recommendation = str(recommended_action).upper()
        identity_actions = {
            "RECOMMEND_RATE_LIMIT",
            "RECOMMEND_DATA_ISOLATION",
            "RECOMMEND_REAUTH_REKEY",
            "RECOMMEND_REAUTH_REKEY_REQUEST",
        }
        link_actions = {"RECOMMEND_CHANNEL_SWITCH", "RECOMMEND_REROUTE"}
        local = [
            event
            for event in reversed(self.events)
            if event.get("observer_node_id") == observer_node_id
            and event.get("event_type") not in {"MODEL_RESULT", "DEFENSE_RESULT"}
        ]
        if recommendation in identity_actions:
            return next(
                (
                    event
                    for event in local
                    if event.get("event_type") == "AUTH_RESULT"
                    and event.get("online_features", {})
                    .get("packet", {})
                    .get("link_id")
                    is not None
                ),
                None,
            )
        if recommendation in link_actions:
            return next(
                (
                    event
                    for event in local
                    if event.get("event_type")
                    in {"PHY_SAMPLE", "RX_SUCCESS", "RX_FAILURE"}
                    and (
                        event.get("direct_link_id") is not None
                        or event.get("online_features", {})
                        .get("packet", {})
                        .get("link_id")
                        is not None
                        or event.get("extensions", {}).get("sample_link_id")
                        is not None
                    )
                ),
                None,
            )
        return local[0] if local else None

    def _process_model_recommendation(
        self,
        result: ModelResult,
        evidence: dict[str, Any] | None,
        observer: Node,
        *,
        allow_defer: bool = True,
        rule_priority_override: bool = False,
        recommendation_source: str = "MODEL",
        target_hint: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rule_priority = rule_priority_override or any(
            evidence_id in self._rule_high_certainty_evidence_ids
            for evidence_id in result.evidence_event_ids
        )
        fusion = self.decision_fusion.decide(
            result, rule_high_certainty=rule_priority
        )
        if evidence is None:
            fusion = FusionDecision(False, fusion.action, "MODEL_EVIDENCE_NOT_FOUND")
        elif evidence.get("observer_node_id") != result.observer_node_id:
            fusion = FusionDecision(
                False, fusion.action, "MODEL_OBSERVER_SCOPE_MISMATCH"
            )

        resolution = None
        if evidence is not None and fusion.action is not None:
            resolution = self.defense_target_resolver.resolve(
                fusion.action, evidence, observer
            )
            if fusion.allowed and not resolution.allowed:
                fusion = FusionDecision(False, fusion.action, resolution.reason)
                if resolution.reason == "AUTHENTICATION_PENDING" and allow_defer:
                    self._pending_model_recommendations[result.result_id] = (
                        result,
                        evidence,
                    )

        defense_dict: dict[str, Any]
        if fusion.allowed and fusion.action is not None and resolution is not None:
            request = DefenseRequest(
                request_id=self.context.ids.next("defense-request"),
                action=fusion.action,
                requester_node_id=observer.node_id,
                target_node_id=resolution.target_node_id,
                target_link_id=resolution.target_link_id,
                peer_id=resolution.peer_id,
                session_id=resolution.session_id,
                requested_time_s=result.decision_time_s,
                reason=result.predicted_label,
            )
            defense_dict = self.defense.execute(
                request, observer, self.context.clock.now_s
            ).to_dict()
            self._attach_runtime_outcome(defense_dict, observer.node_id)
            if (
                defense_dict["executed"]
                and defense_dict["request"]["action"] == DefenseAction.REROUTE.value
            ):
                self._refresh_local_topology(reason="MODEL_FUSION_REROUTE")
        else:
            defense_dict = {
                "request": {
                    "request_id": self.context.ids.next("defense-request"),
                    "action": fusion.action.value if fusion.action else None,
                    "requester_node_id": observer.node_id,
                    "reason": result.predicted_label,
                    "session_id": resolution.session_id if resolution else None,
                },
                "permission": (
                    "MODEL_POLICY_DEFERRED"
                    if fusion.reason == "AUTHENTICATION_PENDING"
                    else "MODEL_POLICY_DENIED"
                ),
                "target": {
                    "node_id": resolution.target_node_id if resolution else observer.node_id,
                    "link_id": resolution.target_link_id if resolution else None,
                    # Never copy an untrusted logical claim into an action
                    # target, even in a denied audit record.
                    "peer_id": resolution.peer_id if resolution else None,
                },
                "requested_time_s": result.decision_time_s,
                "executed_time_s": None,
                "allowed": False,
                "executed": False,
                "failure_reason": fusion.reason,
                "outcome": {
                    "communication_overhead_bytes": None,
                    "compute_overhead_ms": None,
                    "availability": {
                        "communication_overhead_bytes": False,
                        "compute_overhead_ms": False,
                        "missing_reason": "ACTION_NOT_EXECUTED",
                    },
                },
            }
        defense_dict["decision_reason"] = fusion.reason
        defense_dict.setdefault("outcome", {})["decision_reason"] = fusion.reason
        self._model_fusion_in_progress = True
        defense_event = build_event(
            self.context,
            EventType.DEFENSE_RESULT,
            observer,
            availability={
                "payload_available": False,
                "phy_available": False,
                "missing_reason": "MODEL_FUSION_RESULT",
            },
            extensions={
                "defense_result": defense_dict,
                "decision_audit": {
                    "source": "FUSION",
                    "recommendation_source": recommendation_source,
                    "model_result_id": result.result_id,
                    "decision_reason": fusion.reason,
                    "untrusted_target_hint": deepcopy(target_hint or {}),
                    "target_resolution": (
                        {
                            "reason": resolution.reason,
                            "authentication_state": resolution.authentication_state,
                            "logical_claimed_source": resolution.logical_claimed_source,
                            "immediate_hop_peer": resolution.immediate_hop_peer,
                        }
                        if resolution is not None
                        else None
                    ),
                },
            },
            leader_id=self.leader_node_id,
        )
        try:
            self._append_event(defense_event)
        finally:
            self._model_fusion_in_progress = False
        # A pre-auth recommendation is reported only after its deferred policy
        # evaluation is final. Other denied/executed decisions are auditable.
        if not (fusion.reason == "AUTHENTICATION_PENDING" and allow_defer):
            model_event = next(
                (
                    candidate
                    for candidate in reversed(self.events)
                    if candidate.get("event_type") == "MODEL_RESULT"
                    and candidate.get("extensions", {})
                    .get("model_result", {})
                    .get("result_id")
                    == result.result_id
                ),
                None,
            )
            self._report_security_outcome(
                observer,
                result=result,
                decision_source=(
                    "MODEL" if recommendation_source == "MODEL" else recommendation_source
                ),
                action_result=defense_dict,
                evidence={
                    "decision_reason": fusion.reason,
                    "evidence_event_ids": list(result.evidence_event_ids),
                },
                event_time_s=(
                    float(evidence.get("sim_time_s"))
                    if evidence is not None
                    else result.decision_time_s
                ),
                source_event_ids=[
                    *result.evidence_event_ids,
                    *(
                        [str(model_event["event_id"])]
                        if model_event is not None
                        else []
                    ),
                    str(defense_event["event_id"]),
                ],
            )
        return self._sanitize_online_identifiers(defense_dict)

    def _resume_pending_model_recommendations(
        self, auth_event: dict[str, Any]
    ) -> None:
        """Re-evaluate pre-auth recommendations against the auth snapshot."""

        message_id = auth_event.get("message_id")
        if not isinstance(message_id, str):
            return
        pending = [
            (result_id, value)
            for result_id, value in self._pending_model_recommendations.items()
            if value[1].get("message_id") == message_id
            and value[0].observer_node_id == auth_event.get("observer_node_id")
        ]
        for result_id, (result, _original_evidence) in pending:
            self._pending_model_recommendations.pop(result_id, None)
            observer = self.nodes.get(result.observer_node_id)
            if observer is None:
                continue
            self._process_model_recommendation(
                result,
                auth_event,
                observer,
                allow_defer=False,
                rule_priority_override=(
                    auth_event.get("event_id")
                    in self._rule_high_certainty_evidence_ids
                ),
            )

    def run_record(self) -> dict[str, Any]:
        """Return complete semantic provenance for the actual scheduled run."""

        self._refresh_attack_backlog_truth()
        attacks = [
            asdict(record.plan) for record in self.attack_scheduler.records.values()
        ]
        requested_attacks = [
            deepcopy(record.requested_plan)
            for record in self.attack_scheduler.records.values()
        ]
        normal = [
            asdict(record.plan)
            for record in self.normal_disturbances.records.values()
        ]
        record = self.context.run_record(
            attack_plans=attacks,
            normal_disturbance_plans=normal,
        )
        record["rff_simulation"] = {
            "enabled": self.config.rff_enabled,
            "policy_mode": self.config.rff_policy_mode,
            "feature_schema": RFF_FEATURE_SCHEMA,
            "provider": "SIMULATED_FEATURE_TEMPLATE",
            "identification_provider": (
                "NEAREST_TEMPLATE" if self._rff_template_identifier_enabled
                else "EXTERNAL_MODEL_ADAPTER"
            ),
            "calibration_status": "UNCALIBRATED_BASELINE",
            "enrollment_samples": self.config.rff_enrollment_samples,
            "quality_threshold": self.config.rff_quality_threshold,
            "distance_threshold": self.config.rff_distance_threshold,
            "min_identity_margin": self.config.rff_min_identity_margin,
            "application_layer_available": self.config.application_layer_available,
            "queue_pressure_ratio": self.config.rff_queue_pressure_ratio,
            "strict_hold_s": self.config.rff_strict_hold_s,
            "strict_on_rate_alarm": self.config.rff_strict_on_rate_alarm,
        }
        all_roles = {
            str(node_id): node.role.value for node_id, node in sorted(self.nodes.items())
        }
        planned_external_ids = {
            int(record.plan.attacker_node_id)
            for record in self.attack_scheduler.records.values()
            if isinstance(record.plan.attacker_node_id, int)
            and record.plan.attacker_node_id not in self.roles
        }
        for node_id in planned_external_ids:
            all_roles[str(node_id)] = NodeRole.EXTERNAL.value
        record["node_roles"] = dict(
            sorted(all_roles.items(), key=lambda item: int(item[0]))
        )
        record["legitimate_node_count"] = self.config.node_count
        record["legitimate_node_roles"] = {
            str(node_id): role.value
            for node_id, role in sorted(self.roles.items())
        }
        record["external_participants"] = [
            {"node_id": int(node_id), "role": NodeRole.EXTERNAL.value}
            for node_id, role in record["node_roles"].items()
            if role == NodeRole.EXTERNAL.value
        ]
        record["requested_attack_plan"] = requested_attacks
        record["dataset_maturity"] = self.config.dataset_maturity
        record["probe_profile"] = self.probes.profile
        record["application_hmac"] = self.application_auth.provenance()
        record["detection_configuration"] = {
            "application_hmac": {"enabled": True, "scope": "BASE_SECURITY"},
            "replay_protection": {"enabled": True, "scope": "BASE_SECURITY"},
            "flooding": {
                "enabled": self.config.flooding_detection_enabled,
                "scope": "RECEIVER_TOTAL_DECODED_ARRIVALS",
                "window_s": self.config.traffic_statistics_window_s,
                "threshold_pps": self.config.flooding_packet_rate_threshold_pps,
            },
            "direct_eaves_detection": {"enabled": False, "applicable": False},
        }
        record["security_providers"] = {
            "key_provider": self._provider_provenance(self.key_provider),
            "crypto_provider": self._provider_provenance(self.crypto),
            "terminal_credential_provider": {
                **self._provider_provenance(self.terminal_authorizer),
                "status": (
                    "SIMULATED_PROFILE_BINDING"
                    if not self._terminal_authorizer_injected
                    else str(
                        getattr(
                            self.terminal_authorizer,
                            "implementation_status",
                            "EXTERNAL",
                        )
                    )
                ),
            },
        }
        provider_statuses = [
            str(item["status"]).upper()
            for item in record["security_providers"].values()
        ]
        record["security_provider_maturity"] = (
            "FORMAL"
            if provider_statuses
            and all("FORMAL" in status for status in provider_statuses)
            else "TEST"
        )
        record["calibration_maturity"] = (
            self._calibration_profile.profile_maturity
            if self._calibration_profile is not None
            else "UNCALIBRATED"
        )
        current_models = self._collect_model_provenance()
        initial_models = getattr(self, "_model_provenance_at_start", {})
        for slot, model in current_models.items():
            started = initial_models.get(slot, model)
            model["status_at_start"] = started.get(
                "status_at_start", started.get("status_at_export")
            )
            model["error_code_at_start"] = started.get(
                "error_code_at_start", started.get("error_code")
            )
        record["model_assets"] = current_models

        readiness_blockers: list[str] = []
        provider_blockers = {
            "key_provider": "A_FORMAL_KEY_PROVIDER_MISSING",
            "crypto_provider": "A_FORMAL_CRYPTO_PROVIDER_MISSING",
            "terminal_credential_provider": "A_FORMAL_TERMINAL_CREDENTIAL_MISSING",
        }
        for provider_name, blocker in provider_blockers.items():
            status = str(
                record["security_providers"][provider_name]["status"]
            ).upper()
            if "FORMAL" not in status:
                readiness_blockers.append(blocker)
        if record["calibration_maturity"] != "APPROVED":
            readiness_blockers.append("REAL_CALIBRATION_NOT_APPROVED")
        if self.probes.profile != V8_DEFAULT_PROBE_PROFILE:
            readiness_blockers.append("PERSON_A_COMPAT_PROBE_TEST_ONLY")

        model_components: dict[str, str] = {}
        for slot in ("bilstm", "dueling_q", "rff"):
            model = current_models[slot]
            provider_status = str(
                model.get("provider_implementation_status") or ""
            ).upper()
            asset_maturity = str(model.get("asset_maturity") or "").upper()
            formal = asset_maturity == "FORMAL" or provider_status == "FORMAL"
            ready = bool(
                model.get("configured")
                and model.get("status_at_export") == "OK"
                and model.get("model_version")
                and formal
            )
            model_components[slot] = "READY" if ready else "BLOCKED_EXTERNAL"
            if not ready:
                readiness_blockers.append(f"C_{slot.upper()}_NOT_CONFIGURED")
        if self.config.dataset_maturity != "FORMAL":
            readiness_blockers.append("FORMAL_DATASET_MATURITY_NOT_DECLARED")

        record["readiness_components"] = {
            "b_platform_software": "READY",
            "a_integration_interface": "READY",
            "c_data_interface": "READY",
            "c_rl_environment": "READY",
            "c_model_interface": "READY",
            "security_provider_assets": (
                "READY"
                if record["security_provider_maturity"] == "FORMAL"
                else "BLOCKED_EXTERNAL"
            ),
            "calibration_software": "READY",
            "calibration_data": (
                "READY"
                if record["calibration_maturity"] == "APPROVED"
                else "BLOCKED_EXTERNAL"
            ),
            "bilstm_asset": model_components["bilstm"],
            "dueling_q_asset": model_components["dueling_q"],
            "rff_asset": model_components["rff"],
            "model_provenance": (
                "READY"
                if all(value == "READY" for value in model_components.values())
                else "BLOCKED_EXTERNAL"
            ),
            "dataset_generation": "READY",
            "final_formal_experiment": (
                "READY" if not readiness_blockers else "BLOCKED_EXTERNAL"
            ),
        }
        record["dataset_readiness"] = (
            "READY_FOR_C"
            if self.config.dataset_maturity == "FORMAL"
            else "READY_FOR_C_DEVELOPMENT"
        )
        record["readiness_blockers"] = sorted(set(readiness_blockers))
        record["experiment_readiness"] = (
            "READY" if not readiness_blockers else "BLOCKED_EXTERNAL"
        )
        record["scenario_plan"] = self.scenario.provenance()
        record["calibration_profile"] = (
            self._calibration_profile.to_dict()
            if self._calibration_profile is not None
            else None
        )
        record["calibration_runtime_controls"] = (
            self._calibration_profile.runtime_controls()
            if self._calibration_profile is not None
            else None
        )
        record["calibration_parameter_semantics"] = (
            self._calibration_profile.parameter_semantics()
            if self._calibration_profile is not None
            else None
        )
        record["profiles"]["calibration_profile_hash"] = (
            self._calibration_profile.profile_hash
            if self._calibration_profile is not None
            else None
        )
        record["identifier_provenance"] = {
            "online_semantics": "OPAQUE_RUN_SCOPED_IDENTIFIER",
            "links": [
                {
                    "online_link_id": self.observable_link_id(link.link_id),
                    "simulator_src_node_id": link.src_id,
                    "simulator_dst_node_id": link.dst_id,
                }
                for link in sorted(
                    self.topology.links.values(), key=lambda item: item.link_id
                )
            ],
            "online_session_ids": sorted(self._internal_session_ids),
        }
        record["config_fingerprint"] = runtime_semantic_fingerprint(
            record["config_fingerprint"],
            calibration_profile_hash=record["profiles"].get(
                "calibration_profile_hash"
            ),
            model_assets=current_models,
            probe_profile=self.probes.profile,
        )
        return record

    def mechanism_evidence(self) -> dict[str, Any]:
        """Return offline-only evidence used by scenario/batch acceptance gates."""

        return {
            "labels": self.attack_scheduler.labels(),
            "normal_disturbances": [
                {
                    "plan": asdict(record.plan),
                    "status": record.status,
                    "evidence": deepcopy(record.evidence),
                }
                for record in self.normal_disturbances.records.values()
            ],
            "scenario": self.scenario.provenance(),
            "replay_check_results": [
                event.get("online_features", {})
                .get("security_state", {})
                .get("replay_check_result")
                for event in self.events
                if event.get("event_type") == "AUTH_RESULT"
                and event.get("online_features", {})
                .get("security_state", {})
                .get("replay_check_result")
                not in {None, "UNAVAILABLE", "PASS"}
            ],
        }

    @staticmethod
    def _provider_provenance(provider: Any) -> dict[str, str]:
        return {
            "name": type(provider).__name__,
            "version": str(getattr(provider, "version", "builtin-v1")),
            "status": str(getattr(provider, "implementation_status", "UNKNOWN")),
        }

    def _collect_model_provenance(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for slot in sorted(self.model_adapters):
            adapter = self.model_adapters[slot]
            try:
                health = adapter.health()
            except Exception as exc:  # null/internal adapters are still untrusted here
                health = {
                    "model_name": getattr(adapter, "name", slot),
                    "model_version": getattr(adapter, "model_version", None),
                    "status": "ERROR",
                    "error_code": "MODEL_PROVENANCE_HEALTH_EXCEPTION",
                    "error_summary": f"{type(exc).__name__}: health unavailable",
                    "implementation_status": "UNKNOWN",
                }
            provider_status = str(
                health.get("provider_implementation_status")
                or health.get("asset_maturity")
                or health.get("implementation_status")
                or "UNKNOWN"
            )
            item: dict[str, Any] = {
                "configured": slot in self._provided_model_adapters,
                "slot": slot,
                "model_name": health.get("model_name")
                or getattr(adapter, "name", slot),
                "model_version": health.get("model_version")
                or getattr(adapter, "model_version", None),
                "status_at_export": str(health.get("status", "UNKNOWN")).upper(),
                "implementation_status": str(
                    health.get("implementation_status", "UNKNOWN")
                ),
                "provider_implementation_status": provider_status,
                "asset_maturity": health.get("asset_maturity"),
                "error_code": health.get("error_code"),
                "error_summary": health.get("error_summary"),
            }
            for field in (
                "bundle_hash",
                "preprocessor_version",
                "threshold_version",
                "training_data_version",
            ):
                item[field] = health.get(field)
            if not self._model_provenance_at_start:
                item["status_at_start"] = item["status_at_export"]
                item["error_code_at_start"] = item["error_code"]
            result[slot] = item
        return result

    def _close_model_supervisor(self) -> None:
        supervisor = getattr(self, "_model_execution_supervisor", None)
        if supervisor is not None:
            supervisor.close()

    def local_traffic_snapshot(
        self, node_id: int, window_s: float | None = None
    ) -> dict[str, Any]:
        if node_id not in self.nodes:
            raise KeyError(f"unknown node: {node_id}")
        return self.traffic_statistics.snapshot(
            node_id, self.context.clock.now_s, window_s
        )

    def _evaluate_eavesdroppers(
        self, frame: Frame, sender: Node, phy: dict[str, Any]
    ) -> None:
        for record in self.attack_scheduler.active(
            self.context.clock.now_s, "EAVESDROPPING"
        ):
            if record.plan.target_link_ids and frame.link_id not in record.plan.target_link_ids:
                continue
            if record.plan.target_node_ids and not (
                frame.link_sender_id in record.plan.target_node_ids
                or frame.link_receiver_id in record.plan.target_node_ids
            ):
                continue
            attacker_id = record.plan.attacker_node_id if record.plan.attacker_node_id is not None else -1
            attacker = self._external_node(attacker_id)
            radius = float(record.plan.parameters.get("receiver_radius_m", 300.0))
            distance = math.sqrt(
                sum(
                    (a - b) ** 2
                    for a, b in zip(attacker.position_xyz_m, sender.position_xyz_m)
                )
            )
            if distance > radius:
                continue
            AttackOutcomePolicy.attempted(record)
            quality = float(phy.get("measurement_quality") or 0.0)
            rng = self.context.rng.python(f"eavesdrop:{record.plan.attack_id}")
            if rng.random() > quality:
                continue
            outcome = record.outcome
            outcome["captured_count"] = int(outcome.get("captured_count", 0)) + 1
            self.packet_accounting.eaves_captured(record, frame)
            self.packet_accounting.capture_record(record, frame, self.context.clock.now_s)
            if frame.encrypted:
                outcome["ciphertext_count"] = int(outcome.get("ciphertext_count", 0)) + 1
            elif frame.sensitive:
                outcome["plaintext_exposure_count"] = int(
                    outcome.get("plaintext_exposure_count", 0)
                ) + 1
                outcome["content_recovery_count"] = int(
                    outcome.get("content_recovery_count", 0)
                ) + 1
            else:
                outcome["ordinary_plaintext_count"] = int(
                    outcome.get("ordinary_plaintext_count", 0)
                ) + 1
            outcome["protection_effective"] = bool(
                int(outcome.get("ciphertext_count", 0) or 0) > 0
                and int(outcome.get("plaintext_exposure_count", 0) or 0) == 0
            )
            record.truth["receiver_distance_m"] = round(distance, 6)
            AttackOutcomePolicy.injected(record)
            AttackOutcomePolicy.reached_target(record)
            AttackOutcomePolicy.refresh(record)

    def _can_route(self, src_id: int, dst_id: int) -> bool:
        route = self.topology.route(src_id, dst_id)
        return bool(route and len(route) >= 2)

    def _enqueue_source_report(
        self, report: SecurityReport, destination_id: int
    ) -> bool:
        message_id = self.queue_message(
            report.source_node_id,
            destination_id,
            "SECURITY_REPORT",
            report.to_dict(),
            sensitive=True,
            extensions={
                "report_id": report.report_id,
                "delivery_id": report.report_id,
                "report_stage": "SOURCE_TO_LEADER",
            },
            bypass_authorization=True,
        )
        return message_id is not None

    def _enqueue_gcs_payload(
        self, payload: dict[str, Any], destination_id: int
    ) -> bool:
        delivery_id = str(payload.get("report_id") or payload.get("summary_id"))
        packet_type = str(payload.get("report_type", "SECURITY_REPORT"))
        message_id = self.queue_message(
            self.leader_node_id,
            destination_id,
            packet_type,
            payload,
            sensitive=True,
            extensions={
                "report_id": delivery_id,
                "delivery_id": delivery_id,
                "report_stage": "LEADER_TO_GCS",
            },
            bypass_authorization=True,
        )
        return message_id is not None

    def _mark_report_failed(self, message: Message) -> None:
        delivery_id = message.extensions.get("delivery_id") or message.extensions.get(
            "report_id"
        )
        if delivery_id:
            self.reporting.mark_delivery_failed(str(delivery_id))

    def _mark_report_failed_from_frame(self, frame: Frame) -> None:
        delivery_id = frame.extensions.get("delivery_id") or frame.extensions.get(
            "report_id"
        )
        if delivery_id:
            self.reporting.mark_delivery_failed(str(delivery_id))

    def request_defense(
        self,
        *,
        node_id: int,
        action: str,
        target_node_id: int | None = None,
        target_link_id: str | None = None,
        peer_id: int | None = None,
        session_id: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        if node_id not in self.nodes:
            raise KeyError(f"unknown node: {node_id}")
        request = DefenseRequest(
            request_id=self.context.ids.next("defense-request"),
            action=DefenseAction(action),
            requester_node_id=node_id,
            target_node_id=target_node_id,
            target_link_id=target_link_id,
            peer_id=peer_id,
            session_id=session_id,
            requested_time_s=self.context.clock.now_s,
            reason=reason,
        )
        result = self.defense.execute(
            request, self.nodes[node_id], self.context.clock.now_s
        )
        payload = result.to_dict()
        self._attach_runtime_outcome(payload, node_id)
        if payload["executed"] and action == DefenseAction.REROUTE.value:
            self._refresh_local_topology(reason="DEFENSE_REROUTE")
        self._append_event(
            build_event(
                self.context,
                EventType.DEFENSE_RESULT,
                self.nodes[node_id],
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": "RESULT_EVENT",
                },
                extensions={"defense_result": payload},
                leader_id=self.leader_node_id,
            )
        )
        return payload

    def capture_action_baseline(self, observer_node_id: int) -> dict[str, Any]:
        """Capture deterministic counters immediately before a policy action."""

        return {
            "sim_time_s": self.context.clock.now_s,
            "event_index": len(self.events),
            "drop_count": self.nodes[observer_node_id].drop_count,
            "traffic": self.local_traffic_snapshot(observer_node_id, 2.0),
            "attack_counters": {
                attack_id: {
                    key: int(record.outcome.get(key, 0) or 0)
                    for key in (
                        "generated_packets",
                        "affected_transmissions",
                        "decoded_transmissions",
                        "decode_failures",
                        "phy_decode_failures",
                        "malicious_traffic_blocked",
                        "malicious_traffic_delivered",
                    )
                }
                for attack_id, record in self.attack_scheduler.records.items()
            },
        }

    def complete_action_outcome(
        self,
        result: dict[str, Any],
        observer_node_id: int,
        baseline: dict[str, Any],
    ) -> dict[str, Any]:
        """Attach post-action effects measured over the advanced decision epoch."""

        outcome = result["outcome"]
        after = self.local_traffic_snapshot(observer_node_id, 2.0)
        before = baseline["traffic"]
        counter_before = baseline["attack_counters"]
        attempted = 0
        malicious_blocked = 0
        malicious_delivered = 0
        physical_failures = 0
        any_effective = False
        for attack_id, record in self.attack_scheduler.records.items():
            previous = counter_before.get(attack_id, {})

            def delta(name: str) -> int:
                return max(
                    0,
                    int(record.outcome.get(name, 0) or 0)
                    - int(previous.get(name, 0) or 0),
                )

            generated = delta("generated_packets")
            affected = delta("affected_transmissions")
            attempted += max(generated, affected)
            malicious_blocked += delta("malicious_traffic_blocked")
            malicious_delivered += delta("malicious_traffic_delivered")
            any_effective = any_effective or bool(
                record.outcome.get("attack_effective", False)
                and record.plan.impact_start_s
                <= self.context.clock.now_s + 1e-12
                and record.plan.end_s
                > float(baseline["sim_time_s"]) - 1e-12
            )

        impact_numerator = malicious_delivered + physical_failures
        attack_impact = (
            min(1.0, impact_numerator / max(1, attempted))
            if attempted
            else (1.0 if any_effective else 0.0)
        )
        interval_events = self.events[int(baseline["event_index"]) :]
        legitimate_rx = [
            event
            for event in interval_events
            if event.get("observer_node_id") == observer_node_id
            and event.get("event_type") in {"RX_SUCCESS", "RX_FAILURE"}
            and event.get("event_id") not in self._attack_event_ids
        ]
        legitimate_failures = sum(
            event["event_type"] == "RX_FAILURE" for event in legitimate_rx
        )
        drop_delta = max(
            0, self.nodes[observer_node_id].drop_count - int(baseline["drop_count"])
        )
        legitimate_defense_drops = max(0, drop_delta - malicious_blocked)

        before_throughput = float(before.get("throughput_mbps") or 0.0)
        after_throughput = float(after.get("throughput_mbps") or 0.0)
        throughput_loss_ratio = (
            max(0.0, min(1.0, (before_throughput - after_throughput) / before_throughput))
            if before_throughput > 0
            else 0.0
        )
        before_latency = before.get("latency_ms")
        after_latency = after.get("latency_ms")
        latency_increase_ratio = (
            max(
                0.0,
                min(
                    1.0,
                    (float(after_latency) - float(before_latency))
                    / float(before_latency),
                ),
            )
            if isinstance(before_latency, (int, float))
            and before_latency > 0
            and isinstance(after_latency, (int, float))
            else 0.0
        )
        legitimate_drop_ratio = (
            (legitimate_failures + legitimate_defense_drops)
            / max(1, len(legitimate_rx) + legitimate_defense_drops)
        )
        harm_score = min(
            1.0,
            (
                throughput_loss_ratio
                + latency_increase_ratio
                + legitimate_drop_ratio
            )
            / 3.0,
        )
        command_events = [
            event
            for event in legitimate_rx
            if event.get("online_features", {})
            .get("packet", {})
            .get("packet_type")
            == "MISSION_COMMAND"
        ]
        command_failure_ratio = (
            sum(event["event_type"] == "RX_FAILURE" for event in command_events)
            / len(command_events)
            if command_events
            else 0.0
        )
        service_unavailability = (
            legitimate_failures / len(legitimate_rx) if legitimate_rx else 0.0
        )
        mission = MissionImpactEvaluator.from_components(
            command_failure_ratio=(command_failure_ratio if command_events else None),
            telemetry_unavailability_ratio=(
                service_unavailability if legitimate_rx else None
            ),
            service_degradation_ratio=(
                throughput_loss_ratio if before_throughput > 0 else None
            ),
        )

        outcome.update(
            {
                "attack_impact": round(attack_impact, 9),
                "malicious_traffic_blocked": malicious_blocked,
                "legitimate_traffic_harmed": bool(harm_score > 0.0),
                "legitimate_traffic_harm_score": round(harm_score, 9),
                "legitimate_drop_count": legitimate_failures
                + legitimate_defense_drops,
                "throughput_loss_ratio": round(throughput_loss_ratio, 9),
                "latency_increase_ratio": round(latency_increase_ratio, 9),
                "throughput_mbps": after_throughput,
                "latency_ms": after_latency,
                "mission_impact": mission.score,
                "mission_impact_components": mission.components,
                "communication_overhead": outcome.get(
                    "communication_overhead_bytes"
                ),
                "compute_overhead_ms": None,
                "evaluation_interval_s": round(
                    self.context.clock.now_s - float(baseline["sim_time_s"]), 9
                ),
            }
        )
        outcome["availability"] = {
            "attack_impact": True,
            "malicious_traffic_blocked": True,
            "legitimate_traffic_harmed": True,
            "throughput_mbps": True,
            "latency_ms": after_latency is not None,
            "mission_impact": mission.available,
            "communication_overhead": False,
            "communication_overhead_bytes": False,
            "compute_overhead_ms": False,
            "missing_reason": (
                None
                if after_latency is not None
                else "NO_LOCAL_SUCCESSFUL_PACKET_IN_DECISION_EPOCH"
            ),
        }
        self._append_event(
            build_event(
                self.context,
                EventType.DEFENSE_RESULT,
                self.nodes[observer_node_id],
                availability={
                    "payload_available": False,
                    "phy_available": False,
                    "missing_reason": "POST_ACTION_EVALUATION",
                },
                extensions={
                    "defense_result": deepcopy(result),
                    "result_phase": "POST_ACTION_EVALUATION",
                },
                leader_id=self.leader_node_id,
            )
        )
        return result

    def observation(self, node_id: int) -> dict[str, Any]:
        if node_id not in self.nodes:
            raise KeyError(f"unknown node: {node_id}")
        node_events = [
            event for event in self.events if event["observer_node_id"] == node_id
        ]
        node = self.nodes[node_id]
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "observer_node_id": node_id,
            "observer_role": node.role.value,
            "sim_time_s": self.context.clock.now_s,
            "latest_event": deepcopy(node_events[-1]) if node_events else None,
            "queue": {
                "tx": len(node.tx_queue),
                "rx": len(node.rx_queue),
                "forward": len(node.forward_queue),
                "drops": node.drop_count,
            },
            "known_topology": {
                "neighbor_ids": sorted(node.known_neighbor_ids),
                "known_bad_link_ids": sorted(node.known_bad_link_ids),
                "topology_version": node.known_topology_version,
            },
            "model_health": {
                name: adapter.health() for name, adapter in self.model_adapters.items()
            },
        }

    def rl_observation(self, node_id: int) -> dict[str, Any]:
        """Return a local, causal state for C's policy adapter.

        This state is built only from events observed by ``node_id`` and the
        node's own resource/defense state.  Labels and attack scheduler state
        are intentionally not reachable from this method.
        """

        if node_id not in self.nodes:
            raise KeyError(f"unknown node: {node_id}")
        now_s = self.context.clock.now_s
        node = self.nodes[node_id]
        local_events = [
            event
            for event in self.events
            if event["observer_node_id"] == node_id
            and float(event["sim_time_s"]) <= now_s + 1e-12
        ]

        def traffic_window(width: float) -> dict[str, Any]:
            snapshot = self.traffic_statistics.snapshot(node_id, now_s, width)
            return {
                "window_s": width,
                "packet_rate_pps": snapshot["packet_rate_pps"],
                "error_rate": snapshot["error_rate"],
                "queue_length": len(node.rx_queue) + len(node.forward_queue),
                "latency_ms": snapshot["latency_ms"],
                "throughput_mbps": snapshot["throughput_mbps"],
                "availability": {
                    "traffic": True,
                    "latency_ms": snapshot["latency_ms"] is not None,
                    "missing_reason": (
                        None
                        if snapshot["latency_ms"] is not None
                        else "NO_LOCAL_SUCCESSFUL_PACKET_IN_WINDOW"
                    ),
                },
            }

        phy_events = [
            event
            for event in local_events
            if event["event_type"] in {"PHY_SAMPLE", "RX_SUCCESS", "RX_FAILURE"}
            and event["online_features"]["phy"].get("snr_db") is not None
        ]
        phy_names = ("rssi_dbm", "snr_db", "sinr_db", "per_estimate")
        latest_phy = {
            name: (
                phy_events[-1]["online_features"]["phy"].get(name)
                if phy_events
                else None
            )
            for name in phy_names
        }
        previous_phy = {
            name: (
                phy_events[-2]["online_features"]["phy"].get(name)
                if len(phy_events) >= 2
                else phy_events[-1]["online_features"]["phy"].get(name)
                if len(phy_events) == 1
                else None
            )
            for name in phy_names
        }
        phy_delta = {
            name: (
                round(float(latest_phy[name]) - float(previous_phy[name]), 9)
                if isinstance(latest_phy[name], (int, float))
                and isinstance(previous_phy[name], (int, float))
                else None
            )
            for name in phy_names
        }

        recent_security = [
            event
            for event in local_events
            if float(event["sim_time_s"]) >= now_s - 5.0 - 1e-12
        ]
        auth_failure_count = sum(
            event["event_type"] == "AUTH_RESULT"
            and event["online_features"]["security_state"].get("auth_result")
            == "FAIL"
            for event in recent_security
        )
        replay_anomaly_count = sum(
            event["event_type"] == "AUTH_RESULT"
            and event["online_features"]["security_state"].get(
                "replay_check_result"
            )
            in {"DUPLICATE", "STALE", "WRONG_SESSION"}
            for event in recent_security
        )
        # Count RFF decisions, not every later event that carries the persisted
        # local state.  The node counter is incremented once per anomalous
        # RFF MODEL_RESULT and reset with the episode.
        rff_anomaly_count = node.rff_anomaly_count
        sensitive_observation_count = (
            node.protected_sensitive_count + node.unprotected_sensitive_count
        )
        plaintext_protection_risk = (
            node.unprotected_sensitive_count / sensitive_observation_count
            if sensitive_observation_count > 0
            else None
        )

        model_results = [
            event.get("extensions", {}).get("model_result", {})
            for event in local_events
            if event["event_type"] == "MODEL_RESULT"
            and str(
                event.get("extensions", {})
                .get("model_result", {})
                .get("model_name", "")
            ).lower().startswith("bilstm")
        ]
        latest_model = model_results[-1] if model_results else None
        bilstm = {
            "status": (
                latest_model.get("status") if latest_model else "UNAVAILABLE"
            ),
            "scores": latest_model.get("scores") if latest_model else None,
            "confidence": (
                latest_model.get("confidence") if latest_model else None
            ),
            "quality": latest_model.get("quality") if latest_model else None,
            "predicted_label": (
                latest_model.get("predicted_label") if latest_model else None
            ),
            "error_code": (
                latest_model.get("error_code")
                if latest_model
                else "MODEL_NOT_CONFIGURED"
            ),
        }
        channels = sorted(
            {
                self.phy.states[link_id].channel_id
                for link_id in node.known_neighbor_link_ids
                if link_id in self.phy.states
            }
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "observer_node_id": node_id,
            "sim_time_s": now_s,
            "recent_2s": traffic_window(2.0),
            "recent_5s": traffic_window(5.0),
            "phy": {
                "latest": latest_phy,
                "previous": previous_phy,
                "delta": phy_delta,
                "trend": {
                    name: (
                        "UP"
                        if isinstance(phy_delta[name], (int, float))
                        and phy_delta[name] > 0
                        else "DOWN"
                        if isinstance(phy_delta[name], (int, float))
                        and phy_delta[name] < 0
                        else "FLAT"
                        if phy_delta[name] == 0
                        else "UNAVAILABLE"
                    )
                    for name in phy_names
                },
                "availability": {
                    "available": bool(phy_events),
                    "missing_reason": None if phy_events else "NO_LOCAL_PHY_SAMPLE",
                },
            },
            "security": {
                "auth_failure_count": auth_failure_count,
                "replay_anomaly_count": replay_anomaly_count,
                "plaintext_exposure_status": None,
                "plaintext_protection_risk": plaintext_protection_risk,
                "protected_sensitive_count": node.protected_sensitive_count,
                "unprotected_sensitive_count": node.unprotected_sensitive_count,
                "rff_anomaly_count": rff_anomaly_count,
                "availability": {
                    "plaintext_exposure_status": False,
                    "plaintext_protection_risk": sensitive_observation_count > 0,
                    "rff": self.model_adapters["rff"].health().get("status")
                    == "OK",
                    "missing_reason": (
                        "NO_LOCAL_SENSITIVE_TRAFFIC_OBSERVED"
                        if sensitive_observation_count == 0
                        else "EXPOSURE_TRUTH_NOT_LOCALLY_OBSERVABLE"
                    ),
                },
            },
            "model": {"bilstm": bilstm},
            "node": {
                "role": node.role.value,
                "battery_pct": node.battery_pct,
                "flight_state": node.flight_state,
                "neighbor_count": len(node.known_neighbor_ids),
                "bad_link_count": len(node.known_bad_link_ids),
                "current_channel": channels[0] if len(channels) == 1 else channels,
            },
            "defense_resource": {
                "active_actions": {
                    "rate_limited_peer_ids": sorted(node.rate_limited_peer_ids),
                    "isolated_peer_ids": sorted(node.isolated_peer_ids),
                },
                "rate_limit_state": bool(node.rate_limited_peer_ids),
                "isolated_data_source": (
                    sorted(node.isolated_peer_ids)
                    if node.isolated_peer_ids
                    else None
                ),
                "monitoring_level": node.monitoring_level,
                "communication_overhead_bytes": None,
                "compute_overhead_ms": None,
                "availability": {
                    "communication_overhead_bytes": False,
                    "compute_overhead_ms": False,
                    "missing_reason": "RESOURCE_OVERHEAD_NOT_MEASURED",
                },
            },
            "availability": {
                "traffic_statistics": True,
                "phy": bool(phy_events),
                "bilstm": bilstm["status"] == "OK",
                "rff": self.model_adapters["rff"].health().get("status") == "OK",
            },
        }

    def runtime_view(self, cursor: int = 0) -> dict[str, Any]:
        gcs_events = [
            event for event in self.events if event["observer_node_id"] == self.gcs_node_id
        ]
        return {
            "scope": "GCS_RECEIVED_RUNTIME_VIEW",
            "packet_accounting": self.packet_accounting.snapshot(self.run_id),
            "receiver_rate_observations": self.receiver_rate_observations.snapshot(),
            "status": self.status(),
            "run_metadata": self.run_record(),
            "node_roles": {
                str(node_id): role.value for node_id, role in self.roles.items()
            },
            "events": deepcopy(gcs_events[max(0, cursor) :]),
            "next_cursor": len(gcs_events),
            "security_reports": deepcopy(self.reporting.gcs_inbox),
            "missing_or_delayed_reports": sum(
                len(self.reporting.pending_for(node_id))
                for node_id in self.nodes
                if node_id != self.gcs_node_id
            ),
        }

    def evaluation_view(self) -> dict[str, Any]:
        self._refresh_attack_backlog_truth()
        evaluation = ExperimentEvaluator().evaluate(
            self.events,
            self.attack_scheduler.labels(),
            reports=self.reporting.gcs_inbox,
            run_record=self.run_record(),
        )
        evaluation["application_layer_available"] = self.config.application_layer_available
        evaluation["physical_layer"] = evaluate_rff(
            self.events, self.attack_scheduler.labels(),
            transmissions=self.packet_accounting.causal["transmissions"],
            legitimate_node_ids=[node_id for node_id, node in self.nodes.items()
                                 if node.role != NodeRole.EXTERNAL],
            enabled=self.config.rff_enabled,
            policy_mode=self.config.rff_policy_mode,
        )
        return evaluation

    def metrics(self) -> dict[str, Any]:
        tx = self._metric_totals["tx"]
        samples = max(1, self._metric_totals["rx_success"] + self._metric_totals["rx_failure"])
        return {
            "scope": "SIMULATOR_AGGREGATE_METRICS",
            **self._metric_totals,
            "delivery_rate": self._metric_totals["delivered"] / max(1, tx),
            "packet_loss_rate": self._metric_totals["rx_failure"] / samples,
            "mean_latency_ms": self._metric_totals["latency_ms_sum"] / max(1, tx),
            "mean_throughput_mbps": self._metric_totals["throughput_mbps_sum"] / max(1, tx),
        }

    def gcs_metrics(self) -> dict[str, Any]:
        """Aggregate only events locally observed by the GCS plus received reports."""
        local = [
            event
            for event in self.events
            if event["observer_node_id"] == self.gcs_node_id
        ]
        successes = [event for event in local if event["event_type"] == "RX_SUCCESS"]
        failures = [event for event in local if event["event_type"] == "RX_FAILURE"]
        samples = successes + failures
        latencies = [
            float(event["online_features"]["traffic"]["latency_ms"])
            for event in samples
            if event["online_features"]["traffic"]["latency_ms"] is not None
        ]
        throughputs = [
            float(event["online_features"]["traffic"]["throughput_mbps"])
            for event in samples
            if event["online_features"]["traffic"]["throughput_mbps"] is not None
        ]
        total = len(samples)
        missing = sum(
            len(self.reporting.pending_for(node_id))
            for node_id in self.nodes
            if node_id != self.gcs_node_id
        )
        return {
            "scope": "GCS_RECEIVED_AGGREGATE",
            "received_success": len(successes),
            "received_failure": len(failures),
            "delivery_rate": len(successes) / max(1, total),
            "packet_loss_rate": len(failures) / max(1, total),
            "mean_latency_ms": sum(latencies) / max(1, len(latencies)),
            "mean_throughput_mbps": sum(throughputs) / max(1, len(throughputs)),
            "security_report_count": len(self.reporting.gcs_inbox),
            "missing_or_delayed_reports": missing,
        }

    def model_status(self) -> dict[str, Any]:
        return {
            name: adapter.health() for name, adapter in self.model_adapters.items()
        }

    def topology_view(self, *, truth: bool = False) -> dict[str, Any]:
        if truth:
            return {"scope": "SIMULATOR_GROUND_TRUTH", **self.topology.snapshot()}
        gcs = self.nodes[self.gcs_node_id]
        return {
            "scope": "GCS_LOCAL_TOPOLOGY",
            "observer_node_id": self.gcs_node_id,
            "neighbor_ids": sorted(gcs.known_neighbor_ids),
            "neighbor_link_ids": sorted(gcs.known_neighbor_link_ids),
            "known_bad_link_ids": sorted(gcs.known_bad_link_ids),
        }

    def register_rf_sample(
        self,
        record: dict[str, Any],
        *,
        message_id: str,
        link_id: str,
    ) -> str:
        if link_id not in self.topology.links:
            raise KeyError(f"unknown link: {link_id}")
        sample_id = str(record.get("sample_id") or "")
        if not sample_id:
            raise ValueError("rf manifest sample_id is required")
        if any(item.get("sample_id") == sample_id for item in self.rf_manifest):
            raise ValueError(f"duplicate RF sample id: {sample_id}")
        self.rf_manifest.append(deepcopy(record))
        self._rf_sample_bindings[(str(message_id), link_id)] = sample_id
        return sample_id

    def export_dataset(self, output_dir: str | Path) -> dict[str, Any]:
        self._refresh_attack_backlog_truth()
        return DatasetExporter().export(
            output_dir,
            run_record=self.run_record(),
            events=self.events,
            labels=self.attack_scheduler.labels(),
            rf_manifest=self.rf_manifest,
        )

    def reproducible_event_projection(self) -> list[dict[str, Any]]:
        """Projection excluding run-scoped IDs for same-seed comparisons."""

        def canonicalize_ids(value: Any, key: str | None = None) -> Any:
            """Remove run-scoped identifier representation from this view."""

            if isinstance(value, dict):
                return {
                    child_key: canonicalize_ids(child_value, child_key)
                    for child_key, child_value in value.items()
                }
            if isinstance(value, list):
                singular = key[:-1] if isinstance(key, str) and key.endswith("s") else key
                return [canonicalize_ids(item, singular) for item in value]
            if isinstance(value, str) and isinstance(key, str):
                if key == "sample_id" and value.startswith("rff-"):
                    return f"rff-{value.rsplit('-', 1)[-1]}"
                if key.endswith("link_id"):
                    return self.internal_link_id(value)
                if key.endswith("session_id"):
                    return self._internal_session_ids.get(value, value)
            return value

        projection: list[dict[str, Any]] = []
        for event in self.events:
            online = canonicalize_ids(deepcopy(event["online_features"]))
            # Run-scoped identifiers are carried in report payloads.  Their
            # textual length can change encrypted wire size (and its derived
            # latency/rate) even though all simulated choices are identical.
            # Those representation-only quantities are excluded together with
            # the identifiers themselves from this reproducibility projection.
            online["packet"]["packet_size_bytes"] = None
            online["traffic"]["byte_rate_Bps"] = None
            online["traffic"]["throughput_mbps"] = None
            online["traffic"]["latency_ms"] = None
            projection.append(
                {
                "sim_time_s": event["sim_time_s"],
                "event_type": event["event_type"],
                "observer_node_id": event["observer_node_id"],
                "observer_role": event["observer_role"],
                "message_suffix": (
                    event["message_id"].rsplit("-", 1)[-1]
                    if event.get("message_id")
                    else None
                ),
                "online_features": online,
                "availability": event["availability"],
                }
            )
        return projection
