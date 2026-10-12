"""Compatibility facade over the deterministic platform runtime.

New code should use :class:`swarm_sim.runtime.PlatformRuntime` directly. This
class keeps the original HTTP surface usable while removing its wall-clock,
global-truth and one-random-packet-per-request semantics.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.calibration import CalibrationProfile
from swarm_sim.domain import RunState
from swarm_sim.factory import PlatformRuntimeFactory


ATTACK_NAME_MAP = {
    "spoofing": "SPOOFING",
    "dos": "DOS",
    "fdi": "FDI",
    "replay": "REPLAY",
    "eavesdropping": "EAVESDROPPING",
}


class SimulationManager:
    """Legacy adapter whose authoritative state belongs to one runtime."""

    def __init__(
        self, runtime_factory: PlatformRuntimeFactory | None = None
    ) -> None:
        self.runtime: PlatformRuntime | None = None
        self.runtime_factory = runtime_factory or PlatformRuntimeFactory()
        self._calibration_profile: CalibrationProfile | None = None
        self._defense_config: dict[int, dict[str, bool]] = {}
        self._legacy_cursor = 0

    @property
    def is_running(self) -> bool:
        return self.runtime is not None and self.runtime.state not in {
            RunState.STOPPED,
            RunState.COMPLETED,
        }

    @property
    def uav_swarm(self) -> list[Any]:
        return list(self.runtime.nodes.values()) if self.runtime else []

    @property
    def network_topo(self) -> Any:
        return self.runtime.topology if self.runtime else None

    @property
    def stats(self) -> dict[str, int]:
        if not self.runtime:
            return self._empty_stats()
        metrics = self.runtime.metrics()
        labels = self.runtime.attack_scheduler.labels()
        defenses = [
            event
            for event in self.runtime.events
            if event["event_type"] == "DEFENSE_RESULT"
        ]
        return {
            "total_pkts": int(metrics["tx"]),
            "phy_loss": int(metrics["rx_failure"]),
            "total_attacks": len(labels),
            "defense_drops": int(sum(node.drop_count for node in self.runtime.nodes.values())),
            "defense_switch": sum(
                1
                for event in defenses
                if event["extensions"]["defense_result"]["request"]["action"]
                == "CHANNEL_SWITCH"
            ),
            "attack_success": sum(
                1 for label in labels if label.get("outcome", {}).get("attack_effective")
            ),
        }

    @staticmethod
    def _empty_stats() -> dict[str, int]:
        return {
            "total_pkts": 0,
            "phy_loss": 0,
            "total_attacks": 0,
            "defense_drops": 0,
            "defense_switch": 0,
            "attack_success": 0,
        }

    @property
    def attack_metrics(self) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {
            name: {"attempts": 0, "attack_success": 0, "detect_success": 0}
            for name in ["Spoofing", "FDI", "Replay", "DoS"]
        }
        result["Eavesdropping"] = {
            "attempts": 0,
            "attack_success": 0,
            "defense_success": 0,
        }
        if not self.runtime:
            return result
        display_name = {
            "SPOOFING": "Spoofing",
            "FDI": "FDI",
            "REPLAY": "Replay",
            "DOS": "DoS",
            "EAVESDROPPING": "Eavesdropping",
        }
        detected = {
            event.get("extensions", {}).get("model_result", {}).get("predicted_label")
            for event in self.runtime.events
            if event["event_type"] == "MODEL_RESULT"
        }
        for label in self.runtime.attack_scheduler.labels():
            family = str(label["attack_family"])
            key = display_name.get(family)
            if key == "Eavesdropping":
                outcome = label.get("outcome", {})
                result[key]["attempts"] += int(outcome.get("captured_count", 0))
                result[key]["attack_success"] += int(outcome.get("plaintext_exposure_count", 0))
                result[key]["defense_success"] += int(outcome.get("ciphertext_count", 0))
            elif key in result:
                result[key]["attempts"] += 1
                result[key]["attack_success"] += int(
                    bool(label.get("outcome", {}).get("attack_effective"))
                )
                result[key]["detect_success"] += int(family in detected)
        return result

    def init_environment(
        self,
        num_uavs: int = 10,
        *,
        seed: int = 42,
        duration_s: float = 60.0,
        step_s: float = 0.2,
        auto_traffic: bool = True,
    ) -> dict[str, Any]:
        config = RunConfig(
            seed=seed,
            duration_s=duration_s,
            step_s=step_s,
            node_count=max(2, num_uavs),
            auto_traffic=auto_traffic,
        )
        return self.create_run(config)

    def create_run(
        self,
        config: RunConfig | dict[str, Any],
        *,
        calibration_profile: CalibrationProfile | None = None,
    ) -> dict[str, Any]:
        """Install a fresh initialized runtime from the complete V1 config."""
        actual = config if isinstance(config, RunConfig) else RunConfig.from_dict(config)
        if self.runtime is not None:
            self.runtime.close()
        self._calibration_profile = calibration_profile
        self.runtime = self.runtime_factory.create(
            actual, calibration_profile=calibration_profile
        )
        self._legacy_cursor = 0
        self._defense_config = {
            node_id: {name: True for name in ATTACK_NAME_MAP.values()}
            for node_id in self.runtime.nodes
        }
        return {
            "status": "success",
            "message": "deterministic runtime initialized",
            "run": self.runtime.status(),
            **self._legacy_topology(),
        }

    def _require_runtime(self) -> PlatformRuntime:
        if self.runtime is None:
            raise RuntimeError("仿真未初始化")
        return self.runtime

    def start(self) -> dict[str, Any]:
        return self._require_runtime().start()

    def pause(self) -> dict[str, Any]:
        return self._require_runtime().pause()

    def resume(self) -> dict[str, Any]:
        return self._require_runtime().resume()

    def stop(self) -> dict[str, Any]:
        return self._require_runtime().stop()

    def reset(self) -> dict[str, Any]:
        previous = self._require_runtime()
        config = previous.config
        previous.close()
        self.runtime = self.runtime_factory.create(
            config, calibration_profile=self._calibration_profile
        )
        self._legacy_cursor = 0
        self._defense_config = {
            node_id: {name: True for name in ATTACK_NAME_MAP.values()}
            for node_id in self.runtime.nodes
        }
        return self.runtime.status()

    def set_runtime_factory(self, runtime_factory: PlatformRuntimeFactory) -> None:
        """Install the server/program dependency factory for subsequent runs."""

        if not isinstance(runtime_factory, PlatformRuntimeFactory):
            raise TypeError("runtime_factory must be a PlatformRuntimeFactory")
        self.runtime_factory = runtime_factory

    def step(self) -> dict[str, Any]:
        runtime = self._require_runtime()
        if runtime.state == RunState.INITIALIZED:
            runtime.start()
        created = runtime.step() if runtime.state == RunState.RUNNING else []
        data = runtime.runtime_view(self._legacy_cursor)
        self._legacy_cursor = data["next_cursor"]
        return {
            "status": "success",
            "deprecated": "Use lifecycle POST endpoints and read-only GET /api/runtime.",
            "seq": len(runtime.events),
            "sim_time_s": runtime.context.clock.now_s,
            "events": created,
            "metrics": runtime.metrics(),
            "topology": self._legacy_topology(),
            "run": runtime.status(),
        }

    def inject_attack(self, attack_type: str, params: dict[str, Any]) -> dict[str, Any]:
        runtime = self._require_runtime()
        family = ATTACK_NAME_MAP.get(attack_type.lower())
        if family is None:
            return {"status": "error", "msg": f"unsupported attack: {attack_type}"}
        now = runtime.context.clock.now_s
        subtype = str(params.get("subtype") or self._default_subtype(family, params)).upper()
        target_node = params.get("attack_dst")
        targets = [int(target_node)] if target_node is not None else []
        if family == "FDI" and params.get("attack_src") is not None:
            targets = [int(params["attack_src"])]
            if target_node is not None:
                params = {**params, "intended_dst_id": int(target_node)}
        target_link = params.get("target_link")
        link_ids = [self._resolve_link_id(target_link)] if target_link is not None else []
        if family == "DOS":
            # The only supported DoS mechanism is receiver-load flooding; it
            # has no attack target-link or interference-power contract.
            link_ids = []
        attack_params: dict[str, Any] = dict(params.get("parameters") or {})
        if family == "SPOOFING" and params.get("fake_src") is not None:
            attack_params["claimed_src_id"] = int(params["fake_src"])
        if family == "FDI":
            replacement = {"cmd": params.get("malicious_cmd", "LAND")}
            replacement.update(params.get("malicious_params") or {})
            attack_params["replacement"] = replacement
        start_s = float(params.get("scheduled_start_s", now))
        impact_s = float(params.get("impact_start_s", now + runtime.config.step_s))
        end_s = float(params.get("end_s", min(runtime.config.duration_s, impact_s + 5.0)))
        if end_s <= impact_s:
            end_s = impact_s + runtime.config.step_s
        plan = AttackPlan(
            attack_family=family,
            attack_subtype=subtype,
            scheduled_start_s=start_s,
            impact_start_s=impact_s,
            end_s=end_s,
            attacker_node_id=params.get("attack_src"),
            target_node_ids=targets,
            target_link_ids=link_ids,
            intensity=dict(params.get("intensity") or {}),
            parameters=attack_params,
        )
        return {"status": "queued", "attack_plan": runtime.schedule_attack(plan)}

    @staticmethod
    def _default_subtype(family: str, params: dict[str, Any]) -> str:
        if family == "DOS":
            return "FLOODING"
        return {
            "SPOOFING": "KNOWN_ID_CONFLICT",
            "FDI": "COMMAND_REPLACEMENT",
            "REPLAY": "CAPTURE_AND_REPLAY",
            "EAVESDROPPING": "PASSIVE_CAPTURE",
        }[family]

    def _resolve_link_id(self, value: Any) -> str:
        runtime = self._require_runtime()
        raw = str(value)
        if raw in runtime.topology.links:
            return raw
        links = sorted(runtime.topology.links)
        try:
            return links[int(value)]
        except (ValueError, IndexError):
            raise ValueError(f"unknown target link: {value}") from None

    def start_listening(self, attack_type: str, duration: float = 10.0) -> dict[str, Any]:
        now = self._require_runtime().context.clock.now_s
        result = self.inject_attack(attack_type, {"end_s": now + max(duration, 0.2)})
        return {**result, "status": "listening_started", "duration": duration}

    def stop_listening(self, attack_type: str) -> dict[str, Any]:
        runtime = self._require_runtime()
        family = ATTACK_NAME_MAP.get(attack_type.lower(), attack_type.upper())
        for record in runtime.attack_scheduler.records.values():
            if record.plan.attack_family == family and record.status != "ENDED":
                record.plan.end_s = max(runtime.context.clock.now_s, record.plan.impact_start_s + 1e-9)
                record.status = "ENDED"
        return {"status": "listening_stopped", "type": family}

    def get_captured_data(self, attack_type: str) -> dict[str, Any]:
        runtime = self._require_runtime()
        family = ATTACK_NAME_MAP.get(attack_type.lower(), attack_type.upper())
        return {
            "status": "success",
            "type": family,
            "labels": [
                label for label in runtime.attack_scheduler.labels()
                if label["attack_family"] == family
            ],
        }

    def configure_defense(self, node_id: int, attack_type: str, enabled: bool) -> dict[str, Any]:
        runtime = self._require_runtime()
        if node_id not in runtime.nodes:
            return {"status": "error", "msg": f"节点 {node_id} 不存在"}
        normalized = ATTACK_NAME_MAP.get(attack_type.lower(), attack_type.upper())
        self._defense_config.setdefault(node_id, {})[normalized] = bool(enabled)
        return {
            "status": "success",
            "node_id": node_id,
            "attack_type": normalized,
            "enabled": bool(enabled),
            "current_config": dict(self._defense_config[node_id]),
            "note": "Compatibility switch; V1 policy execution remains explicit and auditable.",
        }

    def configure_defense_batch(self, node_id: int, config_dict: dict[str, bool]) -> dict[str, Any]:
        for attack_type, enabled in config_dict.items():
            response = self.configure_defense(node_id, attack_type, enabled)
            if response["status"] == "error":
                return response
        return self.get_defense_status(node_id)

    def configure_defense_global(self, attack_type: str, enabled: bool) -> dict[str, Any]:
        runtime = self._require_runtime()
        for node_id in runtime.nodes:
            self.configure_defense(node_id, attack_type, enabled)
        return {"status": "success", "attack_type": attack_type, "enabled": enabled}

    def get_defense_status(self, node_id: int | None = None) -> dict[str, Any]:
        self._require_runtime()
        if node_id is not None:
            if node_id not in self._defense_config:
                return {"status": "error", "msg": f"节点 {node_id} 不存在"}
            return {"status": "success", "node_id": node_id, "defense_config": dict(self._defense_config[node_id])}
        return {"status": "success", "defense_status": {key: dict(value) for key, value in self._defense_config.items()}}

    def _legacy_topology(self) -> dict[str, Any]:
        runtime = self._require_runtime()
        nodes = [node for node in runtime.nodes.values() if node.node_id >= 0]
        return {
            "nodes": [
                {"id": node.node_id, "role": node.role.value, "pos": list(node.position_xyz_m), "state": node.flight_state}
                for node in nodes
            ],
            "links": [
                {"id": link.link_id, "src": link.src_id, "dst": link.dst_id, "status": "active" if link.active else "blocked"}
                for link in runtime.topology.links.values()
            ],
            "total_nodes": len(nodes),
            "total_links": len(runtime.topology.links),
        }

    def get_network_metrics(self) -> dict[str, Any]:
        return {"status": "success", "overall": self._require_runtime().metrics(), "per_slice": {}}

    def get_metrics_history(self, last_n: int = 100) -> dict[str, Any]:
        runtime = self._require_runtime()
        rows = [event for event in runtime.events if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}]
        return {"status": "success", "history": rows[-max(0, last_n):]}

    def get_node_metrics(self, node_id: int | None = None) -> dict[str, Any]:
        runtime = self._require_runtime()
        ids = [node_id] if node_id is not None else sorted(runtime.nodes)
        data = {}
        for current in ids:
            if current not in runtime.nodes:
                continue
            node = runtime.nodes[current]
            data[current] = {
                "received": node.received_count,
                "forwarded": node.forwarded_count,
                "drops": node.drop_count,
                "queue_depth": len(node.tx_queue) + len(node.rx_queue) + len(node.forward_queue),
            }
        return {"status": "success", "nodes": data}

    def get_link_metrics(self) -> dict[str, Any]:
        runtime = self._require_runtime()
        return {"status": "success", "links": {key: asdict(value) for key, value in runtime.phy.states.items()}}

    def reset_stats(self) -> None:
        runtime = self._require_runtime()
        runtime._metric_totals = {
            key: 0.0 if key in {"latency_ms_sum", "throughput_mbps_sum"} else 0
            for key in runtime._metric_totals
        }

    def _calculate_rates(self) -> dict[str, Any]:
        return self._require_runtime().metrics()


__all__ = ["SimulationManager"]
