"""Dueling-Q-facing environment contract; no reward weights are embedded."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


RECOMMENDATION_TO_ACTION = {
    "NO_CHANGE": "NO_CHANGE",
    "INCREASE_MONITORING": "INCREASE_MONITORING",
    "RECOMMEND_RATE_LIMIT": "RATE_LIMIT",
    "RECOMMEND_CHANNEL_SWITCH": "CHANNEL_SWITCH",
    "RECOMMEND_DATA_ISOLATION": "DATA_ISOLATION",
    "RECOMMEND_REAUTH_REKEY": "REAUTH_REKEY_REQUEST",
}


@dataclass(slots=True)
class RLEpisode:
    runtime: Any
    observer_node_id: int
    plan_fingerprint: str

    @property
    def current_phase(self) -> str:
        return self.runtime.episode_phase()


class UavDefenseEnv:
    def __init__(self, observer_node_id: int = 1, runtime_factory: Any | None = None) -> None:
        from .factory import PlatformRuntimeFactory

        self.observer_node_id = observer_node_id
        self.runtime_factory = runtime_factory or PlatformRuntimeFactory()
        self.episode: RLEpisode | None = None
        self.episode_index = 0

    def reset(
        self, seed: int, run_config: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        from .calibration import CalibrationLoader
        from .simulation import RunConfig

        config_dict = dict(run_config or {})
        calibration_profile_path = config_dict.pop("calibration_profile_path", None)
        calibration_profile = (
            CalibrationLoader.load(calibration_profile_path)
            if calibration_profile_path is not None
            else None
        )
        config_dict["seed"] = seed
        config = RunConfig.from_dict(config_dict)
        if self.episode is not None:
            self.episode.runtime.close()
        self.episode_index += 1
        runtime = self.runtime_factory.create(
            config, calibration_profile=calibration_profile
        )
        runtime.start()
        self.episode = RLEpisode(
            runtime,
            self.observer_node_id,
            runtime.run_record()["config_fingerprint"],
        )
        return runtime.rl_observation(self.observer_node_id)

    def step(
        self, action_request: str | dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        if self.episode is None:
            raise RuntimeError("reset must be called before step")
        request = (
            {"action": action_request}
            if isinstance(action_request, str)
            else dict(action_request)
        )
        runtime = self.episode.runtime
        baseline = runtime.capture_action_baseline(self.observer_node_id)
        recommendation = str(request.get("action", "NO_CHANGE")).upper()
        executed_action = RECOMMENDATION_TO_ACTION.get(recommendation)
        if recommendation not in RECOMMENDATION_TO_ACTION:
            outcome = {
                "allowed": False,
                "executed": False,
                "target": None,
                "execution_time_s": None,
                "failure_reason": "UNKNOWN_RECOMMENDATION",
                "attack_impact": None,
                "malicious_traffic_blocked": None,
                "legitimate_traffic_harmed": None,
                "time_to_action_s": None,
                "throughput_mbps": None,
                "latency_ms": None,
                "mission_impact": None,
                "communication_overhead_bytes": None,
                "communication_overhead": None,
                "compute_overhead_ms": None,
                "availability": {
                    "throughput_mbps": False,
                    "latency_ms": False,
                    "missing_reason": "UNKNOWN_RECOMMENDATION",
                },
            }
        else:
            evidence = runtime.select_recommendation_evidence(
                self.observer_node_id, recommendation
            )
            result = runtime.process_action_recommendation(
                source="RL_TRAINING_AGENT",
                observer_node_id=self.observer_node_id,
                recommended_action=recommendation,
                evidence_event_ids=(
                    [evidence["event_id"]] if evidence is not None else []
                ),
                confidence=float(request.get("confidence", 1.0)),
                quality=float(request.get("quality", 1.0)),
                predicted_label=request.get("predicted_label"),
                target_hint={
                    key: request.get(key)
                    for key in (
                        "target_node_id",
                        "target_link_id",
                        "peer_id",
                        "session_id",
                    )
                    if request.get(key) is not None
                },
            )
            outcome = {
                "allowed": result["allowed"],
                "executed": result["executed"],
                "target": result["target"],
                "execution_time_s": result["executed_time_s"],
                "failure_reason": result["failure_reason"],
                "decision_reason": result.get("decision_reason"),
                **result["outcome"],
            }
        target_time_s = min(
            runtime.config.duration_s,
            runtime.context.clock.now_s + runtime.config.decision_step_s,
        )
        while (
            runtime.context.clock.now_s < target_time_s - 1e-12
            and not runtime.is_terminated
        ):
            runtime.debug_step()
        envelope = {
            "outcome": outcome,
            "request": {
                "action": executed_action or recommendation,
                "reason": "RL_RECOMMENDATION",
            },
            "allowed": outcome["allowed"],
            "executed": outcome["executed"],
            "executed_time_s": outcome["execution_time_s"],
            "target": outcome["target"],
            "failure_reason": outcome["failure_reason"],
        }
        runtime.complete_action_outcome(
            envelope, self.observer_node_id, baseline
        )
        outcome = envelope["outcome"]
        terminated = runtime.is_terminated
        return runtime.rl_observation(self.observer_node_id), outcome, terminated
