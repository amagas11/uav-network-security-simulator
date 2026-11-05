"""FastAPI surface for deterministic run lifecycle and read-only polling."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
import re
from threading import Event, RLock, Thread, current_thread
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from Manager.simulationmanager import SimulationManager
from swarm_sim import AttackPlan, NormalDisturbancePlan, RunConfig
from swarm_sim.calibration import CalibrationLoader
from swarm_sim.domain import RunState
from swarm_sim.factory import PlatformRuntimeFactory, RuntimeDependencies
from swarm_sim.probe import V8_DEFAULT_PROBE_PROFILE
from swarm_sim.simulation import SCHEMA_VERSION, SOFTWARE_VERSION
from swarm_sim.validation import DatasetValidator


class CreateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    demo_profile: str | None = None
    seed: int = 42
    duration_s: float = Field(10.0, gt=0)
    step_s: float = Field(0.2, gt=0)
    node_count: int = Field(4, ge=2)
    node_roles: dict[int, str] | None = None
    auto_traffic: bool = True
    encrypt_sensitive: bool = False
    queue_capacity: int = Field(32, ge=1)
    tx_service_per_step: int = Field(4, ge=1)
    rx_service_per_step: int = Field(2, ge=1)
    phy_sample_interval_s: float = Field(0.2, gt=0)
    traffic_statistics_window_s: float = Field(1.0, gt=0)
    flooding_packet_rate_threshold_pps: float = Field(8.0, gt=0)
    flooding_detection_enabled: bool = Field(True, strict=True)
    rff_enabled: bool = Field(True, strict=True)
    rff_policy_mode: str = "OBSERVE_ONLY"
    rff_enrollment_samples: int = Field(20, ge=1, strict=True)
    rff_quality_threshold: float = Field(0.45, ge=0, le=1)
    rff_distance_threshold: float = Field(3.0, gt=0)
    rff_min_identity_margin: float = Field(0.5, ge=0)
    rff_queue_pressure_ratio: float = Field(0.60, ge=0, le=1)
    rff_strict_hold_s: float = Field(2.0, gt=0)
    rff_strict_on_rate_alarm: bool = Field(True, strict=True)
    application_layer_available: bool = Field(True, strict=True)
    detection_mode: Literal["APPLICATION_ONLY", "PHYSICAL_ONLY", "COMBINED"] | None = None
    replay_timestamp_freshness_s: float = Field(2.0, gt=0)
    replay_reorder_window_size: int = Field(32, ge=1)
    security_summary_window_s: float = Field(0.5, gt=0)
    decision_step_s: float = Field(0.2, gt=0)
    frequency_hz: float = Field(3.5e9, gt=0)
    bandwidth_hz: float = Field(20e6, gt=0)
    channel_profile_id: str = "uncalibrated-static-a2a-v1"
    traffic_profile_id: str = "formation-default-v1"
    attack_specs: list[dict[str, Any]] = Field(default_factory=list)
    normal_disturbance_specs: list[dict[str, Any]] = Field(default_factory=list)
    traffic_specs: list[dict[str, Any]] = Field(default_factory=list)
    session_lifecycle_specs: list[dict[str, Any]] = Field(default_factory=list)
    episode_phases: dict[str, Any] | None = None
    model_recommendation_confidence_threshold: float = Field(0.8, ge=0, le=1)
    model_recommendation_quality_threshold: float = Field(0.5, ge=0, le=1)
    model_inference_timeout_ms: float = Field(100.0, gt=0, le=60000)
    dataset_maturity: str = "DEVELOPMENT"
    require_formal_security: bool = False
    allow_external_model_observer: bool = False
    calibration_profile_path: str | None = None
    auto_advance: bool = True
    wall_interval_s: float = Field(0.05, gt=0, le=5)


class InitRequest(BaseModel):
    num_uavs: int = Field(10, ge=2)
    seed: int = 42
    duration_s: float = Field(60.0, gt=0)
    step_s: float = Field(0.2, gt=0)


class AttackScheduleRequest(BaseModel):
    attack_family: str
    attack_subtype: str
    scheduled_start_s: float = Field(ge=0)
    impact_start_s: float = Field(ge=0)
    end_s: float = Field(gt=0)
    attacker_node_id: int | None = None
    target_node_ids: list[int] = Field(default_factory=list)
    target_link_ids: list[str] = Field(default_factory=list)
    intensity: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    attack_id: str | None = None


class NormalDisturbanceRequest(BaseModel):
    disturbance_type: str
    start_s: float = Field(ge=0)
    end_s: float = Field(gt=0)
    target_node_ids: list[int] = Field(default_factory=list)
    target_link_ids: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    profile_id: str | None = None


class LegacyAttackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    attack_src: int | None = None
    attack_dst: int | None = None
    fake_src: int | None = None
    malicious_cmd: str | None = None
    malicious_params: dict[str, Any] | None = None
    target_seq: int | None = None
    subtype: str | None = None


class ListenRequest(BaseModel):
    type: str
    duration: float = Field(10.0, gt=0)


class DefenseRequest(BaseModel):
    node_id: int
    action: str
    target_node_id: int | None = None
    target_link_id: str | None = None
    peer_id: int | None = None
    session_id: str | None = None
    reason: str | None = None


class LegacyDefenseRequest(BaseModel):
    node_id: int
    attack_type: str
    enabled: bool


class LegacyDefenseBatchRequest(BaseModel):
    node_id: int
    config: dict[str, bool]


class LegacyDefenseGlobalRequest(BaseModel):
    attack_type: str
    enabled: bool


class ProbeRequest(BaseModel):
    first_id: int
    second_id: int
    sample_count: int = Field(16, ge=2, le=4096)


class SimulationController:
    """Serializes API access; wall time paces but never defines simulation time."""

    def __init__(
        self, runtime_factory: PlatformRuntimeFactory | None = None
    ) -> None:
        self.manager = SimulationManager(runtime_factory=runtime_factory)
        self.lock = RLock()
        self.stop_event = Event()
        self.worker: Thread | None = None
        self.auto_advance = True
        self.wall_interval_s = 0.05

    def _halt_worker(self) -> None:
        self.stop_event.set()
        worker = self.worker
        if worker and worker.is_alive() and worker is not current_thread():
            worker.join(timeout=5.0)
        self.worker = None

    def create(self, request: CreateRunRequest) -> dict[str, Any]:
        if request.demo_profile is not None:
            from swarm_sim.demo_budget import validate_demo_budget
            validate_demo_budget(request.model_dump())
        self._halt_worker()
        data = request.model_dump(
            exclude={"auto_advance", "wall_interval_s", "calibration_profile_path", "demo_profile"}
        )
        calibration_profile = (
            CalibrationLoader.load(request.calibration_profile_path)
            if request.calibration_profile_path
            else None
        )
        with self.lock:
            response = self.manager.create_run(
                RunConfig.from_dict(data), calibration_profile=calibration_profile
            )
            self.auto_advance = request.auto_advance
            self.wall_interval_s = request.wall_interval_s
            self.stop_event = Event()
            return response

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            with self.lock:
                runtime = self.manager.runtime
                if runtime is None or runtime.state in {RunState.STOPPED, RunState.COMPLETED}:
                    return
                if runtime.state == RunState.RUNNING:
                    runtime.step()
            self.stop_event.wait(self.wall_interval_s)

    def _ensure_worker(self) -> None:
        if not self.auto_advance:
            return
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        self.worker = Thread(target=self._loop, name="uav-sim-runner", daemon=True)
        self.worker.start()

    def start(self) -> dict[str, Any]:
        with self.lock:
            result = self.manager.start()
        self._ensure_worker()
        return result

    def pause(self) -> dict[str, Any]:
        with self.lock:
            return self.manager.pause()

    def resume(self) -> dict[str, Any]:
        with self.lock:
            result = self.manager.resume()
        self._ensure_worker()
        return result

    def stop(self) -> dict[str, Any]:
        self._halt_worker()
        with self.lock:
            return self.manager.stop()

    def reset(self) -> dict[str, Any]:
        self._halt_worker()
        with self.lock:
            result = self.manager.reset()
            self.stop_event = Event()
            return result

    def close(self) -> None:
        self._halt_worker()


def build_application_runtime_factory() -> PlatformRuntimeFactory:
    """Build the formal Web/UI runtime with the bundled Person-A adapters.

    Direct ``PlatformRuntime`` and bare ``PlatformRuntimeFactory`` callers keep
    their lightweight test defaults.  Only the application composition root
    selects Person-A, using a path anchored to this source file rather than the
    process working directory.  No test/preloaded session key is configured.
    """

    from swarm_sim.integrations.person_a import PersonASecurityBundleFactory

    platform_root = Path(__file__).resolve().parents[1]
    library_path = (platform_root.parent / "person_a_crypto" / "upstream").resolve()
    if not library_path.is_dir():
        raise RuntimeError(f"PERSON_A_CRYPTO_NOT_AVAILABLE:{library_path}")
    bundle = PersonASecurityBundleFactory(
        library_path,
        probe_profile=V8_DEFAULT_PROBE_PROFILE,
    )
    return PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=bundle)
    )


controller = SimulationController(runtime_factory=build_application_runtime_factory())
sim_manager = controller.manager


def configure_runtime_factory(runtime_factory: PlatformRuntimeFactory) -> None:
    """Programmatic server-startup hook for formal A/C dependencies."""

    controller._halt_worker()
    controller.manager.set_runtime_factory(runtime_factory)


def _runtime():
    try:
        return sim_manager._require_runtime()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    controller.close()


app = FastAPI(
    title="UAV Swarm Security Simulation API",
    version="7.0.0",
    lifespan=lifespan,
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "software_version": SOFTWARE_VERSION,
    }


@app.post("/api/runs", status_code=201)
def create_run(request: CreateRunRequest) -> dict[str, Any]:
    try:
        return controller.create(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/runs/start")
def start_run() -> dict[str, Any]:
    _runtime()
    return controller.start()


@app.post("/api/runs/pause")
def pause_run() -> dict[str, Any]:
    _runtime()
    return controller.pause()


@app.post("/api/runs/resume")
def resume_run() -> dict[str, Any]:
    _runtime()
    return controller.resume()


@app.post("/api/runs/stop")
def stop_run() -> dict[str, Any]:
    _runtime()
    return controller.stop()


@app.post("/api/runs/reset")
def reset_run() -> dict[str, Any]:
    _runtime()
    return controller.reset()


@app.get("/api/runs/status")
def run_status() -> dict[str, Any]:
    with controller.lock:
        return _runtime().status()


@app.get("/api/runs/current")
def current_run() -> dict[str, Any]:
    """Return application reachability and the optional current run.

    Unlike ``/api/runs/status``, this presentation endpoint deliberately
    returns HTTP 200 when no run has been created.  The formal SPA can
    therefore distinguish an idle-but-reachable service from a disconnected
    backend without treating the normal idle state as a request failure.
    """

    with controller.lock:
        runtime = sim_manager.runtime
        return {
            "runtime_available": True,
            "run": runtime.status() if runtime is not None else None,
        }


@app.post("/api/debug/step")
def debug_step() -> dict[str, Any]:
    with controller.lock:
        runtime = _runtime()
        created = runtime.debug_step()
        return {"status": runtime.status(), "events_created": len(created)}


@app.get("/api/runtime")
def runtime_view(cursor: int = Query(0, ge=0)) -> dict[str, Any]:
    with controller.lock:
        runtime = _runtime()
        result = runtime.runtime_view(cursor)
        result["metrics"] = runtime.gcs_metrics()
        result["model_status"] = runtime.model_status()
        # Read-only teaching/presentation data.  This is deliberately scoped
        # as simulator scenario configuration so the UI cannot confuse it
        # with a node-local online detection result.  Keeping it on the
        # current runtime endpoint also lets a refreshed SPA route restore the
        # actual node positions without depending on the legacy topology API.
        result["scenario_topology"] = {
            "scope": "SIMULATOR_SCENARIO_CONFIGURATION",
            "nodes": [
                {
                    "id": node.node_id,
                    "role": node.role.value,
                    "pos": list(node.position_xyz_m),
                    "state": node.flight_state,
                    "position_available": True,
                }
                for node in sorted(
                    runtime.nodes.values(), key=lambda item: item.node_id
                )
            ],
            "links": [
                {
                    "id": link.link_id,
                    "src": link.src_id,
                    "dst": link.dst_id,
                    "status": "active" if link.active else "blocked",
                }
                for link in sorted(
                    runtime.topology.links.values(), key=lambda item: item.link_id
                )
            ],
            "total_nodes": len(runtime.nodes),
            "total_links": len(runtime.topology.links),
        }
        return result


@app.get("/api/evaluation")
def evaluation_view() -> dict[str, Any]:
    with controller.lock:
        return _runtime().evaluation_view()


@app.get("/api/gcs/topology")
def gcs_topology() -> dict[str, Any]:
    with controller.lock:
        return _runtime().topology_view(truth=False)


@app.get("/api/models/status")
def model_status() -> dict[str, Any]:
    with controller.lock:
        return {
            "schema_version": SCHEMA_VERSION,
            "software_version": _runtime().config.software_version,
            "models": _runtime().model_status(),
        }


@app.get("/api/observations/{node_id}")
def node_observation(node_id: int) -> dict[str, Any]:
    with controller.lock:
        try:
            return _runtime().observation(node_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/probes")
def create_probe(request: ProbeRequest) -> dict[str, Any]:
    with controller.lock:
        first, second = _runtime().probes.probe(
            request.first_id, request.second_id, sample_count=request.sample_count
        )
        return {"first": first.to_dict(), "second": second.to_dict()}


@app.post("/api/attacks/schedule", status_code=201)
def schedule_attack(request: AttackScheduleRequest) -> dict[str, Any]:
    with controller.lock:
        try:
            return _runtime().schedule_attack(AttackPlan(**request.model_dump()))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/normal-disturbances/schedule", status_code=201)
def schedule_normal_disturbance(
    request: NormalDisturbanceRequest,
) -> dict[str, Any]:
    with controller.lock:
        try:
            return _runtime().schedule_normal_disturbance(
                NormalDisturbancePlan(**request.model_dump())
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/rl/observations/{node_id}")
def rl_observation(node_id: int) -> dict[str, Any]:
    with controller.lock:
        try:
            return _runtime().rl_observation(node_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/defense/actions")
def execute_defense(request: DefenseRequest) -> dict[str, Any]:
    with controller.lock:
        try:
            return _runtime().request_defense(**request.model_dump())
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/datasets/export")
def export_dataset(name: str = Query("latest", pattern=r"^[A-Za-z0-9._-]+$")) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise HTTPException(status_code=422, detail="invalid dataset name")
    root = Path.cwd() / "outputs" / name
    with controller.lock:
        export = _runtime().export_dataset(root)
        validation = DatasetValidator().validate(root).to_dict()
        return {"export": export, "validation": validation}


# ---- Original API compatibility surface ---------------------------------


@app.post("/api/init")
def legacy_init(request: InitRequest) -> dict[str, Any]:
    result = controller.create(
        CreateRunRequest(
            node_count=request.num_uavs,
            seed=request.seed,
            duration_s=request.duration_s,
            step_s=request.step_s,
            auto_advance=False,
        )
    )
    return {**result, "status": "initialized"}


@app.get("/api/step")
def legacy_step() -> dict[str, Any]:
    with controller.lock:
        return sim_manager.step()


@app.post("/api/attack")
def legacy_attack(request: LegacyAttackRequest) -> dict[str, Any]:
    params = request.model_dump(exclude={"type"}, exclude_none=True)
    with controller.lock:
        try:
            return sim_manager.inject_attack(request.type, params)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/listen/start")
def legacy_listen_start(request: ListenRequest) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.start_listening(request.type, request.duration)


@app.post("/api/listen/stop")
def legacy_listen_stop(request: ListenRequest) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.stop_listening(request.type)


@app.get("/api/listen/data/{attack_type}")
def legacy_listen_data(attack_type: str) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_captured_data(attack_type)


@app.get("/api/topology")
def legacy_topology() -> dict[str, Any]:
    with controller.lock:
        return {
            "status": "success",
            "scope": "LEGACY_SIMULATOR_DEBUG_VIEW",
            "deprecated": "Use /api/gcs/topology for node-local knowledge.",
            **sim_manager._legacy_topology(),
        }


@app.get("/api/commands")
def command_templates() -> dict[str, Any]:
    return {
        "status": "success",
        "commands": {
            "TAKEOFF": {"desc": "起飞", "params": {"altitude_m": {"type": "number", "range": [10, 500]} }},
            "LAND": {"desc": "降落", "params": {"altitude_m": {"type": "number", "range": [0, 100]} }},
            "HOVER": {"desc": "悬停", "params": {}},
            "FLY_TO": {"desc": "飞往坐标", "params": {"position_xyz_m": {"type": "array"}}},
            "VIDEO_STREAM": {"desc": "视频流控制", "params": {"action": {"type": "string"}}},
        },
    }


@app.get("/api/stats")
def legacy_stats() -> dict[str, Any]:
    with controller.lock:
        stats = sim_manager.stats
        total = stats["total_pkts"]
        losses = stats["phy_loss"] + stats["defense_drops"]
        return {
            "status": "success",
            **stats,
            "packet_loss": {
                "phy_loss_count": stats["phy_loss"],
                "defense_drop_count": stats["defense_drops"],
                "total_loss_count": losses,
                "total_loss_rate_pct": round(losses / max(1, total) * 100, 2),
                "delivery_rate_pct": round(max(0, total - losses) / max(1, total) * 100, 2),
            },
            "metrics": _runtime().metrics(),
        }


@app.get("/api/metrics/packet_loss")
def packet_loss() -> dict[str, Any]:
    result = legacy_stats()
    return {"status": "success", "data": result["packet_loss"]}


@app.get("/api/metrics/summary")
def metrics_summary() -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_network_metrics()


@app.get("/api/metrics/history")
def metrics_history(last_n: int = Query(100, ge=0, le=10000)) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_metrics_history(last_n)


@app.get("/api/metrics/node")
def metrics_nodes() -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_node_metrics()


@app.get("/api/metrics/node/{node_id}")
def metrics_node(node_id: int) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_node_metrics(node_id)


@app.get("/api/metrics/links")
def metrics_links() -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_link_metrics()


@app.post("/api/defense/config")
def legacy_defense(request: LegacyDefenseRequest) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.configure_defense(request.node_id, request.attack_type, request.enabled)


@app.post("/api/defense/config/batch")
def legacy_defense_batch(request: LegacyDefenseBatchRequest) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.configure_defense_batch(request.node_id, request.config)


@app.post("/api/defense/config/global")
def legacy_defense_global(request: LegacyDefenseGlobalRequest) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.configure_defense_global(request.attack_type, request.enabled)


@app.get("/api/defense/status")
def legacy_defense_status(node_id: int | None = None) -> dict[str, Any]:
    with controller.lock:
        return sim_manager.get_defense_status(node_id)


@app.post("/api/stats/reset")
def legacy_reset_stats() -> dict[str, str]:
    with controller.lock:
        sim_manager.reset_stats()
    return {"status": "success", "msg": "统计已重置"}
