"""V7 runtime factory, reset, RL injection, provenance and readiness gates."""

from __future__ import annotations

import time
from typing import Any

from Manager.simulationmanager import SimulationManager
from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.adapters import ModelResult
from swarm_sim.adapters import MockKeyProvider, TestOnlyAeadCryptoProvider
from swarm_sim.calibration import BaselineCalibrationFitter, CalibrationLoader
from swarm_sim.factory import PlatformRuntimeFactory, RuntimeDependencies
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.terminal import TerminalAuthorizer
from tests.acceptance.test_v7_calibration_runtime import _dataset
from tools.run_experiment import run_batch


class FixtureModel:
    accepted_event_types = frozenset({"NODE_STATE"})

    def __init__(self, slot: str, *, emit: bool = False, block: bool = False) -> None:
        self.slot = slot
        self.name = f"{slot}-v7-fixture"
        self.model_version = "9.9"
        self.emit = emit
        self.block = block
        self.emitted = False

    def reset(self, run_info: dict[str, Any]) -> None:
        del run_info
        self.emitted = False

    def health(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "model_version": self.model_version,
            "status": "OK",
            "implementation_status": "FORMAL",
            "bundle_hash": "f" * 64,
        }

    def observe(self, event: dict[str, Any]) -> list[ModelResult]:
        if self.block:
            time.sleep(1.0)
        if not self.emit or self.emitted or event["observer_node_id"] != 1:
            return []
        self.emitted = True
        predicted = "UNKNOWN" if self.slot == "rff" else "FDI"
        return [
            ModelResult(
                schema_version=SCHEMA_VERSION,
                run_id=event["run_id"],
                result_id=f"{self.slot}-fixture-result",
                observer_node_id=1,
                decision_time_s=event["sim_time_s"],
                model_name=self.name,
                model_version=self.model_version,
                status="OK",
                predicted_label=predicted,
                scores={predicted: 0.99},
                confidence=0.99,
                quality=0.95,
                recommended_action=None,
                evidence_event_ids=[event["event_id"]],
                inference_time_ms=0.1,
                error_code=None,
            )
        ]


def _factory(*, emit: bool = False) -> PlatformRuntimeFactory:
    return PlatformRuntimeFactory(
        RuntimeDependencies(
            model_adapter_factories={
                "bilstm": lambda _config: FixtureModel("bilstm", emit=emit),
                "rff": lambda _config: FixtureModel("rff", emit=emit),
            }
        )
    )


def test_manager_reset_preserves_calibration_and_factory_but_freshens_state():
    profile = BaselineCalibrationFitter().fit(
        _dataset("low", rssi_dbm=-70, snr_db=15, loss_ratio=0.1, latency_ms=20)
    )
    manager = SimulationManager(runtime_factory=_factory())
    manager.create_run(
        RunConfig(seed=7710, duration_s=0.4, auto_traffic=False),
        calibration_profile=profile,
    )
    assert manager.runtime is not None
    old_id = manager.runtime.run_id
    manager.runtime.start()
    manager.runtime.step()
    assert manager.runtime.events

    manager.reset()
    assert manager.runtime is not None
    record = manager.runtime.run_record()
    assert manager.runtime.run_id != old_id
    assert record["calibration_profile"]["profile_hash"] == profile.profile_hash
    assert record["model_assets"]["bilstm"]["model_version"] == "9.9"
    assert manager.runtime.context.clock.now_s == 0.0
    assert not manager.runtime.attack_scheduler.records


def test_factory_is_used_by_batch_and_rl_and_zero_result_model_is_provenanced(tmp_path):
    factory = _factory(emit=False)
    summary = run_batch(
        tmp_path / "batch",
        seeds=[7711],
        duration_s=0.4,
        run_config={"auto_traffic": True},
        runtime_factory=factory,
    )
    assert summary["all_valid"]
    run = summary["runs"][0]["run_record"]
    assert run["model_assets"]["bilstm"]["configured"] is True
    assert run["model_assets"]["bilstm"]["model_version"] == "9.9"

    env = UavDefenseEnv(observer_node_id=1, runtime_factory=_factory(emit=True))
    observation = env.reset(7711, {"duration_s": 0.4, "auto_traffic": False})
    assert observation["model"]["bilstm"]["status"] == "OK"
    assert observation["model"]["bilstm"]["scores"]["FDI"] == 0.99
    assert observation["security"]["rff_anomaly_count"] > 0


def test_final_experiment_readiness_reports_missing_c_model_blockers():
    runtime = PlatformRuntime(RunConfig(duration_s=0.2, auto_traffic=False))
    record = runtime.run_record()
    assert record["readiness_components"]["b_platform_software"] == "READY"
    assert record["dataset_readiness"] == "READY_FOR_C_DEVELOPMENT"
    assert record["experiment_readiness"] == "BLOCKED_EXTERNAL"
    assert "C_BILSTM_NOT_CONFIGURED" in record["readiness_blockers"]
    assert "C_DUELING_Q_NOT_CONFIGURED" in record["readiness_blockers"]
    assert "C_RFF_NOT_CONFIGURED" in record["readiness_blockers"]


class FormalKeyFixture(MockKeyProvider):
    implementation_status = "FORMAL"


class FormalCryptoFixture(TestOnlyAeadCryptoProvider):
    implementation_status = "FORMAL"


class FormalTerminalFixture(TerminalAuthorizer):
    implementation_status = "FORMAL"


def _approved_profile():
    dataset = _dataset(
        "high", rssi_dbm=-70, snr_db=15, loss_ratio=0.1, latency_ms=20
    )
    dataset.maturity = "APPROVED"
    dataset.manifest.source_kind = "real_measurement"
    return BaselineCalibrationFitter().fit(dataset)


def _formal_security_dependencies(**kwargs):
    return RuntimeDependencies(
        key_provider_factory=lambda config: FormalKeyFixture(config.seed),
        crypto_provider_factory=lambda _config, key: FormalCryptoFixture(key),
        terminal_authorizer_factory=lambda _config: FormalTerminalFixture(),
        **kwargs,
    )


def test_readiness_can_be_ready_only_when_all_formal_asset_slots_are_ready():
    profile = _approved_profile()
    dependencies = _formal_security_dependencies(
        model_adapter_factories={
            slot: (lambda config, slot=slot: FixtureModel(slot))
            for slot in ("bilstm", "dueling_q", "rff")
        },
    )
    runtime = PlatformRuntimeFactory(dependencies).create(
        RunConfig(
            duration_s=0.2,
            auto_traffic=False,
            dataset_maturity="FORMAL",
        ),
        calibration_profile=profile,
    )
    record = runtime.run_record()
    assert record["experiment_readiness"] == "READY"
    assert record["readiness_blockers"] == []
    assert all(
        value == "READY" for value in record["readiness_components"].values()
    )


def test_formal_security_and_calibration_without_c_models_remains_blocked():
    runtime = PlatformRuntimeFactory(_formal_security_dependencies()).create(
        RunConfig(
            duration_s=0.2,
            auto_traffic=False,
            dataset_maturity="FORMAL",
        ),
        calibration_profile=_approved_profile(),
    )
    record = runtime.run_record()
    assert record["readiness_components"]["security_provider_assets"] == "READY"
    assert record["readiness_components"]["calibration_data"] == "READY"
    assert record["dataset_readiness"] == "READY_FOR_C"
    assert record["experiment_readiness"] == "BLOCKED_EXTERNAL"
    assert set(record["readiness_blockers"]) == {
        "C_BILSTM_NOT_CONFIGURED",
        "C_DUELING_Q_NOT_CONFIGURED",
        "C_RFF_NOT_CONFIGURED",
    }


def test_api_manager_calibrated_reset_preserves_profile(tmp_path):
    from fastapi.testclient import TestClient
    from app.app import app, controller

    profile = BaselineCalibrationFitter().fit(
        _dataset("low", rssi_dbm=-70, snr_db=15, loss_ratio=0.1, latency_ms=20)
    )
    profile_path = tmp_path / "profile.json"
    CalibrationLoader.save(profile, profile_path)
    with TestClient(app) as client:
        created = client.post(
            "/api/runs",
            json={
                "seed": 7712,
                "duration_s": 0.4,
                "auto_traffic": False,
                "auto_advance": False,
                "calibration_profile_path": str(profile_path),
            },
        )
        assert created.status_code == 201
        assert controller.manager.runtime is not None
        old_id = controller.manager.runtime.run_id
        reset = client.post("/api/runs/reset")
        assert reset.status_code == 200
        assert controller.manager.runtime is not None
        assert controller.manager.runtime.run_id != old_id
        assert (
            controller.manager.runtime.run_record()["calibration_profile"][
                "profile_hash"
            ]
            == profile.profile_hash
        )


def test_timeout_capacity_is_scoped_to_run_and_does_not_poison_next_runtime():
    bad_factory = PlatformRuntimeFactory(
        RuntimeDependencies(
            model_adapter_factories={
                "bilstm": lambda _config: FixtureModel("bilstm", block=True)
            }
        )
    )
    for index in range(10):
        bad = bad_factory.create(
            RunConfig(
                seed=index,
                duration_s=0.2,
                auto_traffic=False,
                model_inference_timeout_ms=2,
            )
        )
        bad.run_to_completion()
        assert bad.model_status()["bilstm"]["error_code"] in {
            "MODEL_INFERENCE_TIMEOUT",
            "MODEL_RESET_TIMEOUT",
        }

    healthy = _factory().create(
        RunConfig(duration_s=0.2, auto_traffic=False, model_inference_timeout_ms=50)
    )
    healthy.run_to_completion()
    assert healthy.model_status()["bilstm"]["status"] == "OK"
    assert healthy.model_status()["bilstm"].get("error_code") != "MODEL_RUNTIME_SATURATED"


def test_run_level_model_provenance_covers_unavailable_and_timeout_states():
    unavailable = PlatformRuntime(
        RunConfig(duration_s=0.2, auto_traffic=False)
    ).run_record()["model_assets"]["bilstm"]
    assert unavailable["configured"] is False
    assert unavailable["status_at_export"] == "UNAVAILABLE"
    assert unavailable["error_code"] == "MODEL_NOT_CONFIGURED"

    timeout = PlatformRuntimeFactory(
        RuntimeDependencies(
            model_adapter_factories={
                "bilstm": lambda _config: FixtureModel("bilstm", block=True)
            }
        )
    ).create(
        RunConfig(
            duration_s=0.2,
            auto_traffic=False,
            model_inference_timeout_ms=2,
        )
    )
    timeout.run_to_completion()
    provenance = timeout.run_record()["model_assets"]["bilstm"]
    assert provenance["configured"] is True
    assert provenance["model_name"] == "bilstm-v7-fixture"
    assert provenance["model_version"] == "9.9"
    assert provenance["status_at_export"] == "ERROR"
    assert provenance["error_code"] == "MODEL_INFERENCE_TIMEOUT"


def test_same_factory_produces_consistent_fresh_model_metadata_across_entrypoints(
    tmp_path,
):
    created: list[FixtureModel] = []
    created_keys: list[MockKeyProvider] = []

    def make_bilstm(_config):
        model = FixtureModel("bilstm")
        created.append(model)
        return model

    def make_key(config):
        provider = MockKeyProvider(config.seed)
        created_keys.append(provider)
        return provider

    factory = PlatformRuntimeFactory(
        RuntimeDependencies(
            key_provider_factory=make_key,
            crypto_provider_factory=lambda _config, key: TestOnlyAeadCryptoProvider(
                key
            ),
            model_adapter_factories={"bilstm": make_bilstm},
        )
    )
    config = RunConfig(seed=7713, duration_s=0.4, auto_traffic=True)
    direct = factory.create(config)
    direct_record = direct.run_record()

    manager = SimulationManager(runtime_factory=factory)
    manager.create_run(config)
    assert manager.runtime is not None
    manager_record = manager.runtime.run_record()

    batch = run_batch(
        tmp_path / "factory-batch",
        seeds=[7713],
        duration_s=0.4,
        run_config={"auto_traffic": True},
        runtime_factory=factory,
    )
    batch_record = batch["runs"][0]["run_record"]

    env = UavDefenseEnv(runtime_factory=factory)
    env.reset(7713, {"duration_s": 0.4, "auto_traffic": True})
    assert env.episode is not None
    rl_record = env.episode.runtime.run_record()

    records = (direct_record, manager_record, batch_record, rl_record)
    assert {
        (
            item["model_assets"]["bilstm"]["model_name"],
            item["model_assets"]["bilstm"]["model_version"],
        )
        for item in records
    } == {("bilstm-v7-fixture", "9.9")}
    assert {
        (
            item["security_providers"]["key_provider"]["name"],
            item["security_providers"]["crypto_provider"]["name"],
        )
        for item in records
    } == {("MockKeyProvider", "TestOnlyAeadCryptoProvider")}
    assert len({id(item) for item in created}) == 4
    assert len({id(item) for item in created_keys}) == 4
    direct.stop()
    manager.runtime.stop()
    env.episode.runtime.stop()


def test_fastapi_server_controller_uses_programmatic_runtime_factory():
    from app.app import CreateRunRequest, SimulationController

    local = SimulationController(runtime_factory=_factory())
    try:
        response = local.create(
            CreateRunRequest(
                seed=7714,
                duration_s=0.2,
                auto_traffic=False,
                auto_advance=False,
            )
        )
        assert response["status"] == "success"
        assert local.manager.runtime is not None
        assert (
            local.manager.runtime.run_record()["model_assets"]["bilstm"][
                "model_version"
            ]
            == "9.9"
        )
    finally:
        local.close()


def test_rl_reset_constructs_fresh_stateful_model_instances_per_episode():
    created: list[FixtureModel] = []

    def build(_config):
        model = FixtureModel("bilstm", emit=True)
        created.append(model)
        return model

    env = UavDefenseEnv(
        runtime_factory=PlatformRuntimeFactory(
            RuntimeDependencies(model_adapter_factories={"bilstm": build})
        )
    )
    first = env.reset(7715, {"duration_s": 0.2, "auto_traffic": False})
    first_runtime = env.episode.runtime
    second = env.reset(7715, {"duration_s": 0.2, "auto_traffic": False})
    assert len(created) == 2
    assert created[0] is not created[1]
    assert first["model"]["bilstm"]["scores"] == second["model"]["bilstm"]["scores"]
    first_runtime.close()
    env.episode.runtime.close()
