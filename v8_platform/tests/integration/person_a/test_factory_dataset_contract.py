from __future__ import annotations

from pathlib import Path

import pytest

from Manager.simulationmanager import SimulationManager
from app.app import CreateRunRequest, SimulationController
from swarm_sim import (
    PlatformRuntime,
    PlatformRuntimeFactory,
    RunConfig,
    RuntimeDependencies,
)
from swarm_sim.integrations.person_a import (
    PersonACryptoNotAvailable,
    PersonASecurityBundleFactory,
)
from swarm_sim.leakage import DatasetLeakageAudit
from swarm_sim.rl import UavDefenseEnv
from swarm_sim.validation import DatasetValidator
from tools.run_experiment import run_batch

from .test_aead_and_skg import SESSION, _factory, _runtime


def test_a24_dataset_validator_and_standard_leakage_audit_pass(person_a_root, tmp_path):
    runtime = _runtime(person_a_root, preload=True, duration_s=1.0)
    runtime.queue_message(
        1, 2, "STATUS", {"value": 4}, sensitive=True, session_id=SESSION
    )
    runtime.run_to_completion()
    output = tmp_path / "person-a-dataset"
    runtime.export_dataset(output)
    validation = DatasetValidator().validate(output)
    leakage = DatasetLeakageAudit.audit_events(runtime.events)
    assert validation.valid, validation.errors
    assert leakage.passed, leakage.errors


def test_a27_same_factory_works_for_direct_manager_api_batch_and_rl(person_a_root, tmp_path):
    factory = _factory(person_a_root)
    config = RunConfig(seed=8101, duration_s=0.3, step_s=0.1, auto_traffic=False)

    direct = factory.create(config)
    manager = SimulationManager(runtime_factory=factory)
    manager.create_run(config)
    assert manager.runtime is not None

    controller = SimulationController(runtime_factory=factory)
    try:
        controller.create(
            CreateRunRequest(
                seed=8101,
                duration_s=0.3,
                step_s=0.1,
                node_count=4,
                auto_traffic=False,
                auto_advance=False,
            )
        )
        assert controller.manager.runtime is not None

        batch = run_batch(
            tmp_path / "batch",
            seeds=[8101],
            duration_s=1.2,
            step_s=0.1,
            run_config={"auto_traffic": True},
            runtime_factory=factory,
        )
        assert batch["all_valid"]
        assert (
            batch["runs"][0]["run_record"]["security_providers"][
                "crypto_provider"
            ]["name"]
            == "PersonACryptoProvider"
        )

        env = UavDefenseEnv(runtime_factory=factory)
        env.reset(8101, {"duration_s": 0.3, "step_s": 0.1, "auto_traffic": False})
        assert env.episode is not None

        runtimes = [
            direct,
            manager.runtime,
            controller.manager.runtime,
            env.episode.runtime,
        ]
        assert all(item.security_coordinator is not None for item in runtimes)
        assert len({id(item.security_coordinator) for item in runtimes}) == len(runtimes)
        assert {
            item.run_record()["security_providers"]["crypto_provider"]["name"]
            for item in runtimes
        } == {"PersonACryptoProvider"}
    finally:
        direct.close()
        if manager.runtime:
            manager.runtime.close()
        controller.close()


def test_a26_manager_reset_builds_fresh_person_a_state(person_a_root):
    manager = SimulationManager(runtime_factory=_factory(person_a_root))
    manager.create_run(
        RunConfig(seed=8102, duration_s=0.6, step_s=0.1, auto_traffic=False)
    )
    first = manager.runtime
    assert first is not None
    first.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
    assert first.security_coordinator.handshakes
    first_id = first.run_id
    manager.reset()
    second = manager.runtime
    assert second is not None
    assert second.run_id != first_id
    assert second.security_coordinator is not first.security_coordinator
    assert second.security_coordinator.handshakes == {}
    assert second.context.clock.now_s == 0.0


def test_a26_api_controller_reset_builds_fresh_person_a_state(person_a_root):
    controller = SimulationController(runtime_factory=_factory(person_a_root))
    try:
        controller.create(
            CreateRunRequest(
                seed=8103,
                duration_s=0.6,
                step_s=0.1,
                node_count=4,
                auto_traffic=False,
                auto_advance=False,
            )
        )
        first = controller.manager.runtime
        assert first is not None
        first.security_coordinator.initiate_session(1, 2, SESSION, key_epoch=1)
        assert first.security_coordinator.handshakes
        controller.reset()
        second = controller.manager.runtime
        assert second is not None
        assert second.run_id != first.run_id
        assert second.security_coordinator is not first.security_coordinator
        assert second.security_coordinator.handshakes == {}
        assert second.context.clock.now_s == 0.0
    finally:
        controller.close()


def test_a26_direct_runtime_reset_also_builds_fresh_person_a_state(person_a_root):
    runtime = _runtime(person_a_root)
    original = runtime.security_coordinator
    original.initiate_session(1, 2, SESSION, key_epoch=1)
    old_run_id = runtime.run_id
    runtime.reset()
    assert runtime.run_id != old_run_id
    assert runtime.security_coordinator is not original
    assert runtime.security_coordinator.handshakes == {}


def test_person_a_nonformal_provenance_is_present_and_blocks_formal_maturity(person_a_root):
    runtime = _runtime(person_a_root)
    run = runtime.run_record()
    providers = run["security_providers"]
    assert providers["key_provider"] == {
        "name": "PersonAKeyCoordinator",
        "version": (
            "person-a-0.1+v8-adapter-1.2+skg-v8-network-2pc+rollback+identity-"
            "ed25519-test-only-generated-identity"
        ),
        "status": "PERSON_A_INTEGRATED_DEVELOPMENT",
    }
    assert providers["crypto_provider"]["version"].endswith("AES-256-GCM")
    assert providers["terminal_credential_provider"]["status"] == "PERSON_A_INTEGRATED_DEVELOPMENT"
    assert run["security_provider_maturity"] == "TEST"
    assert run["experiment_readiness"] == "BLOCKED_EXTERNAL"


def test_person_a_mode_missing_package_fails_explicitly_but_default_mode_survives(tmp_path):
    factory = _factory(tmp_path / "missing-person-a")
    with pytest.raises(PersonACryptoNotAvailable, match="PERSON_A_CRYPTO_NOT_AVAILABLE"):
        factory.create(RunConfig(duration_s=0.2, auto_traffic=False))
    default = PlatformRuntime(RunConfig(duration_s=0.2, auto_traffic=False))
    default.run_to_completion()
    assert default.state.value == "COMPLETED"


def test_upstream_test_vectors_are_not_loaded_by_runtime(person_a_root):
    runtime = _runtime(person_a_root)
    assert runtime.security_coordinator is not None
    assert all("test_vectors" not in name for name in __import__("sys").modules)


def test_integration_source_never_reads_person_a_private_key_record(person_a_root):
    del person_a_root
    source = (
        Path(__file__).resolve().parents[3]
        / "swarm_sim"
        / "integrations"
        / "person_a"
        / "bridge.py"
    ).read_text(encoding="utf-8")
    assert "_KeyRecord" not in source
    assert ".material" not in source
    assert "._key_material" not in source
    assert "synthesize_reciprocal_rssi" not in source
    assert "synthesize_eve_rssi" not in source


def test_formal_identity_and_credential_assets_have_programmatic_factory_boundary(
    person_a_root,
):
    identity_calls = []
    credential_calls = []

    def identity_factory(library, node_id, config):
        identity_calls.append((node_id, config.seed))
        return library.identity.IdentityStore.generate(
            node_id, f"injected-test-identity-{node_id}"
        )

    def credential_factory(library, config):
        credential_calls.append(config.seed)
        return library.credentials.CredentialService(b"c" * 32)

    bundle = PersonASecurityBundleFactory(
        person_a_root,
        identity_store_factory=identity_factory,
        credential_service_factory=credential_factory,
        identity_mode="Ed25519_INJECTED_TEST_IDENTITY",
        credential_mode="INJECTED_TEST_CREDENTIAL_SERVICE",
    )
    runtime = PlatformRuntimeFactory(
        RuntimeDependencies(security_bundle_factory=bundle)
    ).create(RunConfig(seed=8110, duration_s=0.2, auto_traffic=False))
    assert sorted(identity_calls) == [(0, 8110), (1, 8110), (2, 8110), (3, 8110)]
    assert credential_calls == [8110]
    providers = runtime.run_record()["security_providers"]
    assert "injected-test-identity" in providers["key_provider"]["version"]
    assert "injected-test-credential-service" in providers[
        "terminal_credential_provider"
    ]["version"]
