from copy import deepcopy
import json

import pytest

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.dataset import schema_v1
from swarm_sim.validation import DatasetValidator


MODES = {
    "APPLICATION_ONLY": (True, False, "OBSERVE_ONLY"),
    "PHYSICAL_ONLY": (False, True, "ENFORCE"),
    "COMBINED": (True, True, "ENFORCE"),
}


@pytest.mark.parametrize("mode,flags", MODES.items())
def test_named_mode_resolves_all_switches_and_roundtrips(mode, flags):
    config = RunConfig(detection_mode=mode)
    assert (config.application_layer_available, config.rff_enabled, config.rff_policy_mode) == flags
    assert RunConfig.from_dict(config.to_dict()).to_dict() == config.to_dict()
    assert config.effective_detection_mode == mode
    assert config.semantic_fingerprint() == RunConfig(
        application_layer_available=flags[0], rff_enabled=flags[1], rff_policy_mode=flags[2],
    ).semantic_fingerprint()


@pytest.mark.parametrize("mode", ["", "INVALID", True, 1, [], {}])
def test_invalid_mode_fails_cleanly(mode):
    with pytest.raises(ValueError, match="detection_mode"):
        RunConfig(detection_mode=mode)


def test_mode_preset_has_priority_over_legacy_flags():
    config = RunConfig(detection_mode="PHYSICAL_ONLY", application_layer_available=True,
                       rff_enabled=False, rff_policy_mode="OBSERVE_ONLY")
    assert not config.application_layer_available
    assert config.rff_enabled and config.rff_policy_mode == "ENFORCE"


def test_no_mode_preserves_default_observation_and_custom_switches():
    config = RunConfig()
    assert config.detection_mode is None
    assert config.effective_detection_mode == "CUSTOM"
    assert config.application_layer_available and config.rff_enabled
    assert config.rff_policy_mode == "OBSERVE_ONLY"
    custom = RunConfig(application_layer_available=False, rff_enabled=False)
    assert custom.effective_detection_mode == "CUSTOM"
    assert not custom.application_layer_available and not custom.rff_enabled


@pytest.mark.parametrize("mode", MODES)
def test_runtime_records_effective_business_and_management_detection_scopes(mode):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False, detection_mode=mode))
    metadata = runtime.run_record()["detection_configuration"]
    assert metadata["mode"] == mode
    assert metadata["requested_mode"] == mode
    assert metadata["application_hmac"]["enabled"] is (mode != "PHYSICAL_ONLY")
    assert metadata["replay_protection"]["enabled"] is (mode != "PHYSICAL_ONLY")
    assert metadata["flooding"]["enabled"] is (mode != "PHYSICAL_ONLY")
    assert metadata["management_authentication"]["enabled"] is True
    assert metadata["rff"]["enforcing"] is (mode != "APPLICATION_ONLY")
    assert runtime.evaluation_view()["detection_configuration"] == metadata


@pytest.mark.parametrize("mode", MODES)
def test_mode_dataset_and_pre_mode_contract_are_both_valid(tmp_path, mode):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, detection_mode=mode))
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
    historical = deepcopy(schema_v1())
    historical["objects"]["RunConfig"]["fields"].pop("detection_mode")
    (tmp_path / "schema.json").write_text(json.dumps(historical), encoding="utf-8")
    runs_path = tmp_path / "runs.jsonl"
    rows = [json.loads(line) for line in runs_path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        row["run_config"].pop("detection_mode")
    runs_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors
