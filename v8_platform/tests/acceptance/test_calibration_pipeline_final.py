"""Acceptance evidence for V6P-CAL-FITTER-001 and V6P-CAL-ENTRYPOINT-001."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.app import app, controller
from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.calibration import (
    BaselineCalibrationFitter,
    CalibrationDataset,
    CalibrationLoader,
    DatasetManifest,
    compare_calibration_observations,
)
from swarm_sim.rl import UavDefenseEnv
from tools.run_experiment import run_batch


def _dataset() -> CalibrationDataset:
    records = []
    rssi = [-72.0, -71.0, -70.0, -69.0, -68.0] * 2
    snr = [13.0, 14.0, 15.0, 16.0, 17.0] * 2
    latency = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0, 24.0, 26.0, 28.0]
    for index in range(10):
        records.append(
            {
                "rssi_dbm": rssi[index],
                "snr_db": snr[index],
                "decode_success": index != 9,
                "latency_ms": latency[index],
                "throughput_mbps": 4.0 + index * 0.1,
                "frequency_hz": 3.5e9,
                "bandwidth_hz": 20e6,
            }
        )
    manifest = DatasetManifest(
        dataset_id="synthetic-known-statistics",
        version="synthetic-v1",
        source_kind="simulation",
        source_uri="fixture://synthetic-known-statistics",
        license="SYNTHETIC_TEST_ONLY",
        sha256="a" * 64,
        fields=sorted(records[0]),
        notes="Deterministic test fixture; not real calibration data.",
    )
    return CalibrationDataset(manifest=manifest, records=records, maturity="TEST")


def _profile_path(tmp_path: Path) -> tuple[Path, object]:
    profile = BaselineCalibrationFitter(
        calibration_version="baseline-statistics-v1"
    ).fit(_dataset())
    path = tmp_path / "calibration-profile.json"
    CalibrationLoader.save(profile, path)
    return path, profile


def _parameter(profile, name: str) -> float:
    return next(item.value for item in profile.parameters if item.parameter == name)


def test_synthetic_data_fits_explainable_profile_and_round_trips(tmp_path: Path):
    path, profile = _profile_path(tmp_path)
    assert _parameter(profile, "rssi_mean_dbm") == pytest.approx(-70.0)
    assert _parameter(profile, "snr_mean_db") == pytest.approx(15.0)
    assert _parameter(profile, "packet_loss_ratio") == pytest.approx(0.1)
    assert _parameter(profile, "latency_median_ms") == pytest.approx(19.0)
    assert _parameter(profile, "latency_p95_ms") == pytest.approx(27.1)
    assert profile.sample_count == 10
    assert profile.method == "BASELINE_DESCRIPTIVE_STATISTICS"
    assert profile.profile_maturity == "TEST"
    assert profile.profile_hash
    loaded = CalibrationLoader.load(path)
    assert loaded.to_dict() == profile.to_dict()


def test_calibration_profile_direct_runtime_is_reproducible_and_provenanced(
    tmp_path: Path,
):
    _, profile = _profile_path(tmp_path)
    config = RunConfig(seed=7101, duration_s=0.6, auto_traffic=False)
    first = PlatformRuntime(config, run_id="cal-direct-a", calibration_profile=profile)
    second = PlatformRuntime(config, run_id="cal-direct-b", calibration_profile=profile)
    first.run_to_completion()
    second.run_to_completion()
    assert first.reproducible_event_projection() == second.reproducible_event_projection()
    record = first.run_record()
    assert record["data_source"]["kind"] == "calibrated_simulation"
    assert record["calibration_profile"]["profile_hash"] == profile.profile_hash
    assert record["calibration_profile"]["dataset_manifest"]["version"] == "synthetic-v1"


def test_batch_api_and_rl_load_the_same_calibration_profile(tmp_path: Path):
    path, profile = _profile_path(tmp_path)
    batch = run_batch(
        tmp_path / "batch",
        seeds=[7102],
        duration_s=0.4,
        run_config={"auto_traffic": True},
        calibration_profile_path=path,
    )
    assert batch["all_valid"]
    run_path = Path(batch["runs"][0]["export"]["output_dir"]) / "runs.jsonl"
    batch_run = json.loads(run_path.read_text(encoding="utf-8").splitlines()[0])
    assert batch_run["calibration_profile"]["profile_hash"] == profile.profile_hash

    with TestClient(app) as client:
        response = client.post(
            "/api/runs",
            json={
                "seed": 7102,
                "duration_s": 0.4,
                "auto_traffic": False,
                "auto_advance": False,
                "calibration_profile_path": str(path),
            },
        )
        assert response.status_code == 201, response.text
        assert controller.manager.runtime is not None
        api_record = controller.manager.runtime.run_record()
        assert api_record["calibration_profile"]["profile_hash"] == profile.profile_hash

    env = UavDefenseEnv(observer_node_id=1)
    env.reset(
        7102,
        {
            "duration_s": 0.4,
            "auto_traffic": False,
            "calibration_profile_path": str(path),
        },
    )
    assert env.episode is not None
    rl_record = env.episode.runtime.run_record()
    assert rl_record["calibration_profile"]["profile_hash"] == profile.profile_hash


def test_invalid_calibration_profile_is_rejected(tmp_path: Path):
    bad = tmp_path / "bad-profile.json"
    bad.write_text(
        json.dumps(
            {
                "profile_id": "bad",
                "calibration_version": "bad-v1",
                "calibration_status": "CALIBRATED",
                "data_source_kind": "calibrated_simulation",
                "parameters": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dataset_manifest"):
        CalibrationLoader.load(bad)

    manifest = DatasetManifest(
        dataset_id="bad-normalized-fields",
        version="test-v1",
        source_kind="simulation",
        source_uri="fixture://bad-normalized-fields",
        license="SYNTHETIC_TEST_ONLY",
        sha256="b" * 64,
        fields=["rssi_dbm", "unsupported_metric"],
    )
    with pytest.raises(ValueError, match="unsupported normalized calibration fields"):
        CalibrationDataset(
            manifest=manifest,
            records=[{"rssi_dbm": -70.0, "unsupported_metric": 1.0}],
            maturity="TEST",
        )


def test_real_vs_calibrated_comparison_reports_named_statistics():
    reference = _dataset().records
    simulated = [dict(item, rssi_dbm=item["rssi_dbm"] + 1.0) for item in reference]
    comparison = compare_calibration_observations(reference, simulated)
    assert comparison["rssi_dbm"]["source_mean"] == pytest.approx(-70.0)
    assert comparison["rssi_dbm"]["simulation_mean"] == pytest.approx(-69.0)
    assert comparison["packet_loss_ratio"]["source"] == pytest.approx(0.1)
    assert comparison["latency_ms"]["source_median"] == pytest.approx(19.0)
