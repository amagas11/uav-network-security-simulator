"""V7F-CAL-ACTUATION-001 / V7F-CAL-RUNTIME-VALIDATION-001 acceptance."""

from __future__ import annotations

from statistics import fmean, median

from swarm_sim import PlatformRuntime, RunConfig
from Manager.simulationmanager import SimulationManager
from swarm_sim.factory import PlatformRuntimeFactory
from swarm_sim.rl import UavDefenseEnv
from tools.run_experiment import run_batch
from swarm_sim.calibration import (
    BaselineCalibrationFitter,
    CalibrationDataset,
    DatasetManifest,
    RuntimeCalibrationValidator,
    CalibrationParameter,
    CalibrationProfile,
)
import pytest


def _dataset(
    name: str,
    *,
    rssi_dbm: float,
    snr_db: float,
    loss_ratio: float,
    latency_ms: float,
) -> CalibrationDataset:
    records = []
    for index in range(40):
        offset = (-1.5, -0.5, 0.5, 1.5)[index % 4]
        records.append(
            {
                "rssi_dbm": rssi_dbm + offset,
                "snr_db": snr_db + offset / 2.0,
                "decode_success": index >= round(40 * loss_ratio),
                "latency_ms": latency_ms + offset,
                "throughput_mbps": 8.0,
                "frequency_hz": 3.5e9,
                "bandwidth_hz": 20e6,
            }
        )
    return CalibrationDataset(
        manifest=DatasetManifest(
            dataset_id=name,
            version="synthetic-v7",
            source_kind="simulation",
            source_uri=f"fixture://{name}",
            license="SYNTHETIC_TEST_ONLY",
            sha256=("a" if name == "low" else "b") * 64,
            fields=sorted(records[0]),
        ),
        records=records,
        maturity="TEST",
    )


def _stats(profile) -> dict[str, float]:
    runtime = PlatformRuntime(
        RunConfig(
            seed=7701,
            duration_s=8.0,
            auto_traffic=True,
            tx_service_per_step=16,
            rx_service_per_step=16,
        ),
        calibration_profile=profile,
    )
    runtime.run_to_completion()
    receptions = [
        event
        for event in runtime.events
        if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
    ]
    phy = [event["online_features"]["phy"] for event in receptions]
    latency = [
        event["online_features"]["traffic"]["latency_ms"]
        for event in runtime.events
        if event["event_type"] == "TX"
        and event["online_features"]["traffic"]["latency_ms"] is not None
    ]
    return {
        "loss": sum(event["event_type"] == "RX_FAILURE" for event in receptions)
        / len(receptions),
        "rssi": fmean(item["rssi_dbm"] for item in phy),
        "snr": fmean(item["snr_db"] for item in phy),
        "latency": median(latency),
    }


def test_fitted_profile_actuates_runtime_signal_loss_and_latency():
    fitter = BaselineCalibrationFitter()
    good = fitter.fit(
        _dataset("low", rssi_dbm=-65, snr_db=25, loss_ratio=0.0, latency_ms=10)
    )
    poor = fitter.fit(
        _dataset("high", rssi_dbm=-85, snr_db=5, loss_ratio=0.9, latency_ms=500)
    )

    good_stats = _stats(good)
    poor_stats = _stats(poor)

    assert good_stats["rssi"] > poor_stats["rssi"] + 10
    assert good_stats["snr"] > poor_stats["snr"] + 10
    assert poor_stats["loss"] > good_stats["loss"] + 0.5
    assert poor_stats["latency"] > good_stats["latency"] + 300


def test_runtime_calibration_validator_uses_actual_runtime_events():
    dataset = _dataset(
        "low", rssi_dbm=-68, snr_db=18, loss_ratio=0.1, latency_ms=25
    )
    result = RuntimeCalibrationValidator().validate(
        dataset,
        RunConfig(seed=7702, duration_s=4.0, auto_traffic=True),
        seeds=[7702, 7703],
    )

    assert result["profile_hash"]
    assert result["runtime_run_ids"]
    assert result["runtime_record_count"] > 0
    assert result["comparison"]["rssi_dbm"]["simulation_count"] > 0
    assert result["comparison"]["packet_loss_ratio"]["simulation_count"] > 0
    assert result["source_records_are_runtime_records"] is False


def _target_link_phy(runtime: PlatformRuntime) -> list[dict]:
    target = runtime.observable_link_id("link-2-1")
    runtime.run_to_completion()
    return [
        event["online_features"]["phy"]
        for event in runtime.events
        if event["event_type"] == "PHY_SAMPLE"
        and event.get("extensions", {}).get("sample_link_id") == target
    ]


def test_calibration_composes_with_normal_low_snr():
    profile = BaselineCalibrationFitter().fit(
        _dataset("low", rssi_dbm=-70, snr_db=15, loss_ratio=0.05, latency_ms=20)
    )
    base = _target_link_phy(
        PlatformRuntime(
            RunConfig(seed=7704, duration_s=1.0, node_count=3, auto_traffic=False),
            calibration_profile=profile,
        )
    )
    normal = _target_link_phy(
        PlatformRuntime(
            RunConfig(
                seed=7704,
                duration_s=1.0,
                node_count=3,
                auto_traffic=False,
                normal_disturbance_specs=[
                    {
                        "disturbance_type": "NORMAL_LOW_SNR",
                        "start_s": 0.0,
                        "end_s": 1.0,
                        "target_link_ids": ["link-2-1"],
                        "parameters": {"attenuation_db": 15.0},
                    }
                ],
            ),
            calibration_profile=profile,
        )
    )
    assert fmean(item["rssi_dbm"] for item in normal) < fmean(
        item["rssi_dbm"] for item in base
    ) - 10


def test_runtime_calibration_control_units_are_validated():
    dataset = _dataset(
        "low", rssi_dbm=-70, snr_db=15, loss_ratio=0.1, latency_ms=20
    )
    with pytest.raises(ValueError, match="background_loss_probability requires unit ratio"):
        CalibrationProfile(
            profile_id="bad-unit",
            calibration_version="v7",
            calibration_status="TEST_FITTED",
            data_source_kind="calibrated_simulation",
            parameters=[
                CalibrationParameter(
                    "background_loss_probability",
                    0.1,
                    "dBm",
                    "fixture",
                    "bad",
                    [0, 1],
                    "v1",
                    "v7",
                )
            ],
            dataset_manifest=dataset.manifest,
        )


def test_calibration_profile_controls_are_identical_across_direct_manager_batch_rl(
    tmp_path,
):
    profile = BaselineCalibrationFitter().fit(
        _dataset("low", rssi_dbm=-72, snr_db=12, loss_ratio=0.2, latency_ms=30)
    )
    config = RunConfig(seed=7705, duration_s=1.0, auto_traffic=True)
    factory = PlatformRuntimeFactory()
    direct = factory.create(config, calibration_profile=profile).run_record()

    manager = SimulationManager(runtime_factory=factory)
    manager.create_run(config, calibration_profile=profile)
    assert manager.runtime is not None
    managed = manager.runtime.run_record()

    batch = run_batch(
        tmp_path / "calibration-parity",
        seeds=[7705],
        duration_s=1.0,
        run_config={"auto_traffic": True},
        calibration_profile=profile,
        runtime_factory=factory,
    )["runs"][0]["run_record"]

    env = UavDefenseEnv(runtime_factory=factory)
    # RL accepts a profile reference through its formal JSON-shaped config;
    # saving/loading itself is covered by the calibration pipeline tests.
    from swarm_sim.calibration import CalibrationLoader

    profile_path = tmp_path / "parity-profile.json"
    CalibrationLoader.save(profile, profile_path)
    env.reset(
        7705,
        {
            "duration_s": 1.0,
            "auto_traffic": True,
            "calibration_profile_path": str(profile_path),
        },
    )
    assert env.episode is not None
    rl = env.episode.runtime.run_record()

    records = (direct, managed, batch, rl)
    assert {item["calibration_profile"]["profile_hash"] for item in records} == {
        profile.profile_hash
    }
    assert {
        tuple(sorted(item["calibration_runtime_controls"].items()))
        for item in records
    } == {tuple(sorted(profile.runtime_controls().items()))}
