from __future__ import annotations

import json
from pathlib import Path

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.calibration import CalibrationParameter, CalibrationProfile, DatasetManifest
from swarm_sim.dataset import schema_v1
from swarm_sim.validation import DatasetValidator


RF_REQUIRED_FIELDS = {
    "sample_id",
    "file_path",
    "device_id",
    "claimed_device_id",
    "device_model",
    "session_id",
    "receiver_id",
    "receiver_model",
    "center_frequency_hz",
    "sample_rate_hz",
    "bandwidth_hz",
    "sample_format",
    "sample_count",
    "snr_db",
    "rssi_dbm",
    "capture_start_utc",
    "data_source",
    "label_quality",
}


def _manifest(**overrides):
    record = {
        "sample_id": "rf-sample-1",
        "file_path": "rf-sample-1.npy",
        "device_id": "uav-2-radio",
        "claimed_device_id": "uav-2-radio",
        "device_model": "synthetic-fixture-device",
        "session_id": "capture-session-1",
        "receiver_id": "uav-1-radio",
        "receiver_model": "synthetic-fixture-receiver",
        "center_frequency_hz": 3.5e9,
        "sample_rate_hz": 20e6,
        "bandwidth_hz": 10e6,
        "sample_format": "complex64",
        "sample_count": 8,
        "snr_db": 12.5,
        "rssi_dbm": -70.0,
        "capture_start_utc": "2026-09-07T00:00:00Z",
        "data_source": "simulation",
        "label_quality": "SYNTHETIC_TEST_ONLY",
    }
    record.update(overrides)
    return record


def _export_with_manifest(tmp_path, record):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False), run_id="rf-validation")
    runtime.rf_manifest = [record]
    runtime.run_to_completion()
    runtime.export_dataset(tmp_path)
    if record.get("file_path") and ".." not in str(record["file_path"]):
        sample = tmp_path / "rf_samples" / str(record["file_path"])
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_bytes(b"NUMPY-FIXTURE")
    return DatasetValidator().validate(tmp_path)


def test_full_rf_manifest_passes_and_all_required_fields_are_enforced(tmp_path):
    record = _manifest()
    assert set(record) == RF_REQUIRED_FIELDS
    report = _export_with_manifest(tmp_path, record)
    assert report.valid, report.errors


def test_rf_manifest_missing_each_newly_required_field_fails(tmp_path):
    for field in ("device_model", "receiver_model", "snr_db", "rssi_dbm", "capture_start_utc"):
        case = tmp_path / field
        record = _manifest()
        del record[field]
        report = _export_with_manifest(case, record)
        assert not report.valid
        assert any(field in error for error in report.errors)


def test_rf_manifest_invalid_path_and_invalid_types_fail(tmp_path):
    escaped = _export_with_manifest(tmp_path / "escaped", _manifest(file_path="../escape.npy"))
    assert not escaped.valid
    assert any("escapes rf_samples" in error for error in escaped.errors)

    invalid = _export_with_manifest(
        tmp_path / "types",
        _manifest(sample_count=0, sample_rate_hz="not-a-number", capture_start_utc="not-utc"),
    )
    assert not invalid.valid
    assert any("sample_count" in error for error in invalid.errors)
    assert any("sample_rate_hz" in error for error in invalid.errors)
    assert any("capture_start_utc" in error for error in invalid.errors)


def test_non_null_rf_sample_ref_resolves_and_null_is_allowed(tmp_path):
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="rf-reference",
    )
    message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
    runtime.register_rf_sample(_manifest(), message_id=message_id, link_id="link-2-1")
    runtime.run_to_completion()
    rx = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS" and event["message_id"] == message_id
    ]
    assert rx[0]["online_features"]["phy"]["rf_sample_ref"] == "rf-sample-1"
    assert all(
        event["online_features"]["phy"]["rf_sample_ref"] is None
        for event in runtime.events
        if event["event_type"] == "PHY_SAMPLE"
    )
    runtime.export_dataset(tmp_path)
    (tmp_path / "rf_samples" / "rf-sample-1.npy").write_bytes(b"NUMPY-FIXTURE")
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors


def test_event_rf_reference_to_unknown_sample_is_rejected(tmp_path):
    runtime = PlatformRuntime(RunConfig(duration_s=0.4, auto_traffic=False), run_id="rf-bad-ref")
    runtime.run_to_completion()
    runtime.events[0]["online_features"]["phy"]["rf_sample_ref"] = "missing-sample"
    runtime.export_dataset(tmp_path)
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("unknown rf_sample_ref" in error for error in report.errors)


def test_rff_reference_is_hop_local_not_forwarded_as_gcs_phy_evidence():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.4, auto_traffic=False, tx_service_per_step=8, rx_service_per_step=8),
        run_id="rf-hop",
    )
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 100.0})
    runtime.register_rf_sample(_manifest(), message_id=message_id, link_id="link-2-1")
    runtime.run_to_completion()
    rx = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS" and event["message_id"] == message_id
    ]
    leader_rx = next(event for event in rx if event["observer_node_id"] == 1)
    gcs_rx = next(event for event in rx if event["observer_node_id"] == 0)
    assert leader_rx["online_features"]["phy"]["rf_sample_ref"] == "rf-sample-1"
    assert gcs_rx["online_features"]["phy"]["rf_sample_ref"] is None


def test_probe_measurements_are_correlated_not_copied_and_local_snr_is_independent():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="probe-local-snr")
    first, second = runtime.probes.probe(1, 2, sample_count=64)
    assert first.measurement is not None and second.measurement is not None
    assert first.measurement != second.measurement
    first_mean = sum(first.measurement) / len(first.measurement)
    second_mean = sum(second.measurement) / len(second.measurement)
    covariance_direction = sum(
        (left - first_mean) * (right - second_mean)
        for left, right in zip(first.measurement, second.measurement)
    )
    assert covariance_direction > 0
    assert first.noise_var != second.noise_var
    assert first.snr_db is not None and second.snr_db is not None
    assert first.snr_db != second.snr_db
    assert first.probe_id == second.probe_id
    assert first.session_id == second.session_id
    assert first.freq_hz == second.freq_hz


def test_probe_rejects_non_neighbors_and_uses_explicit_missing():
    runtime = PlatformRuntime(RunConfig(node_count=5, auto_traffic=False), run_id="probe-neighbor")
    first, second = runtime.probes.probe(2, 3)
    assert first.missing and second.missing
    assert first.measurement is None and second.measurement is None
    assert first.snr_db is None and second.snr_db is None


def test_calibration_run_record_preserves_profile_provenance_without_real_claim():
    manifest = DatasetManifest(
        dataset_id="synthetic-provenance-fixture",
        version="fixture-v2",
        source_kind="simulation",
        source_uri="synthetic-fixture://calibration/provenance-only",
        license="test-fixture",
        sha256="b" * 64,
        fields=["tx_power_dbm"],
        notes="Metadata-only acceptance fixture; not real calibration data.",
    )
    profile = CalibrationProfile(
        profile_id="synthetic-profile-v2",
        calibration_version="synthetic-cal-v2",
        calibration_status="SYNTHETIC_TEST_PROFILE",
        data_source_kind="simulation",
        parameters=[
            CalibrationParameter(
                "tx_power_dbm",
                18.0,
                "dBm",
                "synthetic_fixture",
                "fixed_test_value",
                [0.0, 40.0],
                "fixture-v2",
                "synthetic-cal-v2",
            )
        ],
        dataset_manifest=manifest,
    )
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), calibration_profile=profile)
    record = runtime.context.run_record()
    assert record["data_source"] == {
        "kind": "simulation",
        "source_dataset_version": "fixture-v2",
        "calibration_version": "synthetic-cal-v2",
    }
    assert record["profiles"]["channel_profile_id"] == "synthetic-profile-v2"
    assert record["calibration_status"] == "SYNTHETIC_TEST_PROFILE"


def test_schema_is_a_field_level_machine_readable_frozen_contract():
    schema = schema_v1()
    required_objects = {
        "runs",
        "events",
        "labels",
        "rf_manifest",
        "model_result",
        "LocalPhyObservation",
        "online_features.packet",
        "online_features.phy",
        "online_features.traffic",
        "online_features.node_state",
        "online_features.topology",
        "online_features.security_state",
        "online_features.resource_state",
    }
    assert required_objects <= set(schema["objects"])
    for object_name in required_objects:
        fields = schema["objects"][object_name]["fields"]
        assert fields
        for field_name, descriptor in fields.items():
            assert descriptor["name"] == field_name
            assert set(descriptor) >= {
                "name",
                "type",
                "required",
                "nullable",
                "description",
                "semantic_id",
            }
    assert schema["objects"]["online_features.phy"]["fields"]["rf_sample_ref"]["nullable"] is True
    assert RF_REQUIRED_FIELDS <= set(schema["objects"]["rf_manifest"]["fields"])
    on_disk = json.loads(Path("dataset/schema.json").read_text(encoding="utf-8"))
    assert on_disk == schema
