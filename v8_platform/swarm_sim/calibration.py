"""Conservative calibration fitting, provenance, loading and comparison."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
from pathlib import Path
from statistics import fmean, median, pstdev
from typing import Any, Protocol


# Canonical four-node formation baseline measured from PersistentPhyModel with
# its default radio parameters.  Fitted offsets preserve path/fading variation
# while moving aggregate output toward the source statistic.
_RUNTIME_REFERENCE_RSSI_DBM = -51.0
_RUNTIME_REFERENCE_SNR_DB = 35.0
_KNOWN_PARAMETER_UNITS = {
    "rssi_mean_dbm": "dBm",
    "rssi_std_db": "dB",
    "rssi_p05_dbm": "dBm",
    "rssi_p50_dbm": "dBm",
    "rssi_p95_dbm": "dBm",
    "snr_mean_db": "dB",
    "snr_std_db": "dB",
    "snr_p05_db": "dB",
    "snr_p50_db": "dB",
    "snr_p95_db": "dB",
    "packet_loss_ratio": "ratio",
    "latency_median_ms": "ms",
    "latency_p95_ms": "ms",
    "throughput_mean_mbps": "Mbps",
    "rssi_bias_db": "dB",
    "snr_bias_db": "dB",
    "background_loss_probability": "ratio",
    "base_latency_ms": "ms",
    "latency_jitter_ms": "ms",
    "frequency_hz": "Hz",
    "bandwidth_hz": "Hz",
    "noise_power_dbm": "dBm",
    "tx_power_dbm": "dBm",
    "shadowing_std_db": "dB",
    "rician_k_db": "dB",
}


_CALIBRATION_MEASUREMENT_FIELDS = {
    "rssi_dbm",
    "snr_db",
    "decode_success",
    "latency_ms",
    "throughput_mbps",
    "frequency_hz",
    "bandwidth_hz",
}
_CALIBRATION_GROUPING_FIELDS = {
    "node_id",
    "sender_node_id",
    "receiver_node_id",
    "link_id",
    "sim_time_s",
    "timestamp_utc",
}
_CALIBRATION_SUPPORTED_FIELDS = (
    _CALIBRATION_MEASUREMENT_FIELDS | _CALIBRATION_GROUPING_FIELDS
)


@dataclass(slots=True)
class DatasetManifest:
    dataset_id: str
    version: str
    source_kind: str
    source_uri: str | None
    license: str | None
    sha256: str | None
    fields: list[str]
    missing_fields: list[str] = field(default_factory=list)
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.source_kind not in {
            "simulation",
            "real_measurement",
            "augmented_real",
        }:
            raise ValueError(
                "calibration dataset source must be simulation, real_measurement, or augmented_real"
            )
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.dataset_id,
                self.version,
                self.source_uri,
                self.license,
                self.sha256,
            )
        ):
            raise ValueError(
                "calibration dataset requires id, version, source_uri, sha256, and license"
            )
        if not isinstance(self.fields, list) or not all(
            isinstance(item, str) and item for item in self.fields
        ):
            raise ValueError("calibration dataset fields must be non-empty strings")
        if not isinstance(self.missing_fields, list) or not all(
            isinstance(item, str) and item for item in self.missing_fields
        ):
            raise ValueError(
                "calibration dataset missing_fields must be non-empty strings"
            )
        if set(self.fields).intersection(self.missing_fields):
            raise ValueError("calibration field cannot be both available and missing")
        if self.notes is not None and not isinstance(self.notes, str):
            raise ValueError("calibration dataset notes must be string or null")
        digest = str(self.sha256).lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("calibration dataset sha256 must be a 64-digit hex digest")


@dataclass(slots=True)
class CalibrationDataset:
    """Normalized observations presented to the baseline fitter.

    Missing measurements are absent or ``None``; the fitter never converts a
    missing measurement to zero.
    """

    manifest: DatasetManifest
    records: list[dict[str, Any]]
    maturity: str = "DEVELOPMENT"

    def __post_init__(self) -> None:
        self.maturity = str(self.maturity).upper()
        if self.maturity not in {"TEST", "DEVELOPMENT", "PRELIMINARY", "APPROVED"}:
            raise ValueError("unsupported calibration dataset maturity")
        if not isinstance(self.records, list) or not self.records:
            raise ValueError("calibration dataset requires at least one record")
        declared = set(self.manifest.fields)
        unsupported = declared - _CALIBRATION_SUPPORTED_FIELDS
        if unsupported:
            raise ValueError(
                f"unsupported normalized calibration fields: {sorted(unsupported)}"
            )
        invalid_missing = set(self.manifest.missing_fields) - _CALIBRATION_SUPPORTED_FIELDS
        if invalid_missing:
            raise ValueError(
                f"unsupported missing calibration fields: {sorted(invalid_missing)}"
            )
        if not declared.intersection(_CALIBRATION_MEASUREMENT_FIELDS):
            raise ValueError("calibration dataset has no supported measurement field")
        for index, record in enumerate(self.records):
            if not isinstance(record, dict):
                raise ValueError(f"calibration record {index} must be an object")
            undeclared = set(record) - declared
            if undeclared:
                raise ValueError(
                    f"calibration record {index} has undeclared fields: {sorted(undeclared)}"
                )
            for name in (
                "rssi_dbm",
                "snr_db",
                "latency_ms",
                "throughput_mbps",
                "frequency_hz",
                "bandwidth_hz",
            ):
                value = record.get(name)
                if value is None:
                    continue
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(float(value))
                ):
                    raise ValueError(
                        f"calibration record {index}.{name} must be a finite number or null"
                    )
            decode = record.get("decode_success")
            if decode is not None and not isinstance(decode, bool):
                raise ValueError(
                    f"calibration record {index}.decode_success must be boolean or null"
                )
            for name in ("latency_ms", "throughput_mbps"):
                value = record.get(name)
                if isinstance(value, (int, float)) and value < 0:
                    raise ValueError(f"calibration record {index}.{name} must be >= 0")
            for name in ("frequency_hz", "bandwidth_hz"):
                value = record.get(name)
                if isinstance(value, (int, float)) and value <= 0:
                    raise ValueError(f"calibration record {index}.{name} must be > 0")
            sim_time = record.get("sim_time_s")
            if sim_time is not None and (
                not isinstance(sim_time, (int, float))
                or isinstance(sim_time, bool)
                or not math.isfinite(float(sim_time))
                or sim_time < 0
            ):
                raise ValueError(
                    f"calibration record {index}.sim_time_s must be >= 0 or null"
                )
            for name in ("node_id", "sender_node_id", "receiver_node_id"):
                value = record.get(name)
                if value is not None and (
                    not isinstance(value, int) or isinstance(value, bool)
                ):
                    raise ValueError(
                        f"calibration record {index}.{name} must be integer or null"
                    )
            for name in ("link_id", "timestamp_utc"):
                value = record.get(name)
                if value is not None and not isinstance(value, str):
                    raise ValueError(
                        f"calibration record {index}.{name} must be string or null"
                    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CalibrationParameter:
    parameter: str
    value: float
    unit: str
    source: str
    fitting_method: str
    valid_range: list[float] | None
    dataset_version: str | None
    calibration_version: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.parameter,
                self.unit,
                self.source,
                self.fitting_method,
                self.calibration_version,
            )
        ):
            raise ValueError(
                "calibration parameter name, unit, source, method, and version are required"
            )
        if self.dataset_version is not None and not isinstance(
            self.dataset_version, str
        ):
            raise ValueError("calibration parameter dataset_version must be string or null")
        if (
            not isinstance(self.value, (int, float))
            or isinstance(self.value, bool)
            or not math.isfinite(float(self.value))
        ):
            raise ValueError("calibration parameter value must be finite")
        self.value = float(self.value)
        if self.valid_range is not None:
            if (
                len(self.valid_range) != 2
                or not all(
                    isinstance(item, (int, float))
                    and not isinstance(item, bool)
                    and math.isfinite(float(item))
                    for item in self.valid_range
                )
                or self.valid_range[0] > self.valid_range[1]
            ):
                raise ValueError("calibration valid_range must be [minimum, maximum]")
            if not self.valid_range[0] <= self.value <= self.valid_range[1]:
                raise ValueError(
                    f"calibration parameter {self.parameter} is outside valid_range"
                )


@dataclass(slots=True)
class CalibrationProfile:
    profile_id: str
    calibration_version: str
    calibration_status: str
    data_source_kind: str
    parameters: list[CalibrationParameter]
    dataset_manifest: DatasetManifest | None = None
    sample_count: int = 0
    method: str = "MANUAL_PROFILE"
    quality: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    created_from: dict[str, Any] = field(default_factory=dict)
    profile_maturity: str = "DEVELOPMENT"
    profile_hash: str | None = None

    def __post_init__(self) -> None:
        if self.data_source_kind not in {
            "simulation",
            "calibrated_simulation",
            "real_measurement",
            "augmented_real",
        }:
            raise ValueError("unsupported calibration data_source_kind")
        claims_calibration = (
            self.data_source_kind != "simulation"
            or self.calibration_status != "UNCALIBRATED_BASELINE"
        )
        if claims_calibration and self.dataset_manifest is None:
            raise ValueError("calibrated/real profile requires a verifiable dataset_manifest")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.profile_id,
                self.calibration_version,
                self.calibration_status,
                self.method,
            )
        ):
            raise ValueError("calibration profile id, version, and method are required")
        if not isinstance(self.sample_count, int) or self.sample_count < 0:
            raise ValueError("calibration profile sample_count must be a non-negative integer")
        if not isinstance(self.parameters, list) or not all(
            isinstance(item, CalibrationParameter) for item in self.parameters
        ):
            raise ValueError("calibration profile parameters are invalid")
        if not isinstance(self.quality, dict) or not isinstance(
            self.created_from, dict
        ):
            raise ValueError("calibration profile quality/created_from must be objects")
        if not isinstance(self.warnings, list) or not all(
            isinstance(item, str) for item in self.warnings
        ):
            raise ValueError("calibration profile warnings must be strings")
        names = [item.parameter for item in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("calibration profile has duplicate parameters")
        for item in self.parameters:
            expected_unit = _KNOWN_PARAMETER_UNITS.get(item.parameter)
            if expected_unit is not None and item.unit != expected_unit:
                raise ValueError(
                    f"calibration parameter {item.parameter} requires unit {expected_unit}"
                )
        self.profile_maturity = str(self.profile_maturity).upper()
        if self.profile_maturity not in {
            "TEST",
            "DEVELOPMENT",
            "PRELIMINARY",
            "APPROVED",
        }:
            raise ValueError("unsupported calibration profile maturity")
        expected_hash = self._calculate_hash()
        if self.profile_hash is None:
            self.profile_hash = expected_hash
        elif self.profile_hash != expected_hash:
            raise ValueError("CALIBRATION_PROFILE_HASH_MISMATCH")

    def _calculate_hash(self) -> str:
        payload = {
            "profile_id": self.profile_id,
            "calibration_version": self.calibration_version,
            "calibration_status": self.calibration_status,
            "data_source_kind": self.data_source_kind,
            "parameters": [asdict(item) for item in self.parameters],
            "dataset_manifest": (
                asdict(self.dataset_manifest) if self.dataset_manifest else None
            ),
            "sample_count": self.sample_count,
            "method": self.method,
            "quality": self.quality,
            "warnings": self.warnings,
            "created_from": self.created_from,
            "profile_maturity": self.profile_maturity,
        }
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def parameter_values(self) -> dict[str, float]:
        """Return the validated numeric parameter map."""

        return {item.parameter: float(item.value) for item in self.parameters}

    def runtime_controls(self) -> dict[str, float]:
        """Map descriptive calibration targets to explicit runtime controls.

        Profiles produced before V7 contained only descriptive statistics.  The
        fallback mapping keeps those profiles usable without pretending that a
        target statistic and an actuator are the same thing.  New fitter output
        persists both forms, so provenance states exactly what drives the PHY.
        """

        values = self.parameter_values()
        latency_median = values.get("latency_median_ms", 0.0)
        latency_p95 = values.get("latency_p95_ms", latency_median)
        controls = {
            "rssi_bias_db": values.get(
                "rssi_bias_db",
                values.get("rssi_mean_dbm", _RUNTIME_REFERENCE_RSSI_DBM)
                - _RUNTIME_REFERENCE_RSSI_DBM,
            ),
            "snr_bias_db": values.get(
                "snr_bias_db",
                values.get("snr_mean_db", _RUNTIME_REFERENCE_SNR_DB)
                - _RUNTIME_REFERENCE_SNR_DB,
            ),
            "background_loss_probability": values.get(
                "background_loss_probability",
                values.get("packet_loss_ratio", 0.0),
            ),
            "base_latency_ms": values.get("base_latency_ms", latency_median),
            "latency_jitter_ms": values.get(
                "latency_jitter_ms",
                max(0.0, latency_p95 - latency_median) / 1.6448536269514722,
            ),
        }
        controls["background_loss_probability"] = max(
            0.0, min(1.0, controls["background_loss_probability"])
        )
        controls["base_latency_ms"] = max(0.0, controls["base_latency_ms"])
        controls["latency_jitter_ms"] = max(0.0, controls["latency_jitter_ms"])
        return controls

    def parameter_semantics(self) -> dict[str, dict[str, Any]]:
        """Describe target statistics separately from active controls."""

        controls = set(self.runtime_controls())
        return {
            item.parameter: {
                "role": (
                    "RUNTIME_CONTROL"
                    if item.parameter in controls
                    else "DESCRIPTIVE_VALIDATION_TARGET"
                ),
                "unit": item.unit,
            }
            for item in self.parameters
        }

    @classmethod
    def uncalibrated_baseline(cls) -> "CalibrationProfile":
        version = "baseline-v1"
        values = [
            ("frequency_hz", 3.5e9, "Hz", [3.4e9, 3.6e9]),
            ("bandwidth_hz", 20e6, "Hz", [1e6, 100e6]),
            ("tx_power_dbm", 23.0, "dBm", [0.0, 40.0]),
            ("noise_power_dbm", -89.0, "dBm", [-130.0, -60.0]),
            ("shadowing_std_db", 2.0, "dB", [0.0, 20.0]),
            ("rician_k_db", 10.0, "dB", [-20.0, 40.0]),
        ]
        return cls(
            profile_id="uncalibrated-static-a2a-v1",
            calibration_version=version,
            calibration_status="UNCALIBRATED_BASELINE",
            data_source_kind="simulation",
            parameters=[
                CalibrationParameter(
                    parameter=name,
                    value=value,
                    unit=unit,
                    source="simulation_baseline",
                    fitting_method="not_fitted",
                    valid_range=valid_range,
                    dataset_version=None,
                    calibration_version=version,
                )
                for name, value, unit, valid_range in values
            ],
            method="NOT_FITTED",
            profile_maturity="DEVELOPMENT",
        )


class CalibrationLoader:
    _PROFILE_KEYS = {
        "profile_id",
        "calibration_version",
        "calibration_status",
        "data_source_kind",
        "parameters",
        "dataset_manifest",
        "sample_count",
        "method",
        "quality",
        "warnings",
        "created_from",
        "profile_maturity",
        "profile_hash",
    }

    @classmethod
    def load(cls, path: str | Path) -> CalibrationProfile:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("calibration profile must be an object")
        unknown = set(data) - cls._PROFILE_KEYS
        if unknown:
            raise ValueError(f"unknown calibration profile fields: {sorted(unknown)}")
        manifest = data.get("dataset_manifest")
        return CalibrationProfile(
            profile_id=data["profile_id"],
            calibration_version=data["calibration_version"],
            calibration_status=data["calibration_status"],
            data_source_kind=data["data_source_kind"],
            parameters=[CalibrationParameter(**item) for item in data["parameters"]],
            dataset_manifest=DatasetManifest(**manifest) if manifest else None,
            sample_count=int(data.get("sample_count", 0)),
            method=str(data.get("method", "MANUAL_PROFILE")),
            quality=dict(data.get("quality", {})),
            warnings=list(data.get("warnings", [])),
            created_from=dict(data.get("created_from", {})),
            profile_maturity=str(data.get("profile_maturity", "DEVELOPMENT")),
            profile_hash=data.get("profile_hash"),
        )

    @staticmethod
    def save(profile: CalibrationProfile, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(profile.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return destination


class CalibrationDatasetLoader:
    @staticmethod
    def load(path: str | Path) -> CalibrationDataset:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("calibration dataset must be an object")
        unknown = set(data) - {"manifest", "records", "maturity"}
        if unknown:
            raise ValueError(f"unknown calibration dataset fields: {sorted(unknown)}")
        return CalibrationDataset(
            manifest=DatasetManifest(**data["manifest"]),
            records=data["records"],
            maturity=data.get("maturity", "DEVELOPMENT"),
        )

    @staticmethod
    def save(dataset: CalibrationDataset, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(dataset.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return destination


class CalibrationFitter(Protocol):
    def fit(
        self,
        dataset: CalibrationDataset | DatasetManifest,
        records: list[dict[str, Any]] | None = None,
    ) -> CalibrationProfile: ...


def _numbers(records: list[dict[str, Any]], name: str) -> list[float]:
    return [
        float(record[name])
        for record in records
        if isinstance(record.get(name), (int, float))
        and not isinstance(record.get(name), bool)
        and math.isfinite(float(record[name]))
    ]


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "mean": None,
            "std": None,
            "p05": None,
            "median": None,
            "p95": None,
        }
    return {
        "count": len(values),
        "mean": fmean(values),
        "std": pstdev(values),
        "p05": _percentile(values, 0.05),
        "median": median(values),
        "p95": _percentile(values, 0.95),
    }


class BaselineCalibrationFitter:
    """Fit transparent statistics plus an explicit baseline runtime mapping."""

    method = "BASELINE_DESCRIPTIVE_STATISTICS"

    def __init__(self, calibration_version: str = "baseline-statistics-v1") -> None:
        if not calibration_version:
            raise ValueError("calibration_version is required")
        self.calibration_version = calibration_version

    def fit(
        self,
        dataset: CalibrationDataset | DatasetManifest,
        records: list[dict[str, Any]] | None = None,
    ) -> CalibrationProfile:
        if isinstance(dataset, DatasetManifest):
            if records is None:
                raise ValueError("records are required with a DatasetManifest")
            dataset = CalibrationDataset(dataset, records)
        elif records is not None:
            raise ValueError("records must be omitted with CalibrationDataset")

        measurements = dataset.records
        summaries = {
            name: _summary(_numbers(measurements, name))
            for name in (
                "rssi_dbm",
                "snr_db",
                "latency_ms",
                "throughput_mbps",
                "frequency_hz",
                "bandwidth_hz",
            )
        }
        decode = [
            record["decode_success"]
            for record in measurements
            if isinstance(record.get("decode_success"), bool)
        ]
        packet_loss_ratio = (
            sum(not value for value in decode) / len(decode) if decode else None
        )
        paired_noise = [
            float(record["rssi_dbm"]) - float(record["snr_db"])
            for record in measurements
            if isinstance(record.get("rssi_dbm"), (int, float))
            and not isinstance(record.get("rssi_dbm"), bool)
            and isinstance(record.get("snr_db"), (int, float))
            and not isinstance(record.get("snr_db"), bool)
        ]

        parameters: list[CalibrationParameter] = []

        def add(name: str, value: float | int | None, unit: str, limits: list[float]) -> None:
            if value is None:
                return
            parameters.append(
                CalibrationParameter(
                    parameter=name,
                    value=float(value),
                    unit=unit,
                    source=dataset.manifest.dataset_id,
                    fitting_method=self.method,
                    valid_range=limits,
                    dataset_version=dataset.manifest.version,
                    calibration_version=self.calibration_version,
                )
            )

        add("rssi_mean_dbm", summaries["rssi_dbm"]["mean"], "dBm", [-160.0, 20.0])
        add("rssi_std_db", summaries["rssi_dbm"]["std"], "dB", [0.0, 100.0])
        add("rssi_p05_dbm", summaries["rssi_dbm"]["p05"], "dBm", [-160.0, 20.0])
        add("rssi_p50_dbm", summaries["rssi_dbm"]["median"], "dBm", [-160.0, 20.0])
        add("rssi_p95_dbm", summaries["rssi_dbm"]["p95"], "dBm", [-160.0, 20.0])
        add("snr_mean_db", summaries["snr_db"]["mean"], "dB", [-100.0, 100.0])
        add("snr_std_db", summaries["snr_db"]["std"], "dB", [0.0, 100.0])
        add("snr_p05_db", summaries["snr_db"]["p05"], "dB", [-100.0, 100.0])
        add("snr_p50_db", summaries["snr_db"]["median"], "dB", [-100.0, 100.0])
        add("snr_p95_db", summaries["snr_db"]["p95"], "dB", [-100.0, 100.0])
        add("packet_loss_ratio", packet_loss_ratio, "ratio", [0.0, 1.0])
        add("latency_median_ms", summaries["latency_ms"]["median"], "ms", [0.0, 1e9])
        add("latency_p95_ms", summaries["latency_ms"]["p95"], "ms", [0.0, 1e9])
        add("throughput_mean_mbps", summaries["throughput_mbps"]["mean"], "Mbps", [0.0, 1e9])
        add("frequency_hz", summaries["frequency_hz"]["median"], "Hz", [1.0, 1e15])
        add("bandwidth_hz", summaries["bandwidth_hz"]["median"], "Hz", [1.0, 1e15])
        add("noise_power_dbm", fmean(paired_noise) if paired_noise else None, "dBm", [-200.0, 100.0])
        add("shadowing_std_db", summaries["rssi_dbm"]["std"], "dB", [0.0, 100.0])

        # Runtime controls are intentionally simple and explainable.  The
        # signal controls are offsets from the documented nominal B-platform
        # baseline; loss and latency controls directly represent observed
        # background behavior.  Throughput remains a comparison target because
        # runtime throughput is derived from bandwidth, SINR and loss.
        add(
            "rssi_bias_db",
            (
                float(summaries["rssi_dbm"]["mean"])
                - _RUNTIME_REFERENCE_RSSI_DBM
                if summaries["rssi_dbm"]["mean"] is not None
                else None
            ),
            "dB",
            [-100.0, 100.0],
        )
        add(
            "snr_bias_db",
            (
                float(summaries["snr_db"]["mean"])
                - _RUNTIME_REFERENCE_SNR_DB
                if summaries["snr_db"]["mean"] is not None
                else None
            ),
            "dB",
            [-100.0, 100.0],
        )
        add(
            "background_loss_probability",
            packet_loss_ratio,
            "ratio",
            [0.0, 1.0],
        )
        add(
            "base_latency_ms",
            summaries["latency_ms"]["median"],
            "ms",
            [0.0, 1e9],
        )
        latency_jitter = None
        if (
            summaries["latency_ms"]["median"] is not None
            and summaries["latency_ms"]["p95"] is not None
        ):
            latency_jitter = max(
                0.0,
                float(summaries["latency_ms"]["p95"])
                - float(summaries["latency_ms"]["median"]),
            ) / 1.6448536269514722
        add("latency_jitter_ms", latency_jitter, "ms", [0.0, 1e9])

        availability = {
            "rssi_dbm": bool(summaries["rssi_dbm"]["count"]),
            "snr_db": bool(summaries["snr_db"]["count"]),
            "packet_loss_ratio": bool(decode),
            "latency_ms": bool(summaries["latency_ms"]["count"]),
            "throughput_mbps": bool(summaries["throughput_mbps"]["count"]),
            "frequency_hz": bool(summaries["frequency_hz"]["count"]),
            "bandwidth_hz": bool(summaries["bandwidth_hz"]["count"]),
        }
        warnings = [
            f"{name}: NOT_AVAILABLE"
            for name, available in availability.items()
            if not available
        ]
        source_material = json.dumps(
            dataset.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        source_fingerprint = hashlib.sha256(source_material).hexdigest()
        return CalibrationProfile(
            profile_id=f"cal-{source_fingerprint[:20]}",
            calibration_version=self.calibration_version,
            calibration_status=(
                "CALIBRATED"
                if dataset.manifest.source_kind in {"real_measurement", "augmented_real"}
                else "TEST_FITTED"
            ),
            data_source_kind="calibrated_simulation",
            parameters=parameters,
            dataset_manifest=dataset.manifest,
            sample_count=len(measurements),
            method=self.method,
            quality={
                "availability": availability,
                "source_record_count": len(measurements),
                "descriptive_statistics": summaries,
                "runtime_mapping": {
                    "version": "BASELINE_RUNTIME_MAPPING_V1",
                    "rssi_reference_dbm": _RUNTIME_REFERENCE_RSSI_DBM,
                    "snr_reference_db": _RUNTIME_REFERENCE_SNR_DB,
                    "throughput_mean_mbps": "DESCRIPTIVE_VALIDATION_TARGET",
                },
            },
            warnings=warnings,
            created_from={
                "dataset_id": dataset.manifest.dataset_id,
                "dataset_version": dataset.manifest.version,
                "dataset_sha256": dataset.manifest.sha256,
                "source_kind": dataset.manifest.source_kind,
                "license": dataset.manifest.license,
                "normalized_records_sha256": source_fingerprint,
            },
            profile_maturity=(
                "TEST"
                if dataset.maturity == "TEST"
                else "PRELIMINARY"
                if dataset.maturity != "APPROVED"
                else "APPROVED"
            ),
        )


def compare_observations(
    reference: list[float], simulated: list[float]
) -> dict[str, float | int | None]:
    if not reference or not simulated:
        return {
            "reference_count": len(reference),
            "simulated_count": len(simulated),
            "mean_error": None,
            "mean_absolute_error": None,
        }
    count = min(len(reference), len(simulated))
    errors = [simulated[index] - reference[index] for index in range(count)]
    return {
        "reference_count": len(reference),
        "simulated_count": len(simulated),
        "mean_error": sum(errors) / count,
        "mean_absolute_error": sum(abs(value) for value in errors) / count,
    }


def compare_calibration_observations(
    source_records: list[dict[str, Any]],
    simulation_records: list[dict[str, Any]],
) -> dict[str, dict[str, float | int | None]]:
    """Compare named source/simulation statistics without inventing values."""

    result: dict[str, dict[str, float | int | None]] = {}
    for name in ("rssi_dbm", "snr_db", "throughput_mbps"):
        source = _summary(_numbers(source_records, name))
        simulation = _summary(_numbers(simulation_records, name))
        result[name] = {
            "source_count": source["count"],
            "simulation_count": simulation["count"],
            "source_mean": source["mean"],
            "simulation_mean": simulation["mean"],
            "source_std": source["std"],
            "simulation_std": simulation["std"],
        }
    source_latency = _summary(_numbers(source_records, "latency_ms"))
    simulation_latency = _summary(_numbers(simulation_records, "latency_ms"))
    result["latency_ms"] = {
        "source_count": source_latency["count"],
        "simulation_count": simulation_latency["count"],
        "source_median": source_latency["median"],
        "simulation_median": simulation_latency["median"],
        "source_p95": source_latency["p95"],
        "simulation_p95": simulation_latency["p95"],
    }

    def loss(records: list[dict[str, Any]]) -> tuple[int, float | None]:
        decoded = [
            item["decode_success"]
            for item in records
            if isinstance(item.get("decode_success"), bool)
        ]
        return len(decoded), (
            sum(not item for item in decoded) / len(decoded) if decoded else None
        )

    source_count, source_loss = loss(source_records)
    simulation_count, simulation_loss = loss(simulation_records)
    result["packet_loss_ratio"] = {
        "source_count": source_count,
        "simulation_count": simulation_count,
        "source": source_loss,
        "simulation": simulation_loss,
    }
    return result


class RuntimeCalibrationValidator:
    """Fit a profile, execute real runtimes, and compare their emitted data.

    This deliberately does not manufacture a synthetic ``simulation_records``
    list from the source data.  Every simulation statistic below is collected
    from TX/RX events produced by :class:`PlatformRuntime`.
    """

    def __init__(self, fitter: CalibrationFitter | None = None) -> None:
        self.fitter = fitter or BaselineCalibrationFitter()

    def validate(
        self,
        dataset: CalibrationDataset,
        run_config: Any,
        *,
        seeds: list[int] | tuple[int, ...] | None = None,
        runtime_factory: Any | None = None,
    ) -> dict[str, Any]:
        from .factory import PlatformRuntimeFactory
        from .simulation import RunConfig

        profile = self.fitter.fit(dataset)
        factory = runtime_factory or PlatformRuntimeFactory()
        base = (
            run_config.to_dict()
            if isinstance(run_config, RunConfig)
            else dict(run_config or {})
        )
        selected_seeds = list(seeds or [int(base.get("seed", 42))])
        runtime_records: list[dict[str, Any]] = []
        run_ids: list[str] = []
        for seed in selected_seeds:
            payload = dict(base)
            payload["seed"] = int(seed)
            runtime = factory.create(
                RunConfig.from_dict(payload), calibration_profile=profile
            )
            runtime.run_to_completion()
            run_ids.append(runtime.run_id)
            for event in runtime.events:
                event_type = event.get("event_type")
                online = event.get("online_features", {})
                if event_type in {"RX_SUCCESS", "RX_FAILURE"}:
                    phy = online.get("phy", {})
                    runtime_records.append(
                        {
                            "rssi_dbm": phy.get("rssi_dbm"),
                            "snr_db": phy.get("snr_db"),
                            "decode_success": event_type == "RX_SUCCESS",
                        }
                    )
                if event_type == "TX":
                    traffic = online.get("traffic", {})
                    runtime_records.append(
                        {
                            "latency_ms": traffic.get("latency_ms"),
                            "throughput_mbps": traffic.get("throughput_mbps"),
                        }
                    )
        return {
            "profile_id": profile.profile_id,
            "profile_hash": profile.profile_hash,
            "runtime_controls": profile.runtime_controls(),
            "runtime_run_ids": run_ids,
            "runtime_record_count": len(runtime_records),
            "source_records_are_runtime_records": runtime_records is dataset.records,
            "comparison": compare_calibration_observations(
                dataset.records, runtime_records
            ),
        }
