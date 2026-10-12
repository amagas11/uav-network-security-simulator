"""Run deterministic seed batches and export validated V7-platform datasets."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.calibration import CalibrationLoader, CalibrationProfile
from swarm_sim.factory import PlatformRuntimeFactory
from swarm_sim.scenario_validation import ScenarioMechanismValidator
from swarm_sim.simulation import SCHEMA_VERSION
from swarm_sim.validation import DatasetValidator


def _load_plans(
    path: Path | None, *, collection_key: str, description: str
) -> list[dict[str, Any]]:
    if path is None:
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get(collection_key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(
            f"{description} JSON must be an array or "
            f"{{'{collection_key}': [...]}} object"
        )
    return value


def _load_attacks(path: Path | None) -> list[dict[str, Any]]:
    return _load_plans(
        path, collection_key="attacks", description="attack-plan"
    )


def _load_normal_disturbances(path: Path | None) -> list[dict[str, Any]]:
    return _load_plans(
        path,
        collection_key="normal_disturbances",
        description="normal-disturbance-plan",
    )


def run_batch(
    output_dir: str | Path,
    *,
    seeds: list[int],
    duration_s: float | None = None,
    step_s: float | None = None,
    node_count: int | None = None,
    attack_specs: list[dict[str, Any]] | None = None,
    normal_disturbance_specs: list[dict[str, Any]] | None = None,
    traffic_specs: list[dict[str, Any]] | None = None,
    session_lifecycle_specs: list[dict[str, Any]] | None = None,
    run_config: dict[str, Any] | RunConfig | None = None,
    require_formal_security: bool | None = None,
    dataset_maturity: str | None = None,
    calibration_profile: CalibrationProfile | None = None,
    calibration_profile_path: str | Path | None = None,
    runtime_factory: PlatformRuntimeFactory | None = None,
) -> dict[str, Any]:
    if calibration_profile is not None and calibration_profile_path is not None:
        raise ValueError("specify calibration_profile or calibration_profile_path, not both")
    resolved_calibration = calibration_profile or (
        CalibrationLoader.load(calibration_profile_path)
        if calibration_profile_path is not None
        else None
    )
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    all_valid = True
    batch_id = f"batch-{uuid4().hex}"
    factory = runtime_factory or PlatformRuntimeFactory()

    base_config = (
        asdict(run_config)
        if isinstance(run_config, RunConfig)
        else deepcopy(run_config or {})
    )
    effective_attacks = (
        deepcopy(attack_specs)
        if attack_specs is not None
        else deepcopy(base_config.get("attack_specs", []))
    )
    effective_normal = (
        deepcopy(normal_disturbance_specs)
        if normal_disturbance_specs is not None
        else deepcopy(base_config.get("normal_disturbance_specs", []))
    )
    effective_traffic = (
        deepcopy(traffic_specs)
        if traffic_specs is not None
        else deepcopy(base_config.get("traffic_specs", []))
    )
    effective_lifecycle = (
        deepcopy(session_lifecycle_specs)
        if session_lifecycle_specs is not None
        else deepcopy(base_config.get("session_lifecycle_specs", []))
    )

    def scenario_name() -> str | None:
        attacks = effective_attacks
        normal = effective_normal
        if not attacks and not normal:
            return "NORMAL_BASELINE"
        if len(attacks) == 1 and not normal:
            return (
                f"{str(attacks[0].get('attack_family', '')).upper()}_"
                f"{str(attacks[0].get('attack_subtype', '')).upper()}"
            )
        if len(normal) == 1 and not attacks:
            return str(normal[0].get("disturbance_type", "")).upper()
        return None

    inferred_scenario = scenario_name()
    resolved_duration_s = float(
        duration_s if duration_s is not None else base_config.get("duration_s", 10.0)
    )
    resolved_step_s = float(
        step_s if step_s is not None else base_config.get("step_s", 0.2)
    )
    resolved_node_count = int(
        node_count if node_count is not None else base_config.get("node_count", 4)
    )
    resolved_require_formal = bool(
        require_formal_security
        if require_formal_security is not None
        else base_config.get("require_formal_security", False)
    )
    resolved_maturity = str(
        dataset_maturity
        if dataset_maturity is not None
        else base_config.get("dataset_maturity", "DEVELOPMENT")
    )
    for run_index, seed in enumerate(seeds, 1):
        run_id = f"{batch_id}-run-{run_index:04d}-seed-{seed}"
        config_payload = deepcopy(base_config)
        config_payload.update(
            {
                "seed": seed,
                "duration_s": resolved_duration_s,
                "step_s": resolved_step_s,
                "node_count": resolved_node_count,
                "attack_specs": deepcopy(effective_attacks),
                "normal_disturbance_specs": deepcopy(effective_normal),
                "traffic_specs": deepcopy(effective_traffic),
                "session_lifecycle_specs": deepcopy(effective_lifecycle),
                "require_formal_security": resolved_require_formal,
                "dataset_maturity": resolved_maturity,
            }
        )
        runtime = factory.create(
            RunConfig.from_dict(config_payload),
            run_id=run_id,
            calibration_profile=resolved_calibration,
        )
        runtime.run_to_completion()
        run_dir = root / f"run-{run_index:04d}-seed-{seed}-{batch_id[-8:]}"
        export = runtime.export_dataset(run_dir)
        validation = DatasetValidator().validate(run_dir).to_dict()
        mechanism = (
            ScenarioMechanismValidator.validate(runtime, inferred_scenario)
            if inferred_scenario
            else None
        )
        projection_fingerprint = hashlib.sha256(
            json.dumps(
                runtime.reproducible_event_projection(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        all_valid = all_valid and bool(validation["valid"]) and (
            mechanism is None or mechanism.passed
        )
        rows.append(
            {
                "run_index": run_index,
                "seed": seed,
                "run_id": runtime.run_id,
                "status": runtime.status(),
                "metrics": runtime.metrics(),
                "evaluation": runtime.evaluation_view(),
                "mechanism_evidence": runtime.mechanism_evidence(),
                "mechanism_validation": (
                    {
                        "scenario": mechanism.scenario,
                        "passed": mechanism.passed,
                        "errors": list(mechanism.errors),
                        "evidence": mechanism.evidence,
                    }
                    if mechanism is not None
                    else {
                        "scenario": "COMPOUND_OR_MULTI_PLAN",
                        "passed": None,
                        "errors": [],
                        "evidence": {},
                    }
                ),
                "semantic_event_fingerprint": projection_fingerprint,
                "run_record": runtime.run_record(),
                "export": export,
                "validation": validation,
            }
        )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "batch_id": batch_id,
        "all_valid": all_valid,
        "run_count": len(rows),
        "runs": rows,
    }
    (root / "batch_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", action="append", type=int, dest="seeds")
    parser.add_argument("--duration-s", type=float)
    parser.add_argument("--step-s", type=float)
    parser.add_argument("--node-count", type=int)
    parser.add_argument("--attack-plan", type=Path)
    parser.add_argument("--normal-disturbance-plan", type=Path)
    parser.add_argument("--traffic-plan", type=Path)
    parser.add_argument("--session-lifecycle-plan", type=Path)
    parser.add_argument(
        "--calibration-profile",
        type=Path,
        help="Validated CalibrationProfile JSON used by every run in this batch.",
    )
    parser.add_argument(
        "--run-config",
        type=Path,
        help="Complete strict RunConfig JSON; explicit CLI plan options override it.",
    )
    parser.add_argument(
        "--require-formal-security", action="store_true", default=None
    )
    parser.add_argument(
        "--dataset-maturity",
        choices=("DEVELOPMENT", "PRELIMINARY", "FORMAL"),
        default=None,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_config = None
    if args.run_config is not None:
        run_config = json.loads(args.run_config.read_text(encoding="utf-8"))
        if not isinstance(run_config, dict):
            raise ValueError("run-config JSON must be an object")
    summary = run_batch(
        args.output_dir,
        seeds=args.seeds or [42],
        duration_s=args.duration_s,
        step_s=args.step_s,
        node_count=args.node_count,
        attack_specs=(
            _load_attacks(args.attack_plan) if args.attack_plan is not None else None
        ),
        normal_disturbance_specs=(
            _load_normal_disturbances(args.normal_disturbance_plan)
            if args.normal_disturbance_plan is not None
            else None
        ),
        traffic_specs=(
            _load_plans(
                args.traffic_plan,
                collection_key="traffic_specs",
                description="traffic-plan",
            )
            if args.traffic_plan is not None
            else None
        ),
        session_lifecycle_specs=(
            _load_plans(
                args.session_lifecycle_plan,
                collection_key="session_lifecycle_specs",
                description="session-lifecycle-plan",
            )
            if args.session_lifecycle_plan is not None
            else None
        ),
        require_formal_security=args.require_formal_security,
        dataset_maturity=args.dataset_maturity,
        run_config=run_config,
        calibration_profile_path=args.calibration_profile,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["all_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
