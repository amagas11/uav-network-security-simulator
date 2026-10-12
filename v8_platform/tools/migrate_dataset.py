"""Conservative dataset migration analysis for frozen schema contracts.

Schema 2 data cannot faithfully recover V7 opaque identifiers, resolved plans,
business-execution outcomes, or provider maturity.  This tool therefore emits
a machine-readable incompatibility report instead of guessing those values.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


MIGRATION_TOOL_VERSION = "schema-migrator-v1"
CURRENT_SCHEMA_VERSION = "3.2.0"

_SCHEMA2_UNRECOVERABLE = [
    "opaque online session/link/probe/flow identifiers",
    "requested versus resolved attack plan",
    "attack attempted/injected/reached-target/business-executed stages",
    "external participant contract",
    "model and security provider maturity provenance",
    "observer-local plaintext protection risk availability",
]


def _dataset_hash(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        relative = path.relative_to(source).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _read_schema_version(source: Path) -> str:
    schema_path = source / "schema.json"
    if not schema_path.is_file():
        raise ValueError("SOURCE_SCHEMA_MISSING")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("SOURCE_SCHEMA_INVALID") from exc
    version = schema.get("schema_version") if isinstance(schema, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError("SOURCE_SCHEMA_VERSION_MISSING")
    return version


def migrate_dataset(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    target_schema: str = CURRENT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Assess a migration and write a report without inventing semantics.

    V7 intentionally rejects 2.x -> 3.2 migration because the missing semantic
    evidence cannot be reconstructed from the old JSONL records.  Re-generating
    the run from its original scenario is the supported path.
    """

    source = Path(input_dir).resolve()
    destination = Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError("SOURCE_DATASET_DIRECTORY_MISSING")
    if source == destination:
        raise ValueError("MIGRATION_OUTPUT_MUST_DIFFER_FROM_INPUT")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("MIGRATION_OUTPUT_DIRECTORY_NOT_EMPTY")
    if target_schema != CURRENT_SCHEMA_VERSION:
        raise ValueError(f"UNSUPPORTED_TARGET_SCHEMA:{target_schema}")

    source_version = _read_schema_version(source)
    source_hash = _dataset_hash(source)
    major = source_version.split(".", 1)[0]
    if major == "2":
        status = "REJECTED"
        warnings = [
            "Schema 2 records cannot be upgraded without fabricating V7 semantics.",
            "Re-run the source scenario with platform-v7 when reproducible source configuration is available.",
        ]
        unrecoverable = list(_SCHEMA2_UNRECOVERABLE)
    elif source_version == target_schema:
        status = "NO_MIGRATION_REQUIRED"
        warnings = ["Source dataset already uses the requested schema."]
        unrecoverable = []
    else:
        status = "REJECTED"
        warnings = [
            f"No reviewed migration path exists from {source_version} to {target_schema}."
        ]
        unrecoverable = ["unreviewed source-to-target semantic differences"]

    report: dict[str, Any] = {
        "status": status,
        "source_schema_version": source_version,
        "target_schema_version": target_schema,
        "migration_tool_version": MIGRATION_TOOL_VERSION,
        "migration_time_utc": datetime.now(timezone.utc).isoformat(),
        "source_dataset_sha256": source_hash,
        "warnings": warnings,
        "unrecoverable_fields": unrecoverable,
        "data_files_written": False,
    }
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "migration_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-schema", default=CURRENT_SCHEMA_VERSION)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = migrate_dataset(
        args.input, args.output, target_schema=args.target_schema
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "NO_MIGRATION_REQUIRED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
