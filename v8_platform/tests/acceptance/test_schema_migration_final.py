"""Acceptance evidence for V6P-SCHEMA-MIGRATION-001."""

from __future__ import annotations

import json
from pathlib import Path

from tools.migrate_dataset import migrate_dataset


def test_schema2_migration_utility_rejects_unrecoverable_truth_without_guessing(
    tmp_path: Path,
):
    source = tmp_path / "schema2"
    source.mkdir()
    (source / "schema.json").write_text(
        json.dumps({"schema_version": "2.0.0"}), encoding="utf-8"
    )
    for name in ("runs.jsonl", "events.jsonl", "labels.jsonl", "rf_manifest.jsonl"):
        (source / name).write_text("", encoding="utf-8")
    target = tmp_path / "schema3"

    report = migrate_dataset(source, target, target_schema="3.2.0")

    assert report["status"] == "REJECTED"
    assert report["source_schema_version"] == "2.0.0"
    assert report["target_schema_version"] == "3.2.0"
    assert report["migration_tool_version"]
    assert report["source_dataset_sha256"]
    assert report["unrecoverable_fields"]
    assert (target / "migration_report.json").exists()
    assert not (target / "events.jsonl").exists()
