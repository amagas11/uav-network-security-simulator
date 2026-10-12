"""C-facing UTF-8 JSONL schema-3 dataset export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .simulation import SCHEMA_VERSION


def schema_v1() -> dict[str, Any]:
    schema_path = Path(__file__).resolve().parents[1] / "dataset" / "schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if schema.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("on-disk dataset schema does not match runtime schema version")
    return schema


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            stream.write("\n")


class DatasetExporter:
    def export(
        self,
        output_dir: str | Path,
        *,
        run_record: dict[str, Any],
        events: list[dict[str, Any]],
        labels: list[dict[str, Any]],
        rf_manifest: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        (root / "rf_samples").mkdir(exist_ok=True)
        (root / "schema.json").write_text(
            json.dumps(schema_v1(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        _write_jsonl(root / "runs.jsonl", [run_record])
        _write_jsonl(root / "events.jsonl", events)
        _write_jsonl(root / "labels.jsonl", labels)
        _write_jsonl(root / "rf_manifest.jsonl", rf_manifest or [])
        return {
            "status": "EXPORTED",
            "schema_version": SCHEMA_VERSION,
            "output_dir": str(root.resolve()),
            "counts": {
                "runs": 1,
                "events": len(events),
                "labels": len(labels),
                "rf_samples": len(rf_manifest or []),
            },
        }
