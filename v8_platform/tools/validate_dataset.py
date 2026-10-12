"""Validate a dataset directory against the frozen schema-3 contract."""

from __future__ import annotations

import argparse
import json

from swarm_sim.validation import DatasetValidator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_dir")
    args = parser.parse_args(argv)
    report = DatasetValidator().validate(args.dataset_dir).to_dict()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
