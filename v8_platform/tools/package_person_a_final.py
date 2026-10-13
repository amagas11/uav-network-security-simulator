"""Build the portable V8 + Person-A integration delivery archive."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ARCHIVE_ROOT = "V8_PERSON_A_FINAL"
EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "work",
    }
)
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})
FIXED_ZIP_TIMESTAMP = (2026, 9, 13, 0, 0, 0)
PORTABLE_FILE_NAMES = {
    "v8_platform/A_B_无线观测字段说明.md": "v8_platform/A_B_wireless_observation_fields.md",
    "v8_platform/c需求文档.md": "v8_platform/c_requirements.md",
    "v8_platform/UAV 前端部署说明.md": "v8_platform/UAV_frontend_deployment.md",
    "v8_platform/交付清单.md": "v8_platform/delivery_manifest.md",
    "v8_platform/分工安排.md": "v8_platform/work_assignment.md",
    (
        "person_a_crypto/upstream/docs/person_a/A1-B所需无线观测.md"
    ): "person_a_crypto/upstream/docs/person_a/A1_B_required_wireless_observations.md",
    (
        "person_a_crypto/upstream/docs/person_a/A1-观测与密码接口.md"
    ): "person_a_crypto/upstream/docs/person_a/A1_observation_crypto_interface.md",
}


def _is_excluded(relative: Path) -> bool:
    return (
        any(part in EXCLUDED_DIRECTORIES for part in relative.parts)
        or relative.suffix.lower() in EXCLUDED_SUFFIXES
        or relative.name in {".coverage", "coverage.xml"}
        or relative.as_posix() == "PORTABLE_PATH_MAP.json"
    )


def _validate_bundle(bundle_root: Path) -> None:
    required = (
        bundle_root / "v8_platform" / "swarm_sim" / "__init__.py",
        bundle_root
        / "person_a_crypto"
        / "upstream"
        / "crypto"
        / "__init__.py",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise ValueError(f"PORTABLE_BUNDLE_MISSING_REQUIRED_FILES:{missing}")

    non_ascii_directories = sorted(
        {
            str(path.relative_to(bundle_root))
            for path in bundle_root.rglob("*")
            if path.is_dir() and not path.name.isascii()
        }
    )
    if non_ascii_directories:
        raise ValueError(
            "NON_ASCII_CANONICAL_DIRECTORY:" + ",".join(non_ascii_directories)
        )


def _portable_relative(relative: Path) -> PurePosixPath:
    source = relative.as_posix()
    portable = PurePosixPath(PORTABLE_FILE_NAMES.get(source, source))
    if not all(part.isascii() for part in portable.parts):
        raise ValueError(f"NON_ASCII_ARCHIVE_PATH_WITHOUT_MAPPING:{source}")
    return portable


def _write_bytes(
    archive: ZipFile, arcname: str, data: bytes, *, mode: int = 0o100644
) -> None:
    info = ZipInfo(arcname, date_time=FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_DEFLATED
    info.external_attr = (mode & 0xFFFF) << 16
    archive.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)


def build_portable_archive(bundle_root: str | Path, output: str | Path) -> dict[str, object]:
    """Create a deterministic archive with one canonical Person-A source tree."""

    root = Path(bundle_root).resolve()
    destination = Path(output).resolve()
    _validate_bundle(root)
    if destination == root or root in destination.parents:
        raise ValueError("ARCHIVE_OUTPUT_MUST_BE_OUTSIDE_BUNDLE_ROOT")
    destination.parent.mkdir(parents=True, exist_ok=True)

    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and not _is_excluded(path.relative_to(root))
    ]
    files.sort(key=lambda path: path.relative_to(root).as_posix())
    archive_names: set[str] = set()
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(root)
            portable = _portable_relative(relative)
            arcname = f"{ARCHIVE_ROOT}/{portable.as_posix()}"
            if arcname in archive_names:
                raise ValueError(f"PORTABLE_ARCHIVE_NAME_COLLISION:{arcname}")
            archive_names.add(arcname)
            _write_bytes(
                archive,
                arcname,
                path.read_bytes(),
                mode=path.stat().st_mode,
            )
        path_map = {
            "policy": "ASCII archive paths; source bytes unchanged",
            "renamed_files": PORTABLE_FILE_NAMES,
        }
        _write_bytes(
            archive,
            f"{ARCHIVE_ROOT}/PORTABLE_PATH_MAP.json",
            json.dumps(path_map, ensure_ascii=False, indent=2, sort_keys=True).encode(
                "utf-8"
            ),
        )

    digest = hashlib.sha256(destination.read_bytes()).hexdigest().upper()
    with ZipFile(destination) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if any("\\" in name or name.startswith("/") or ".." in Path(name).parts for name in names):
            raise ValueError("NON_PORTABLE_ARCHIVE_PATH")
        if any(
            part in EXCLUDED_DIRECTORIES
            for name in names
            for part in Path(name).parts
        ):
            raise ValueError("CACHE_OR_WORK_DIRECTORY_IN_ARCHIVE")
        if len(
            [name for name in names if "/person_a_crypto/upstream/crypto/__init__.py" in name]
        ) != 1:
            raise ValueError("PERSON_A_UPSTREAM_MUST_HAVE_ONE_CANONICAL_COPY")
        if not all(part.isascii() for name in names for part in PurePosixPath(name).parts):
            raise ValueError("NON_ASCII_FINAL_ARCHIVE_PATH")

    return {
        "archive": str(destination),
        "archive_root": ARCHIVE_ROOT,
        "file_count": len(entries),
        "sha256": digest,
        "utf8_filename_entries": sum(bool(item.flag_bits & 0x800) for item in entries),
        "renamed_file_count": len(PORTABLE_FILE_NAMES),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="directory containing v8_platform and person_a_crypto/upstream",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            build_portable_archive(args.bundle_root, args.output),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
