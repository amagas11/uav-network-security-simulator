from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

from tools.package_person_a_final import (
    ARCHIVE_ROOT,
    PORTABLE_FILE_NAMES,
    build_portable_archive,
)


def test_final_package_has_ascii_directories_and_default_extractall_works(tmp_path):
    bundle_root = Path(__file__).resolve().parents[4]
    archive_path = tmp_path / "portable.zip"
    manifest = build_portable_archive(bundle_root, archive_path)

    assert manifest["archive_root"] == ARCHIVE_ROOT
    assert manifest["file_count"] > 0
    with ZipFile(archive_path) as archive:
        names = archive.namelist()
        assert all(name.startswith(f"{ARCHIVE_ROOT}/") for name in names)
        assert all("\\" not in name for name in names)
        assert all(part.isascii() for name in names for part in Path(name).parts)
        assert not any("__pycache__" in Path(name).parts for name in names)
        assert not any(".pytest_cache" in Path(name).parts for name in names)
        assert not any(name.endswith((".pyc", ".pyo")) for name in names)
        assert f"{ARCHIVE_ROOT}/PORTABLE_PATH_MAP.json" in names
        for source, portable in PORTABLE_FILE_NAMES.items():
            source_path = bundle_root / Path(source)
            if not source_path.is_file():
                source_path = bundle_root / Path(portable)
            assert archive.read(f"{ARCHIVE_ROOT}/{portable}") == (
                source_path.read_bytes()
            )
        archive.extractall(tmp_path / "fresh")

    extracted = tmp_path / "fresh" / ARCHIVE_ROOT
    upstream = extracted / "person_a_crypto" / "upstream"
    platform = extracted / "v8_platform"
    assert (upstream / "crypto" / "__init__.py").is_file()
    assert (platform / "swarm_sim" / "__init__.py").is_file()
    assert not (extracted / "person_a_crypto" / "无人机").exists()

    subprocess.run(
        [sys.executable, "-c", "from crypto.key_provider import KeyProvider; KeyProvider(1)"],
        cwd=upstream,
        check=True,
        timeout=30,
    )
    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "from swarm_sim.integrations.person_a import PersonASecurityBundleFactory; "
                "PersonASecurityBundleFactory(Path('../person_a_crypto/upstream'))"
            ),
        ],
        cwd=platform,
        check=True,
        timeout=30,
    )
