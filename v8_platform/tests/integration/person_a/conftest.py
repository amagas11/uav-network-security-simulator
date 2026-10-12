from __future__ import annotations

import os
from pathlib import Path

import pytest


def _library_root() -> Path:
    configured = os.environ.get("PERSON_A_CRYPTO_ROOT")
    if configured:
        return Path(configured).resolve()
    here = Path(__file__).resolve()
    # Canonical portable delivery layout:
    # V8_PERSON_A_FINAL/{v8_platform,person_a_crypto/upstream}.
    candidates = [
        here.parents[4] / "person_a_crypto" / "upstream",
    ]
    return next(
        (candidate.resolve() for candidate in candidates if candidate.is_dir()),
        candidates[0].resolve(),
    )


@pytest.fixture(scope="session")
def person_a_root() -> Path:
    root = _library_root()
    if not (root / "crypto" / "__init__.py").is_file():
        pytest.fail(f"required Person-A delivery is unavailable: {root}")
    return root
