"""Secret-boundary audit for Person-A integration artifacts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class SecretLeakageFinding:
    path: str
    reason: str


class PersonASecretLeakageAudit:
    """Rule scan plus exact-secret representation scan.

    Public nonces, key handles, algorithms and public identity identifiers are
    intentionally allowed. Callers may supply integration-fixture secrets so
    byte, hex and base64 copies are detected without logging those values.
    """

    FORBIDDEN_KEYS = {
        "raw_key",
        "key_material",
        "private_key",
        "private_key_pem",
        "master_key",
        "credential_serial",
        "derived_secret",
        "candidate_key",
        "quantized_secret_bits",
        "privacy_amplification_intermediate",
    }

    @classmethod
    def scan(
        cls, value: Any, *, known_secrets: Iterable[bytes] = ()
    ) -> list[SecretLeakageFinding]:
        findings: list[SecretLeakageFinding] = []
        encoded: set[str] = set()
        raw_values: list[bytes] = []
        for secret in known_secrets:
            raw = bytes(secret)
            if not raw:
                continue
            raw_values.append(raw)
            encoded.add(raw.hex().lower())
            encoded.add(base64.b64encode(raw).decode("ascii"))

        def visit(item: Any, path: str) -> None:
            if isinstance(item, dict):
                for key, child in item.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    if str(key).lower() in cls.FORBIDDEN_KEYS:
                        findings.append(SecretLeakageFinding(child_path, "FORBIDDEN_SECRET_FIELD"))
                    visit(child, child_path)
            elif isinstance(item, list):
                for index, child in enumerate(item):
                    visit(child, f"{path}[{index}]")
            elif isinstance(item, bytes):
                if any(secret in item for secret in raw_values):
                    findings.append(SecretLeakageFinding(path, "KNOWN_SECRET_BYTES"))
            elif isinstance(item, str):
                lowered = item.lower()
                if "-----begin private key-----" in lowered:
                    findings.append(SecretLeakageFinding(path, "PRIVATE_PEM"))
                if any(token and token in item for token in encoded):
                    findings.append(SecretLeakageFinding(path, "KNOWN_SECRET_ENCODING"))

        visit(value, "")
        return findings

