"""Terminal-profile binding and anti-copy authorization simulation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


AUTHORIZED_EVENTS = {"PROGRAM_START", "NETWORK_JOIN", "SENSITIVE_COMMAND"}


@dataclass(slots=True)
class TerminalProfile:
    terminal_id: str
    hardware_fingerprint_attributes: dict[str, str]
    software_environment: dict[str, str]
    os_environment: dict[str, str]

    def public_fingerprint(self) -> str:
        payload = asdict(self)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class TerminalAuthorizer:
    """Uses an opaque credential handle; no A-owned key material is logged."""

    implementation_status = "INTERFACE_READY"

    def __init__(self) -> None:
        self._bindings: dict[str, str] = {}

    @staticmethod
    def _binding(profile: TerminalProfile, credential_handle: str) -> str:
        return hashlib.sha256(
            f"{profile.public_fingerprint()}:{credential_handle}".encode("utf-8")
        ).hexdigest()

    def enroll(self, profile: TerminalProfile, credential_handle: str) -> dict[str, Any]:
        self._bindings[profile.terminal_id] = self._binding(profile, credential_handle)
        return {
            "terminal_id": profile.terminal_id,
            "status": "ENROLLED",
            "credential_state": "OPAQUE_HANDLE_BOUND",
        }

    def is_enrolled(self, terminal_id: str) -> bool:
        return terminal_id in self._bindings

    def authorize(
        self,
        event: str,
        profile: TerminalProfile,
        credential_handle: str,
    ) -> dict[str, Any]:
        if event not in AUTHORIZED_EVENTS:
            return {
                "event": event,
                "terminal_id": profile.terminal_id,
                "allowed": False,
                "failure_reason": "UNSUPPORTED_AUTHORIZATION_EVENT",
            }
        expected = self._bindings.get(profile.terminal_id)
        presented = self._binding(profile, credential_handle)
        allowed = expected is not None and expected == presented
        return {
            "event": event,
            "terminal_id": profile.terminal_id,
            "allowed": allowed,
            "failure_reason": None if allowed else "TERMINAL_PROFILE_BINDING_MISMATCH",
        }
