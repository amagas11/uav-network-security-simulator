"""Adapters joining the independent Person-A library to the V8 runtime.

This module is intentionally the only B-side place aware of Person-A Python
types.  It loads the upstream package from its own directory, converts V8 PHY
observations through mappings, keeps one A ``KeyProvider`` per legitimate
node, and never reads raw key material from those providers.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import base64
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Callable, Iterable

from ...adapters import (
    CryptoOpenResult,
    CryptoProtectionError,
    KeyReference,
    RekeyResult,
)
from ...domain import Frame, Message, NodeRole
from ...packets import serialized_application_size
from ...probe import (
    PERSON_A_V01_COMPAT_PROBE_PROFILE,
    SUPPORTED_PROBE_PROFILES,
    V8_DEFAULT_PROBE_PROFILE,
)


class PersonACryptoNotAvailable(RuntimeError):
    """Raised only when PERSON_A mode was explicitly selected."""


def _load_person_a_library(root: str | Path) -> Any:
    root_path = Path(root).resolve()
    package_dir = root_path / "crypto"
    init_file = package_dir / "__init__.py"
    if not init_file.is_file():
        raise PersonACryptoNotAvailable(
            f"PERSON_A_CRYPTO_NOT_AVAILABLE: {root_path} has no crypto package"
        )
    token = hashlib.sha256(str(root_path).encode("utf-8")).hexdigest()[:12]
    package_name = f"person_a_crypto_upstream_{token}"
    if package_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            package_name,
            init_file,
            submodule_search_locations=[str(package_dir)],
        )
        if spec is None or spec.loader is None:
            raise PersonACryptoNotAvailable("PERSON_A_CRYPTO_NOT_AVAILABLE")
        module = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = module
        spec.loader.exec_module(module)
    try:
        return type(
            "PersonALibrary",
            (),
            {
                "package": sys.modules[package_name],
                "key_provider": importlib.import_module(f"{package_name}.key_provider"),
                "skg": importlib.import_module(f"{package_name}.skg"),
                "identity": importlib.import_module(f"{package_name}.identity"),
                "credentials": importlib.import_module(f"{package_name}.credentials"),
                "observations": importlib.import_module(f"{package_name}.observations"),
                "types": importlib.import_module(f"{package_name}.types"),
                "root": root_path,
            },
        )()
    except Exception as exc:  # pragma: no cover - invalid upstream installation
        raise PersonACryptoNotAvailable(
            f"PERSON_A_CRYPTO_NOT_AVAILABLE: {type(exc).__name__}"
        ) from exc


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def build_aad(
    *,
    message_id: str,
    claimed_src_id: int | None,
    claimed_dst_id: int | None,
    packet_type: str,
    sequence_no: int,
    session_id: str,
    key_epoch: int | str,
    sender_id: int,
    receiver_id: int,
    link_id: str,
    hop_index: int,
) -> bytes:
    """Canonical immutable hop AAD shared byte-for-byte by protect/open."""

    return _json_bytes(
        {
            "message_id": message_id,
            "claimed_src_id": claimed_src_id,
            "claimed_dst_id": claimed_dst_id,
            "packet_type": packet_type,
            "sequence_no": sequence_no,
            "session_id": session_id,
            "key_epoch": key_epoch,
            "link_sender_id": sender_id,
            "link_receiver_id": receiver_id,
            "internal_link_id": link_id,
            "hop_index": hop_index,
        }
    )


@dataclass(slots=True)
class _Handshake:
    first_id: int
    second_id: int
    session_id: str
    key_epoch: int
    probe_id: str
    engines: dict[int, Any]
    previous_epochs: dict[int, int | None] = field(default_factory=dict)
    status: str = "NEGOTIATING"
    state_history: list[str] = field(default_factory=lambda: ["NEGOTIATING"])
    received_reconcile: set[int] = field(default_factory=set)
    received_confirm: set[int] = field(default_factory=set)
    generated_confirm_blobs: dict[int, bytes] = field(default_factory=dict)
    pending_confirm_blobs: dict[int, bytes] = field(default_factory=dict)
    control_message_ids: list[str] = field(default_factory=list)
    started_at_s: float = 0.0
    completed_at_s: float | None = None
    failure_reason: str | None = None
    rollback_results: dict[int, dict[str, Any]] = field(default_factory=dict)


class RekeyCoordinator:
    """Own the one-active-handshake invariant for a pair/session/epoch."""

    ACTIVE_STATES = frozenset(
        {"NEGOTIATING", "CONFIRM_PENDING", "COMMIT_READY", "UPDATING"}
    )

    def __init__(self) -> None:
        self._by_key: dict[tuple[int, int, str, int], str] = {}

    @staticmethod
    def key(
        first_id: int, second_id: int, session_id: str, target_epoch: int
    ) -> tuple[int, int, str, int]:
        first, second = sorted((int(first_id), int(second_id)))
        return first, second, str(session_id), int(target_epoch)

    def active_probe(
        self,
        first_id: int,
        second_id: int,
        session_id: str,
        target_epoch: int,
        handshakes: dict[str, _Handshake],
    ) -> str | None:
        probe_id = self._by_key.get(
            self.key(first_id, second_id, session_id, target_epoch)
        )
        if probe_id is None:
            return None
        handshake = handshakes.get(probe_id)
        if handshake is None or handshake.status not in self.ACTIVE_STATES:
            return None
        return probe_id

    def reserve(self, handshake: _Handshake) -> None:
        self._by_key[
            self.key(
                handshake.first_id,
                handshake.second_id,
                handshake.session_id,
                handshake.key_epoch,
            )
        ] = handshake.probe_id

    def active_count(self, handshakes: dict[str, _Handshake]) -> int:
        return sum(
            1
            for probe_id in self._by_key.values()
            if probe_id in handshakes
            and handshakes[probe_id].status in self.ACTIVE_STATES
        )


class PersonAKeyCoordinator:
    """Runtime-level facade over independent node-local A key providers."""

    implementation_status = "PERSON_A_INTEGRATED_DEVELOPMENT"
    version = (
        "person-a-0.1+v8-adapter-1.2+skg-v8-network-2pc+rollback+identity-"
        "ed25519-test-only-generated-identity"
    )

    def __init__(
        self,
        library: Any,
        node_ids: Iterable[int],
        *,
        timeout_s: float = 3.0,
        identities: dict[int, Any] | None = None,
        identity_mode: str = "Ed25519_TEST_ONLY_GENERATED_IDENTITY",
        probe_profile: str = V8_DEFAULT_PROBE_PROFILE,
    ) -> None:
        if probe_profile not in SUPPORTED_PROBE_PROFILES:
            raise ValueError(f"UNSUPPORTED_PROBE_PROFILE:{probe_profile}")
        self.library = library
        self.node_ids = tuple(sorted(int(value) for value in node_ids))
        self.providers = {
            node_id: library.key_provider.KeyProvider(node_id)
            for node_id in self.node_ids
        }
        if identities is None:
            self.identities = {
                node_id: library.identity.IdentityStore.generate(
                    node_id, f"person-a-test-node-{node_id}"
                )
                for node_id in self.node_ids
            }
        else:
            self.identities = {int(key): value for key, value in identities.items()}
            if set(self.identities) != set(self.node_ids) or any(
                int(getattr(store, "node_id", -10_000)) != node_id
                for node_id, store in self.identities.items()
            ):
                raise ValueError("PERSON_A_IDENTITY_SET_DOES_NOT_MATCH_RUNTIME_NODES")
        self.identity_mode = str(identity_mode)
        identity_slug = self.identity_mode.lower().replace("_", "-")
        self.version = (
            "person-a-0.1+v8-adapter-1.2+skg-v8-network-2pc+rollback+identity-"
            f"{identity_slug}"
        )
        self.probe_profile = probe_profile
        public = {
            node_id: store.public_material()
            for node_id, store in self.identities.items()
        }
        for local_id, store in self.identities.items():
            for peer_id, material in public.items():
                if peer_id != local_id:
                    store.trust_public(material)
        self.timeout_s = float(timeout_s)
        self.runtime: Any | None = None
        self.handshakes: dict[str, _Handshake] = {}
        self.rekey_coordinator = RekeyCoordinator()
        self._references: dict[tuple[int, int, str, int], str] = {}
        self.audit_log: list[dict[str, Any]] = []

    def attach_runtime(self, runtime: Any) -> None:
        self.runtime = runtime

    def reset(self, run_info: dict[str, Any]) -> None:
        # A fresh coordinator is created by RuntimeDependencies for every run.
        # Runtime's conventional reset hook therefore records context only.
        self._run_id = str(run_info.get("run_id", ""))

    def provider_for(self, node_id: int) -> Any | None:
        return self.providers.get(int(node_id))

    @property
    def active_rekey_count(self) -> int:
        return self.rekey_coordinator.active_count(self.handshakes)

    @staticmethod
    def _epoch(value: int | str) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        try:
            return int(str(value))
        except ValueError:
            return None

    def key_reference(
        self, local_id: int, peer_id: int, session_id: str, key_epoch: int | str
    ) -> KeyReference:
        provider = self.provider_for(local_id)
        epoch = self._epoch(key_epoch)
        if provider is None or epoch is None:
            return KeyReference(None, key_epoch, "MISSING", "KEY_UNAVAILABLE")
        status = str(
            provider.get_status(
                int(peer_id), str(session_id), key_epoch=epoch,
                sim_time_s=self._sim_time(),
            )
        )
        state = {
            "ok": "AVAILABLE",
            "key_expired": "EXPIRED",
            "key_revoked": "REVOKED",
        }.get(status, "MISSING")
        return KeyReference(
            self._references.get((int(local_id), int(peer_id), str(session_id), epoch)),
            epoch,
            state,
            None if state == "AVAILABLE" else status.upper(),
        )

    def current_epoch(self, local_id: int, peer_id: int, session_id: str) -> int | None:
        candidates = [
            epoch
            for (left, right, session, epoch), _handle in self._references.items()
            if left == int(local_id)
            and right == int(peer_id)
            and session == str(session_id)
            and self.key_reference(left, right, session, epoch).state == "AVAILABLE"
        ]
        return max(candidates) if candidates else None

    def preload_test_key(
        self,
        first_id: int,
        second_id: int,
        session_id: str,
        key: bytes,
        *,
        key_epoch: int = 1,
    ) -> None:
        """Explicit integration-test fixture; no production caller uses it."""

        for local_id, peer_id in ((first_id, second_id), (second_id, first_id)):
            event = self.providers[local_id].put(
                peer_id, session_id, key, key_epoch=key_epoch, sim_time_s=self._sim_time()
            )
            if str(event.status) != "ok":
                raise ValueError(f"PERSON_A_TEST_KEY_INSTALL_FAILED:{event.status}")
            self._references[(local_id, peer_id, session_id, key_epoch)] = str(event.key_id)

    def request_rekey(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        current_key_epoch: int | str,
    ) -> RekeyResult:
        previous = self._epoch(current_key_epoch)
        if previous is None:
            return RekeyResult(
                False, current_key_epoch, None, ["UNKNOWN", "FAILED"],
                "INVALID_KEY_EPOCH", self.implementation_status,
            )
        result = self.initiate_session(
            int(local_id), int(peer_id), str(session_id), key_epoch=previous + 1
        )
        if not result["accepted"]:
            reason = str(result.get("failure_reason") or "SKG_START_FAILED")
            return RekeyResult(
                False,
                previous,
                None,
                [
                    self.key_reference(local_id, peer_id, session_id, previous).state,
                    (
                        "UPDATING"
                        if reason == "existing_rekey_in_progress"
                        else "FAILED"
                    ),
                ],
                reason,
                self.implementation_status,
            )
        return RekeyResult(
            True,
            previous,
            None,
            [self.key_reference(local_id, peer_id, session_id, previous).state, "UPDATING"],
            None,
            self.implementation_status,
        )

    def ensure_session(
        self, first_id: int, second_id: int, session_id: str, key_epoch: int | str
    ) -> dict[str, Any]:
        epoch = self._epoch(key_epoch)
        if epoch is None:
            return {"accepted": False, "failure_reason": "INVALID_KEY_EPOCH"}
        existing = self.key_reference(first_id, second_id, session_id, epoch)
        if existing.state == "AVAILABLE":
            return {"accepted": True, "state": "AVAILABLE"}
        return self.initiate_session(first_id, second_id, session_id, key_epoch=epoch)

    def initiate_session(
        self, first_id: int, second_id: int, session_id: str, *, key_epoch: int = 1
    ) -> dict[str, Any]:
        runtime = self.runtime
        first_id, second_id = int(first_id), int(second_id)
        if runtime is None:
            return {"accepted": False, "failure_reason": "RUNTIME_NOT_ATTACHED"}
        if first_id not in self.providers or second_id not in self.providers:
            return {"accepted": False, "failure_reason": "LEGITIMATE_PROVIDER_REQUIRED"}
        existing_probe = self.rekey_coordinator.active_probe(
            first_id,
            second_id,
            str(session_id),
            int(key_epoch),
            self.handshakes,
        )
        if existing_probe is not None:
            existing = self.handshakes[existing_probe]
            return {
                "accepted": False,
                "state": existing.status,
                "failure_reason": "existing_rekey_in_progress",
                "probe_id": existing_probe,
            }
        first_obs, second_obs = runtime.probes.probe(
            first_id,
            second_id,
            sample_count=64,
            session_id=str(session_id),
            measurement_kind="csi",
        )
        probe_id = first_obs.probe_id
        engines = {
            first_id: self.library.skg.SkgEngine(
                first_id, self.providers[first_id], key_epoch=int(key_epoch)
            ),
            second_id: self.library.skg.SkgEngine(
                second_id, self.providers[second_id], key_epoch=int(key_epoch)
            ),
        }
        # Cross the integration boundary through plain mappings exactly as A's
        # contract specifies. Each engine receives only its own observation.
        converted = {
            first_id: self.library.observations.LocalPhyObservation.from_mapping(
                first_obs.to_dict()
            ),
            second_id: self.library.observations.LocalPhyObservation.from_mapping(
                second_obs.to_dict()
            ),
        }
        first_result = engines[first_id].on_local_observation(converted[first_id])
        second_result = engines[second_id].on_local_observation(converted[second_id])
        handshake = _Handshake(
            first_id,
            second_id,
            str(session_id),
            int(key_epoch),
            probe_id,
            engines,
            previous_epochs={
                first_id: self.current_epoch(first_id, second_id, str(session_id)),
                second_id: self.current_epoch(second_id, first_id, str(session_id)),
            },
            started_at_s=self._sim_time(),
        )
        self.handshakes[probe_id] = handshake
        self.rekey_coordinator.reserve(handshake)
        if first_obs.missing or second_obs.missing or any(
            str(item.status) != "ok" for item in (first_result, second_result)
        ):
            self._fail(handshake, first_obs.missing_reason or second_obs.missing_reason or "SKG_OBSERVATION_FAILED")
            return {"accepted": False, "failure_reason": handshake.failure_reason, "probe_id": probe_id}
        for sender_id, receiver_id in ((first_id, second_id), (second_id, first_id)):
            made = engines[sender_id].make_reconcile_blob(probe_id)
            if str(made.status) != "ok" or made.blob is None:
                self._fail(handshake, "SKG_RECONCILE_CREATE_FAILED")
                return {"accepted": False, "failure_reason": handshake.failure_reason, "probe_id": probe_id}
            if not self._queue_control(handshake, sender_id, receiver_id, "RECONCILE", made.blob):
                self._fail(handshake, "SKG_CONTROL_QUEUE_FAILED")
                return {"accepted": False, "failure_reason": handshake.failure_reason, "probe_id": probe_id}
        self.audit_log.append(
            {
                "event": "SKG_STARTED",
                "probe_id": probe_id,
                "session_id": session_id,
                "key_epoch": key_epoch,
                "participants": [first_id, second_id],
                "observation_source": "V8_PROBE_SERVICE",
                "probe_profile": self.probe_profile,
            }
        )
        return {"accepted": True, "state": handshake.status, "probe_id": probe_id}

    def _queue_control(
        self,
        handshake: _Handshake,
        sender_id: int,
        receiver_id: int,
        phase: str,
        blob: bytes,
    ) -> bool:
        signed = self.identities[sender_id].sign_handshake(
            sender_id,
            receiver_id,
            handshake.session_id,
            handshake.probe_id,
            blob,
        )
        if str(signed.status) != "ok" or signed.signature is None:
            return False
        payload = {
            "protocol": "PERSON_A_SKG_V1",
            "phase": phase,
            "probe_id": handshake.probe_id,
            "session_id": handshake.session_id,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "identity_id": signed.identity_id,
            "public_key_pem": signed.public_key_pem,
            "blob_b64": base64.b64encode(blob).decode("ascii"),
            "signature_b64": base64.b64encode(signed.signature).decode("ascii"),
        }
        message_id = self.runtime.queue_message(
            sender_id,
            receiver_id,
            "SKG_CONTROL",
            payload,
            sensitive=False,
            encrypt=False,
            session_id=handshake.session_id,
            extensions={
                "security_control": {
                    "protocol": "PERSON_A_SKG_V1",
                    "phase": phase,
                    "public_blob_length": len(blob),
                }
            },
        )
        if message_id is not None:
            handshake.control_message_ids.append(message_id)
            return True
        return False

    def verify_control(self, payload: dict[str, Any], receiver_id: int) -> tuple[bool, str | None]:
        try:
            sender_id = int(payload["sender_id"])
            claimed_receiver = int(payload["receiver_id"])
            session_id = str(payload["session_id"])
            probe_id = str(payload["probe_id"])
            blob = base64.b64decode(str(payload["blob_b64"]), validate=True)
            signature = base64.b64decode(str(payload["signature_b64"]), validate=True)
        except (KeyError, TypeError, ValueError):
            return False, "IDENTITY_FAIL"
        if claimed_receiver != int(receiver_id) or receiver_id not in self.identities:
            return False, "IDENTITY_FAIL"
        result = self.identities[receiver_id].verify_handshake(
            receiver_id,
            sender_id,
            session_id,
            probe_id,
            blob,
            signature=signature,
            identity_id=payload.get("identity_id"),
            public_key_pem=payload.get("public_key_pem"),
        )
        return str(result.status) == "ok", None if str(result.status) == "ok" else "IDENTITY_FAIL"

    def handle_control(self, receiver_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        probe_id = str(payload.get("probe_id", ""))
        handshake = self.handshakes.get(probe_id)
        if handshake is None or handshake.status in {"FAILED", "AVAILABLE"}:
            return {"accepted": False, "failure_reason": "UNKNOWN_OR_FAILED_SKG"}
        sender_id = int(payload["sender_id"])
        receiver_id = int(receiver_id)
        phase = str(payload.get("phase", "")).upper()
        blob = base64.b64decode(str(payload["blob_b64"]), validate=True)
        participants = {handshake.first_id, handshake.second_id}
        if (
            {sender_id, receiver_id} != participants
            or str(payload.get("session_id")) != handshake.session_id
        ):
            self._fail(handshake, "SKG_CONTROL_SCOPE_MISMATCH")
            return {"accepted": False, "failure_reason": handshake.failure_reason}
        engine = handshake.engines[receiver_id]
        if phase == "RECONCILE":
            result = engine.apply_reconcile_blob(probe_id, blob)
            if str(result.status) != "ok":
                self._fail(handshake, "SKG_RECONCILE_MISMATCH")
                return {"accepted": False, "failure_reason": handshake.failure_reason}
            handshake.received_reconcile.add(receiver_id)
            confirm = engine.make_confirm_blob(probe_id)
            if str(confirm.status) != "ok" or confirm.blob is None or not self._queue_control(
                handshake, receiver_id, sender_id, "CONFIRM", confirm.blob
            ):
                self._fail(handshake, "SKG_CONFIRM_CREATE_FAILED")
                return {"accepted": False, "failure_reason": handshake.failure_reason}
            handshake.generated_confirm_blobs[receiver_id] = bytes(confirm.blob)
            self._transition(handshake, "CONFIRM_PENDING")
            commit = self._attempt_commit(handshake)
            return commit or {
                "accepted": True,
                "phase": phase,
                "state": handshake.status,
            }
        if phase == "CONFIRM":
            previous = handshake.pending_confirm_blobs.get(receiver_id)
            if previous is not None and previous != blob:
                self._fail(handshake, "SKG_CROSS_CONFIRM_CONFLICT")
                return {"accepted": False, "failure_reason": handshake.failure_reason}
            # Phase one: retain the authenticated public confirmation only.
            # Crucially, A.apply_confirm_blob() is not called here.
            handshake.pending_confirm_blobs[receiver_id] = bytes(blob)
            handshake.received_confirm.add(receiver_id)
            self._transition(handshake, "CONFIRM_PENDING")
            commit = self._attempt_commit(handshake)
            return commit or {
                "accepted": True,
                "phase": phase,
                "state": handshake.status,
            }
        self._fail(handshake, "UNSUPPORTED_SKG_PHASE")
        return {"accepted": False, "failure_reason": handshake.failure_reason}

    def _attempt_commit(self, handshake: _Handshake) -> dict[str, Any] | None:
        """Validate both cross-confirms before either A provider is committed."""

        participants = {handshake.first_id, handshake.second_id}
        if (
            set(handshake.generated_confirm_blobs) != participants
            or set(handshake.pending_confirm_blobs) != participants
        ):
            return None
        for receiver_id in participants:
            if (
                handshake.pending_confirm_blobs[receiver_id]
                != handshake.generated_confirm_blobs[receiver_id]
            ):
                self._fail(handshake, "SKG_CROSS_CONFIRM_CONFLICT")
                return {
                    "accepted": False,
                    "failure_reason": handshake.failure_reason,
                }

        # Phase two. A v0.1 commits inside apply_confirm_blob(), so B first
        # validates the full pair and then invokes both deterministic commits.
        # Any unexpected second-side error restores the transaction's recorded
        # predecessor on both endpoints without exporting key material.
        self._transition(handshake, "COMMIT_READY")
        results: dict[int, Any] = {}
        try:
            for receiver_id in sorted(participants):
                results[receiver_id] = handshake.engines[
                    receiver_id
                ].apply_confirm_blob(
                    handshake.probe_id,
                    handshake.pending_confirm_blobs[receiver_id],
                )
        except Exception:
            self._rollback_new_epoch(handshake)
            self._fail(handshake, "SKG_CONFIRM_COMMIT_FAILED")
            return {"accepted": False, "failure_reason": handshake.failure_reason}

        if any(
            str(result.status) != "ok"
            or result.key_epoch != handshake.key_epoch
            or result.key_id is None
            for result in results.values()
        ) or len({str(result.key_id) for result in results.values()}) != 1:
            self._rollback_new_epoch(handshake)
            self._fail(handshake, "SKG_CONFIRM_COMMIT_FAILED")
            return {"accepted": False, "failure_reason": handshake.failure_reason}

        for receiver_id, result in results.items():
            sender_id = (
                handshake.second_id
                if receiver_id == handshake.first_id
                else handshake.first_id
            )
            self._references[
                (receiver_id, sender_id, handshake.session_id, handshake.key_epoch)
            ] = str(result.key_id)
        handshake.completed_at_s = self._sim_time()
        self._transition(handshake, "AVAILABLE")
        for node_id in participants:
            if node_id in self.runtime.nodes:
                self.runtime.nodes[node_id].key_epoch = handshake.key_epoch
        self.audit_log.append(
            {
                "event": "SKG_COMPLETED",
                "probe_id": handshake.probe_id,
                "session_id": handshake.session_id,
                "key_epoch": handshake.key_epoch,
                "participants": sorted(participants),
                "completed_at_s": handshake.completed_at_s,
                "commit_protocol": "PAIRWISE_TWO_PHASE_COMMIT",
            }
        )
        return {"accepted": True, "phase": "CONFIRM", "state": handshake.status}

    def _rollback_new_epoch(self, handshake: _Handshake) -> None:
        """Abort the target epoch and restore each endpoint's valid predecessor."""

        sim_time_s = self._sim_time()
        for local_id, peer_id in (
            (handshake.first_id, handshake.second_id),
            (handshake.second_id, handshake.first_id),
        ):
            provider = self.providers[local_id]
            previous_epoch = handshake.previous_epochs.get(local_id)
            outcome: dict[str, Any] = {
                "target_epoch": handshake.key_epoch,
                "previous_epoch": previous_epoch,
                "restored": False,
            }
            rollback = getattr(provider, "rollback_epoch", None)
            if not callable(rollback):
                outcome["status"] = "ROLLBACK_API_UNAVAILABLE"
            else:
                try:
                    event = rollback(
                        peer_id,
                        handshake.session_id,
                        failed_epoch=handshake.key_epoch,
                        restore_epoch=previous_epoch,
                        sim_time_s=sim_time_s,
                    )
                    outcome["status"] = str(event.status).upper()
                    outcome["event"] = str(event.event)
                    outcome["restored"] = (
                        previous_epoch is not None
                        and str(event.status) == "ok"
                        and str(
                            provider.get_status(
                                peer_id,
                                handshake.session_id,
                                key_epoch=previous_epoch,
                                sim_time_s=sim_time_s,
                            )
                        )
                        == "ok"
                    )
                except Exception as exc:  # lifecycle failure must not crash runtime
                    outcome["status"] = "ROLLBACK_EXCEPTION"
                    outcome["error_type"] = type(exc).__name__
            if outcome["restored"] and local_id in self.runtime.nodes:
                self.runtime.nodes[local_id].key_epoch = int(previous_epoch)
            outcome["target_state"] = str(
                provider.get_status(
                    peer_id,
                    handshake.session_id,
                    key_epoch=handshake.key_epoch,
                    sim_time_s=sim_time_s,
                )
            ).upper()
            handshake.rollback_results[local_id] = outcome
            self._references.pop(
                (local_id, peer_id, handshake.session_id, handshake.key_epoch),
                None,
            )

    @staticmethod
    def _transition(handshake: _Handshake, state: str) -> None:
        if handshake.status != state:
            handshake.status = state
            handshake.state_history.append(state)

    def advance(self, sim_time_s: float) -> None:
        for handshake in self.handshakes.values():
            if handshake.status in {"AVAILABLE", "FAILED"}:
                continue
            if float(sim_time_s) - handshake.started_at_s >= self.timeout_s:
                self._fail(handshake, "SKG_NETWORK_TIMEOUT")

    def _fail(self, handshake: _Handshake, reason: str) -> None:
        if handshake.status == "FAILED":
            return
        self._transition(handshake, "FAILED")
        handshake.failure_reason = str(reason)
        self.audit_log.append(
            {
                "event": "SKG_FAILED",
                "probe_id": handshake.probe_id,
                "session_id": handshake.session_id,
                "key_epoch": handshake.key_epoch,
                "failure_reason": handshake.failure_reason,
                "previous_epochs": dict(handshake.previous_epochs),
                "rollback_results": dict(handshake.rollback_results),
            }
        )

    def _sim_time(self) -> float | None:
        if self.runtime is None:
            return None
        return float(self.runtime.context.clock.now_s)

    def provenance(self) -> dict[str, Any]:
        return {
            "provider_name": "PERSON_A_CRYPTO",
            "library_version": "person-a-0.1",
            "integration_version": "v8-adapter-1.2",
            "crypto_algorithm": "AES-256-GCM",
            "identity_mode": self.identity_mode,
            "skg_mode": "V8_PROBE_OVER_V8_NETWORK",
            "probe_profile": self.probe_profile,
            "probe_profile_maturity": (
                "TEST_ONLY"
                if self.probe_profile == PERSON_A_V01_COMPAT_PROBE_PROFILE
                else "V8_DEFAULT"
            ),
            "key_commit_protocol": "PAIRWISE_TWO_PHASE_COMMIT",
            "commit_failure_policy": "RESTORE_RECORDED_VALID_PREVIOUS_EPOCH",
            "implementation_status": self.implementation_status,
        }


class PersonACryptoProvider:
    """V8 CryptoProvider using only A KeyProvider.encrypt/decrypt APIs."""

    implementation_status = "PERSON_A_INTEGRATED_DEVELOPMENT"
    version = "person-a-0.1+v8-adapter-1.0+AES-256-GCM"

    def __init__(self, coordinator: PersonAKeyCoordinator) -> None:
        self.coordinator = coordinator

    def protect(
        self,
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> Frame:
        if message.packet_type == "SKG_CONTROL":
            return self._public_control_frame(
                message, sender_id, receiver_id, link_id, hop_index
            )
        if not message.encrypt_requested:
            return self._plaintext_frame(
                message, sender_id, receiver_id, link_id, hop_index
            )
        provider = self.coordinator.provider_for(sender_id)
        if provider is None:
            raise CryptoProtectionError(
                "KEY_UNAVAILABLE", key_state="MISSING", key_epoch=message.key_epoch
            )
        effective_epoch = self.coordinator.current_epoch(
            sender_id, receiver_id, message.session_id
        )
        if effective_epoch is None:
            effective_epoch = PersonAKeyCoordinator._epoch(message.key_epoch)
        if effective_epoch is None:
            raise CryptoProtectionError("INVALID_KEY_EPOCH", key_state="MISSING")
        aad = build_aad(
            message_id=message.message_id,
            claimed_src_id=message.claimed_src_id,
            claimed_dst_id=message.claimed_dst_id,
            packet_type=message.packet_type,
            sequence_no=message.sequence_no,
            session_id=message.session_id,
            key_epoch=effective_epoch,
            sender_id=sender_id,
            receiver_id=receiver_id,
            link_id=link_id,
            hop_index=hop_index,
        )
        result = provider.encrypt(
            sender_id,
            receiver_id,
            message.session_id,
            _json_bytes(message.payload),
            aad,
            sim_time_s=self.coordinator._sim_time(),
        )
        if str(result.status) != "ok" or result.ciphertext is None or result.nonce is None:
            state = {
                "key_expired": "EXPIRED",
                "nonce_reuse": "FAILED",
            }.get(str(result.status), "MISSING")
            raise CryptoProtectionError(
                str(result.status).upper(),
                key_state=state,
                key_epoch=result.key_epoch if result.key_epoch is not None else effective_epoch,
                status="ERROR" if str(result.status) != "key_unavailable" else "UNAVAILABLE",
            )
        message.key_epoch = int(result.key_epoch)
        return Frame(
            message_id=message.message_id,
            claimed_src_id=message.claimed_src_id,
            claimed_dst_id=message.claimed_dst_id,
            packet_type=message.packet_type,
            sequence_no=message.sequence_no,
            session_id=message.session_id,
            key_epoch=int(result.key_epoch),
            hop_index=hop_index,
            link_id=link_id,
            link_sender_id=sender_id,
            link_receiver_id=receiver_id,
            protected_payload={
                "ciphertext_b64": base64.b64encode(result.ciphertext).decode("ascii"),
                "algorithm": "AES-256-GCM",
                "key_handle": result.key_id,
            },
            encrypted=True,
            auth_tag=None,
            nonce_b64=base64.b64encode(result.nonce).decode("ascii"),
            sensitive=message.sensitive,
            created_time_s=message.created_time_s,
            route=list(message.route),
            application_size_bytes=message.application_size_bytes,
            extensions=deepcopy(message.extensions),
            runtime_attack_id=message.runtime_attack_id,
            observable_session_id=message.observable_session_id,
            application_direction=message.application_direction,
            app_hmac_tag=message.app_hmac_tag,
            app_hmac_key_id=message.app_hmac_key_id,
        )

    def open(self, frame: Frame, receiver_id: int) -> CryptoOpenResult:
        if int(receiver_id) != int(frame.link_receiver_id):
            return CryptoOpenResult(
                "ERROR", "FAIL", None, "UNAVAILABLE", frame.key_epoch, "WRONG_RECEIVER"
            )
        if frame.packet_type == "SKG_CONTROL":
            valid, error = self.coordinator.verify_control(
                frame.protected_payload, receiver_id
            )
            return CryptoOpenResult(
                "OK" if valid else "ERROR",
                "PASS" if valid else "FAIL",
                deepcopy(frame.protected_payload) if valid else None,
                "UPDATING" if valid else "MISSING",
                frame.key_epoch,
                error,
                None,
                "Ed25519",
            )
        if not frame.encrypted:
            return CryptoOpenResult(
                "OK",
                "PASS",
                deepcopy(frame.protected_payload),
                "UNAVAILABLE",
                frame.key_epoch,
                "UNPROTECTED_DEVELOPMENT_TRAFFIC",
                None,
                None,
            )
        provider = self.coordinator.provider_for(receiver_id)
        if provider is None:
            return CryptoOpenResult(
                "UNAVAILABLE", "UNAVAILABLE", None, "MISSING", frame.key_epoch,
                "KEY_UNAVAILABLE",
            )
        try:
            ciphertext = base64.b64decode(
                str(frame.protected_payload.get("ciphertext_b64", "")), validate=True
            )
            nonce = base64.b64decode(str(frame.nonce_b64 or ""), validate=True)
        except ValueError:
            return CryptoOpenResult(
                "ERROR", "FAIL", None, "AVAILABLE", frame.key_epoch, "AUTH_FAIL"
            )
        aad = build_aad(
            message_id=frame.message_id,
            claimed_src_id=frame.claimed_src_id,
            claimed_dst_id=frame.claimed_dst_id,
            packet_type=frame.packet_type,
            sequence_no=frame.sequence_no,
            session_id=frame.session_id,
            key_epoch=frame.key_epoch,
            sender_id=frame.link_sender_id,
            receiver_id=receiver_id,
            link_id=frame.link_id,
            hop_index=frame.hop_index,
        )
        result = provider.decrypt(
            receiver_id,
            frame.link_sender_id,
            frame.session_id,
            ciphertext,
            aad,
            nonce=nonce,
            key_id=frame.protected_payload.get("key_handle"),
            key_epoch=PersonAKeyCoordinator._epoch(frame.key_epoch),
            sim_time_s=self.coordinator._sim_time(),
        )
        status = str(result.status)
        state = {
            "ok": "AVAILABLE",
            "key_expired": "EXPIRED",
            "key_unavailable": "MISSING",
            "nonce_reuse": "FAILED",
        }.get(status, "AVAILABLE")
        if status != "ok" or result.plaintext is None:
            return CryptoOpenResult(
                "UNAVAILABLE" if status == "key_unavailable" else "ERROR",
                "UNAVAILABLE" if status == "key_unavailable" else "FAIL",
                None,
                state,
                frame.key_epoch,
                status.upper(),
                result.key_id,
                "AES-256-GCM",
            )
        try:
            payload = json.loads(result.plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return CryptoOpenResult(
                "ERROR", "FAIL", None, state, frame.key_epoch, "INVALID_PLAINTEXT",
                result.key_id, "AES-256-GCM"
            )
        return CryptoOpenResult(
            "OK", "PASS", payload, state, frame.key_epoch, None,
            result.key_id, "AES-256-GCM"
        )

    @staticmethod
    def _plaintext_frame(
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> Frame:
        return Frame(
            message_id=message.message_id,
            claimed_src_id=message.claimed_src_id,
            claimed_dst_id=message.claimed_dst_id,
            packet_type=message.packet_type,
            sequence_no=message.sequence_no,
            session_id=message.session_id,
            key_epoch=message.key_epoch,
            hop_index=hop_index,
            link_id=link_id,
            link_sender_id=sender_id,
            link_receiver_id=receiver_id,
            protected_payload=deepcopy(message.payload),
            encrypted=False,
            auth_tag=None,
            nonce_b64=None,
            sensitive=message.sensitive,
            created_time_s=message.created_time_s,
            route=list(message.route),
            application_size_bytes=message.application_size_bytes,
            extensions=deepcopy(message.extensions),
            runtime_attack_id=message.runtime_attack_id,
            observable_session_id=message.observable_session_id,
            application_direction=message.application_direction,
            app_hmac_tag=message.app_hmac_tag,
            app_hmac_key_id=message.app_hmac_key_id,
        )

    @classmethod
    def _public_control_frame(
        cls,
        message: Message,
        sender_id: int,
        receiver_id: int,
        link_id: str,
        hop_index: int,
    ) -> Frame:
        frame = cls._plaintext_frame(
            message, sender_id, receiver_id, link_id, hop_index
        )
        frame.auth_tag = "PERSON_A_ED25519"
        frame.application_size_bytes = serialized_application_size(
            frame.protected_payload
        )
        return frame


class PersonATerminalAuthorizerAdapter:
    """A CredentialService bound to V8's simulated public fingerprint."""

    implementation_status = "PERSON_A_INTEGRATED_DEVELOPMENT"
    version = "person-a-credential-0.1+v8-adapter-1.0"

    def __init__(
        self,
        credential_service: Any,
        *,
        credential_mode: str = "SIMULATED_TERMINAL_FINGERPRINT",
    ) -> None:
        self._service = credential_service
        self.credential_mode = str(credential_mode)
        mode_slug = self.credential_mode.lower().replace("_", "-")
        self.version = (
            "person-a-credential-0.1+v8-adapter-1.0+mode-" f"{mode_slug}"
        )
        self._serials: dict[str, bytes] = {}
        self._credential_ids: dict[str, str] = {}

    @staticmethod
    def _fingerprint(profile: Any) -> bytes:
        return str(profile.public_fingerprint()).encode("utf-8")

    def enroll(self, profile: Any, credential_handle: str) -> dict[str, Any]:
        del credential_handle
        result = self._service.derive(
            self._fingerprint(profile), terminal_id=str(profile.terminal_id)
        )
        if str(result.status) == "ok" and result.serial is not None:
            self._serials[str(profile.terminal_id)] = bytes(result.serial)
            self._credential_ids[str(profile.terminal_id)] = str(result.credential_id)
        return {
            "terminal_id": str(profile.terminal_id),
            "status": "ENROLLED" if str(result.status) == "ok" else "CREDENTIAL_FAIL",
            "credential_id": result.credential_id,
            "credential_state": "PERSON_A_SIMULATED_FINGERPRINT_BOUND",
        }

    def is_enrolled(self, terminal_id: str) -> bool:
        return str(terminal_id) in self._serials

    def authorize(
        self, event: str, profile: Any, credential_handle: str
    ) -> dict[str, Any]:
        del credential_handle
        if event not in {"PROGRAM_START", "NETWORK_JOIN", "SENSITIVE_COMMAND"}:
            return {
                "event": event,
                "terminal_id": str(profile.terminal_id),
                "allowed": False,
                "failure_reason": "UNSUPPORTED_AUTHORIZATION_EVENT",
            }
        serial = self._serials.get(str(profile.terminal_id))
        if serial is None:
            status = "credential_fail"
            credential_id = None
        else:
            result = self._service.verify(
                self._fingerprint(profile), serial, terminal_id=str(profile.terminal_id)
            )
            status = str(result.status)
            credential_id = result.credential_id
        return {
            "event": event,
            "terminal_id": str(profile.terminal_id),
            "credential_id": credential_id,
            "allowed": status == "ok",
            "failure_reason": None if status == "ok" else "CREDENTIAL_FAIL",
        }


class PersonASecurityBundleFactory:
    """Create fresh A providers, nonce state, identities and credentials per run."""

    def __init__(
        self,
        library_path: str | Path,
        *,
        test_only_preloaded_keys: list[dict[str, Any]] | None = None,
        skg_timeout_s: float = 3.0,
        identity_store_factory: Callable[[Any, int, Any], Any] | None = None,
        credential_service_factory: Callable[[Any, Any], Any] | None = None,
        identity_mode: str | None = None,
        credential_mode: str | None = None,
        probe_profile: str = V8_DEFAULT_PROBE_PROFILE,
    ) -> None:
        if probe_profile not in SUPPORTED_PROBE_PROFILES:
            raise ValueError(f"UNSUPPORTED_PROBE_PROFILE:{probe_profile}")
        self.library_path = Path(library_path).resolve()
        self.test_only_preloaded_keys = deepcopy(test_only_preloaded_keys or [])
        self.skg_timeout_s = float(skg_timeout_s)
        self.identity_store_factory = identity_store_factory
        self.credential_service_factory = credential_service_factory
        self.identity_mode = identity_mode
        self.credential_mode = credential_mode
        self.probe_profile = probe_profile

    def __call__(self, config: Any) -> dict[str, Any]:
        library = _load_person_a_library(self.library_path)
        node_ids = [
            node_id
            for node_id, role in config.resolved_roles().items()
            if role != NodeRole.EXTERNAL
        ]
        identities = (
            {
                node_id: self.identity_store_factory(library, node_id, config)
                for node_id in node_ids
            }
            if self.identity_store_factory is not None
            else None
        )
        coordinator = PersonAKeyCoordinator(
            library,
            node_ids,
            timeout_s=self.skg_timeout_s,
            identities=identities,
            identity_mode=(
                self.identity_mode
                or (
                    "Ed25519_INJECTED_IDENTITY"
                    if identities is not None
                    else "Ed25519_TEST_ONLY_GENERATED_IDENTITY"
                )
            ),
            probe_profile=self.probe_profile,
        )
        coordinator._bundle_factory = self
        for spec in self.test_only_preloaded_keys:
            coordinator.preload_test_key(
                int(spec["first_id"]),
                int(spec["second_id"]),
                str(spec["session_id"]),
                bytes(spec["key"]),
                key_epoch=int(spec.get("key_epoch", 1)),
            )
        if self.credential_service_factory is not None:
            credential_service = self.credential_service_factory(library, config)
            credential_mode = self.credential_mode or "INJECTED_CREDENTIAL_SERVICE"
        else:
            master = hashlib.sha256(
                f"PERSON-A-INTEGRATION-TEST-CREDENTIAL:{config.seed}".encode("utf-8")
            ).digest()
            credential_service = library.credentials.CredentialService(master)
            credential_mode = (
                self.credential_mode or "SIMULATED_TERMINAL_FINGERPRINT_TEST_MASTER"
            )
        terminal = PersonATerminalAuthorizerAdapter(
            credential_service,
            credential_mode=credential_mode,
        )
        return {
            "key_provider": coordinator,
            "crypto_provider": PersonACryptoProvider(coordinator),
            "security_coordinator": coordinator,
            "terminal_authorizer": terminal,
        }
