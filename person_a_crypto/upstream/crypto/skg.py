"""SKG 流水线：量化 → 公开协调 → 隐私放大 → 确认。

输入是合成或将来由 B 提供的局部观测；本模块未校准、未接入仿真。
两端只使用自己的 measurement。失败返回 skg_fail，不 put 密钥，不退回固定测试密钥。
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aead import KEY_LEN
from .key_provider import EVENT_KEY_READY, EVENT_REKEY_OK, KeyEvent, KeyProvider
from .observations import LocalPhyObservation
from .types import STATUS_BAD_ARGUMENT, STATUS_OK, STATUS_SKG_FAIL

PHASE_RECONCILE = "reconcile"
PHASE_CONFIRM = "confirm"
_SYNDROME_LEN = 8
_HKDF_INFO_PREFIX = b"uav-skg-v1|"
_SYNTHETIC_NOTE = "synthetic, uncalibrated, not from simulation"


@dataclass(frozen=True, slots=True)
class SkgResult:
    status: str
    probe_id: str | None = None
    session_id: str | None = None
    key_id: str | None = None
    key_epoch: int | None = None
    skg_phase: str | None = None
    blob: bytes | None = None


@dataclass
class _ProbeState:
    local_id: int
    peer_id: int
    session_id: str
    probe_id: str
    sim_time_s: float
    bits: bytes
    failed: bool = False
    reconciled: bool = False
    candidate_key: bytes | None = None
    completed: bool = False
    key_id: str | None = None
    key_epoch: int | None = None


def _parse_obs(obs: LocalPhyObservation | Mapping[str, Any]) -> LocalPhyObservation:
    if isinstance(obs, LocalPhyObservation):
        return obs
    return LocalPhyObservation.from_mapping(obs)


def quantize_rssi_dbm(measurement: tuple[float, ...] | list[float]) -> bytes:
    if not measurement:
        return b""
    threshold = sum(measurement) / len(measurement)
    n = len(measurement)
    packed = bytearray((n + 7) // 8)
    for index, value in enumerate(measurement):
        if value >= threshold:
            packed[index // 8] |= 1 << (index % 8)
    return n.to_bytes(2, "big") + bytes(packed)


def _syndrome(bits: bytes, probe_id: str) -> bytes:
    return sha256(b"uav-skg-syndrome|" + probe_id.encode("utf-8") + b"|" + bits).digest()[:_SYNDROME_LEN]


def _privacy_amplify(bits: bytes, probe_id: str, session_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=probe_id.encode("utf-8"),
        info=_HKDF_INFO_PREFIX + session_id.encode("utf-8"),
    )
    return hkdf.derive(bits)


def _confirm_tag(key: bytes, probe_id: str, session_id: str) -> bytes:
    return sha256(
        b"uav-skg-confirm|" + probe_id.encode("utf-8") + b"|" + session_id.encode("utf-8") + b"|" + key
    ).digest()


def _incoming_blob(message: SkgResult | bytes, *, expected_phase: str) -> bytes | None:
    if isinstance(message, SkgResult):
        if message.status != STATUS_OK or message.skg_phase != expected_phase or message.blob is None:
            return None
        return message.blob
    if isinstance(message, (bytes, bytearray)):
        return bytes(message)
    return None


class SkgEngine:
    """每节点一个引擎，只消费本端 LocalPhyObservation。"""

    def __init__(self, local_id: int, key_provider: KeyProvider, *, key_epoch: int = 1) -> None:
        if key_provider.local_id != local_id:
            raise ValueError("KeyProvider.local_id must match SkgEngine.local_id")
        self.local_id = local_id
        self._keys = key_provider
        self._key_epoch = key_epoch
        self._probes: dict[str, _ProbeState] = {}

    def __repr__(self) -> str:
        return f"SkgEngine(local_id={self.local_id}, probes={len(self._probes)}, note={_SYNTHETIC_NOTE!r})"

    def on_local_observation(self, obs: LocalPhyObservation | Mapping[str, Any]) -> SkgResult:
        try:
            parsed = _parse_obs(obs)
        except (KeyError, TypeError, ValueError):
            return SkgResult(status=STATUS_BAD_ARGUMENT)

        if parsed.local_id != self.local_id:
            return SkgResult(
                status=STATUS_SKG_FAIL,
                probe_id=parsed.probe_id,
                session_id=parsed.session_id,
            )
        if parsed.peer_id == parsed.local_id or parsed.session_id == "" or parsed.probe_id == "":
            return SkgResult(
                status=STATUS_BAD_ARGUMENT,
                probe_id=parsed.probe_id,
                session_id=parsed.session_id,
            )

        invalid = (
            parsed.missing
            or parsed.measurement_kind not in {"rssi_dbm", "csi"}
            or len(parsed.measurement) == 0
        )
        if invalid:
            self._probes.pop(parsed.probe_id, None)
            return SkgResult(
                status=STATUS_SKG_FAIL,
                probe_id=parsed.probe_id,
                session_id=parsed.session_id,
            )

        bits = quantize_rssi_dbm(parsed.measurement)
        self._probes[parsed.probe_id] = _ProbeState(
            local_id=parsed.local_id,
            peer_id=parsed.peer_id,
            session_id=parsed.session_id,
            probe_id=parsed.probe_id,
            sim_time_s=parsed.sim_time_s,
            bits=bits,
        )
        return SkgResult(
            status=STATUS_OK,
            probe_id=parsed.probe_id,
            session_id=parsed.session_id,
        )

    def make_reconcile_blob(self, probe_id: str) -> SkgResult:
        state = self._probes.get(probe_id)
        if state is None or state.failed:
            return SkgResult(status=STATUS_SKG_FAIL, probe_id=probe_id, skg_phase=PHASE_RECONCILE)
        return SkgResult(
            status=STATUS_OK,
            probe_id=state.probe_id,
            session_id=state.session_id,
            skg_phase=PHASE_RECONCILE,
            blob=_syndrome(state.bits, state.probe_id),
        )

    def apply_reconcile_blob(self, probe_id: str, message: SkgResult | bytes) -> SkgResult:
        state = self._probes.get(probe_id)
        if state is None or state.failed:
            return SkgResult(status=STATUS_SKG_FAIL, probe_id=probe_id, skg_phase=PHASE_RECONCILE)
        blob = _incoming_blob(message, expected_phase=PHASE_RECONCILE)
        local = _syndrome(state.bits, state.probe_id)
        if blob is None or blob != local:
            self._fail(state)
            return SkgResult(
                status=STATUS_SKG_FAIL,
                probe_id=state.probe_id,
                session_id=state.session_id,
                skg_phase=PHASE_RECONCILE,
            )
        state.candidate_key = _privacy_amplify(state.bits, state.probe_id, state.session_id)
        state.reconciled = True
        return SkgResult(
            status=STATUS_OK,
            probe_id=state.probe_id,
            session_id=state.session_id,
            skg_phase=PHASE_RECONCILE,
        )

    def make_confirm_blob(self, probe_id: str) -> SkgResult:
        state = self._probes.get(probe_id)
        if state is None or state.failed or not state.reconciled or state.candidate_key is None:
            return SkgResult(status=STATUS_SKG_FAIL, probe_id=probe_id, skg_phase=PHASE_CONFIRM)
        return SkgResult(
            status=STATUS_OK,
            probe_id=state.probe_id,
            session_id=state.session_id,
            skg_phase=PHASE_CONFIRM,
            blob=_confirm_tag(state.candidate_key, state.probe_id, state.session_id),
        )

    def apply_confirm_blob(self, probe_id: str, message: SkgResult | bytes) -> SkgResult:
        state = self._probes.get(probe_id)
        if state is None or state.failed or not state.reconciled or state.candidate_key is None:
            return SkgResult(status=STATUS_SKG_FAIL, probe_id=probe_id, skg_phase=PHASE_CONFIRM)
        blob = _incoming_blob(message, expected_phase=PHASE_CONFIRM)
        local = _confirm_tag(state.candidate_key, state.probe_id, state.session_id)
        if blob is None or blob != local:
            self._fail(state)
            return SkgResult(
                status=STATUS_SKG_FAIL,
                probe_id=state.probe_id,
                session_id=state.session_id,
                skg_phase=PHASE_CONFIRM,
            )
        event = self._commit(state)
        if event.status != STATUS_OK or event.event not in {EVENT_KEY_READY, EVENT_REKEY_OK}:
            self._fail(state)
            return SkgResult(
                status=STATUS_SKG_FAIL,
                probe_id=state.probe_id,
                session_id=state.session_id,
                skg_phase=PHASE_CONFIRM,
            )
        return SkgResult(
            status=STATUS_OK,
            probe_id=state.probe_id,
            session_id=state.session_id,
            key_id=event.key_id,
            key_epoch=event.key_epoch,
            skg_phase=PHASE_CONFIRM,
        )

    def _commit(self, state: _ProbeState) -> KeyEvent:
        key = state.candidate_key
        assert key is not None
        event = self._keys.put(
            state.peer_id,
            state.session_id,
            key,
            key_epoch=self._key_epoch,
            sim_time_s=state.sim_time_s,
        )
        state.candidate_key = None
        state.bits = b""
        state.completed = event.status == STATUS_OK
        state.key_id = event.key_id
        state.key_epoch = event.key_epoch
        return event

    def _fail(self, state: _ProbeState) -> None:
        state.failed = True
        state.reconciled = False
        state.candidate_key = None
        state.bits = b""
