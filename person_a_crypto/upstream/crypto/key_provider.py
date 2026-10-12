"""按邻接链路保管会话密钥。对外只有 key_id；加解密走本节点的 AeadService。"""

from __future__ import annotations

from dataclasses import dataclass

from .aead import AeadService, KEY_LEN
from .types import (
    ALG_AES_256_GCM,
    AuthResult,
    CryptoResult,
    STATUS_AUTH_FAIL,
    STATUS_BAD_ARGUMENT,
    STATUS_KEY_EXPIRED,
    STATUS_KEY_UNAVAILABLE,
    STATUS_OK,
)

EVENT_KEY_READY = "key_ready"
EVENT_KEY_FAILED = "key_failed"
EVENT_KEY_EXPIRED = "key_expired"
EVENT_KEY_REVOKED = "key_revoked"
EVENT_REKEY_OK = "rekey_ok"
EVENT_REKEY_ROLLBACK_OK = "rekey_rollback_ok"

STATUS_KEY_REVOKED = "key_revoked"


def _key_id(local_id: int, peer_id: int, session_id: str, key_epoch: int) -> str:
    lo, hi = (local_id, peer_id) if local_id <= peer_id else (peer_id, local_id)
    return f"k-{lo}-{hi}-{session_id}-e{key_epoch:02d}"


def _is_node_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class KeyEvent:
    event: str
    local_id: int
    peer_id: int | None
    session_id: str | None
    key_id: str | None
    key_epoch: int | None
    status: str
    sim_time_s: float | None = None


@dataclass
class _KeyRecord:
    material: bytes
    key_id: str
    key_epoch: int
    expires_at_s: float | None = None
    revoked: bool = False


@dataclass
class _LinkState:
    current_epoch: int
    by_epoch: dict[int, _KeyRecord]


class KeyProvider:
    """一节点一把钥匙串、一个 AeadService，避免多节点共用 nonce 计数。"""

    def __init__(self, local_id: int, *, aead: AeadService | None = None) -> None:
        if not _is_node_id(local_id):
            raise TypeError("local_id must be an int")
        self.local_id = local_id
        self._aead = aead if aead is not None else AeadService()
        self._links: dict[tuple[int, str], _LinkState] = {}

    def __repr__(self) -> str:
        return f"KeyProvider(local_id={self.local_id}, links={len(self._links)})"

    def put(
        self,
        peer_id: int,
        session_id: str,
        key: bytes,
        *,
        key_epoch: int = 0,
        key_id: str | None = None,
        expires_at_s: float | None = None,
        sim_time_s: float | None = None,
    ) -> KeyEvent:
        if not _is_node_id(peer_id) or not isinstance(session_id, str) or session_id == "":
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, None, STATUS_BAD_ARGUMENT, sim_time_s
            )
        if peer_id == self.local_id:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, None, STATUS_BAD_ARGUMENT, sim_time_s
            )
        if not isinstance(key_epoch, int) or isinstance(key_epoch, bool) or key_epoch < 0:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, None, STATUS_BAD_ARGUMENT, sim_time_s
            )
        if key is None or not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, None, STATUS_KEY_UNAVAILABLE, sim_time_s
            )
        if len(key) != KEY_LEN:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, None, STATUS_BAD_ARGUMENT, sim_time_s
            )

        handle = key_id or _key_id(self.local_id, peer_id, session_id, key_epoch)
        record = _KeyRecord(
            material=bytes(key),
            key_id=handle,
            key_epoch=key_epoch,
            expires_at_s=expires_at_s,
        )
        link = (peer_id, session_id)
        state = self._links.get(link)
        if state is None:
            self._links[link] = _LinkState(current_epoch=key_epoch, by_epoch={key_epoch: record})
            return self._event(
                EVENT_KEY_READY, peer_id, session_id, handle, key_epoch, STATUS_OK, sim_time_s
            )
        if key_epoch < state.current_epoch:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, handle, key_epoch, STATUS_BAD_ARGUMENT, sim_time_s
            )

        event = EVENT_REKEY_OK if key_epoch > state.current_epoch else EVENT_KEY_READY
        kept: dict[int, _KeyRecord] = {}
        if key_epoch > state.current_epoch:
            previous = state.by_epoch.get(state.current_epoch)
            if previous is not None and not previous.revoked:
                kept[state.current_epoch] = previous
        elif key_epoch == state.current_epoch:
            for epoch, rec in state.by_epoch.items():
                if epoch != key_epoch:
                    kept[epoch] = rec
        kept[key_epoch] = record
        state.current_epoch = key_epoch
        state.by_epoch = kept
        return self._event(event, peer_id, session_id, handle, key_epoch, STATUS_OK, sim_time_s)

    def get_status(
        self,
        peer_id: int,
        session_id: str,
        *,
        key_epoch: int | None = None,
        sim_time_s: float | None = None,
    ) -> str:
        rec = self._record(peer_id, session_id, key_epoch=key_epoch)
        if rec is None:
            return STATUS_KEY_UNAVAILABLE
        return self._record_status(rec, sim_time_s)

    def revoke(
        self,
        peer_id: int,
        session_id: str,
        *,
        key_epoch: int | None = None,
        sim_time_s: float | None = None,
    ) -> KeyEvent:
        state = self._links.get((peer_id, session_id))
        if state is None:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, key_epoch, STATUS_KEY_UNAVAILABLE, sim_time_s
            )
        if key_epoch is None:
            targets = list(state.by_epoch.values())
        else:
            rec = state.by_epoch.get(key_epoch)
            targets = [rec] if rec is not None else []
        if not targets:
            return self._event(
                EVENT_KEY_FAILED, peer_id, session_id, None, key_epoch, STATUS_KEY_UNAVAILABLE, sim_time_s
            )
        handle = None
        epoch = key_epoch
        for rec in targets:
            rec.revoked = True
            handle = rec.key_id
            epoch = rec.key_epoch
        if key_epoch is None:
            current = state.by_epoch.get(state.current_epoch)
            if current is not None:
                handle = current.key_id
                epoch = current.key_epoch
        return self._event(
            EVENT_KEY_REVOKED, peer_id, session_id, handle, epoch, STATUS_KEY_REVOKED, sim_time_s
        )

    def rollback_epoch(
        self,
        peer_id: int,
        session_id: str,
        *,
        failed_epoch: int,
        restore_epoch: int | None,
        sim_time_s: float | None = None,
    ) -> KeyEvent:
        """Abort one failed rekey commit and restore its recorded predecessor.

        This lifecycle operation never exports key material.  ``restore_epoch``
        must identify the epoch that was current before the failed transaction;
        the provider will only restore it when that record is still available.
        A revoked or expired predecessor is deliberately not resurrected.
        """

        if (
            not _is_node_id(peer_id)
            or not isinstance(session_id, str)
            or session_id == ""
            or not isinstance(failed_epoch, int)
            or isinstance(failed_epoch, bool)
            or failed_epoch < 0
            or (
                restore_epoch is not None
                and (
                    not isinstance(restore_epoch, int)
                    or isinstance(restore_epoch, bool)
                    or restore_epoch < 0
                    or restore_epoch == failed_epoch
                )
            )
        ):
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                None,
                failed_epoch,
                STATUS_BAD_ARGUMENT,
                sim_time_s,
            )

        state = self._links.get((peer_id, session_id))
        if state is None:
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                None,
                failed_epoch,
                STATUS_KEY_UNAVAILABLE,
                sim_time_s,
            )

        # Refuse to rewrite an unrelated epoch selected after this transaction.
        allowed_current = {failed_epoch}
        if restore_epoch is not None:
            allowed_current.add(restore_epoch)
        if state.current_epoch not in allowed_current:
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                None,
                failed_epoch,
                STATUS_BAD_ARGUMENT,
                sim_time_s,
            )

        failed = state.by_epoch.get(failed_epoch)
        if failed is not None:
            failed.revoked = True

        if restore_epoch is None:
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                failed.key_id if failed is not None else None,
                failed_epoch,
                STATUS_KEY_UNAVAILABLE,
                sim_time_s,
            )

        previous = state.by_epoch.get(restore_epoch)
        if previous is None:
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                failed.key_id if failed is not None else None,
                failed_epoch,
                STATUS_KEY_UNAVAILABLE,
                sim_time_s,
            )
        previous_status = self._record_status(previous, sim_time_s)
        if previous_status != STATUS_OK:
            return self._event(
                EVENT_KEY_FAILED,
                peer_id,
                session_id,
                previous.key_id,
                restore_epoch,
                previous_status,
                sim_time_s,
            )

        state.current_epoch = restore_epoch
        return self._event(
            EVENT_REKEY_ROLLBACK_OK,
            peer_id,
            session_id,
            previous.key_id,
            restore_epoch,
            STATUS_OK,
            sim_time_s,
        )

    def encrypt(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        plaintext: bytes,
        aad: bytes,
        *,
        sim_time_s: float | None = None,
    ) -> CryptoResult:
        if local_id != self.local_id:
            return _crypto_fail(STATUS_BAD_ARGUMENT, local_id=local_id, claimed_src=local_id)
        rec = self._record(peer_id, session_id)
        if rec is None:
            return _crypto_fail(STATUS_KEY_UNAVAILABLE, local_id=local_id, claimed_src=local_id)
        blocked = self._encrypt_block_status(rec, sim_time_s)
        if blocked is not None:
            if blocked == STATUS_KEY_EXPIRED:
                return _crypto_fail(
                    STATUS_KEY_EXPIRED,
                    key_id=rec.key_id,
                    key_epoch=rec.key_epoch,
                    local_id=local_id,
                    claimed_src=local_id,
                )
            return _crypto_fail(
                blocked,
                key_id=rec.key_id,
                key_epoch=rec.key_epoch,
                local_id=local_id,
                claimed_src=local_id,
            )
        return self._aead.encrypt(
            local_id,
            peer_id,
            session_id,
            plaintext,
            aad,
            key=rec.material,
            key_id=rec.key_id,
            key_epoch=rec.key_epoch,
        )

    def decrypt(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        ciphertext: bytes,
        aad: bytes,
        *,
        nonce: bytes | None = None,
        key_id: str | None = None,
        key_epoch: int | None = None,
        sim_time_s: float | None = None,
    ) -> CryptoResult:
        if local_id != self.local_id:
            return _crypto_fail(STATUS_BAD_ARGUMENT, local_id=local_id, claimed_src=peer_id)
        state = self._links.get((peer_id, session_id))
        if state is None:
            return _crypto_fail(STATUS_KEY_UNAVAILABLE, local_id=local_id, claimed_src=peer_id)

        candidates = self._decrypt_candidates(state, key_id=key_id, key_epoch=key_epoch)
        if not candidates:
            return _crypto_fail(
                STATUS_KEY_UNAVAILABLE,
                key_id=key_id,
                key_epoch=key_epoch,
                local_id=local_id,
                claimed_src=peer_id,
            )

        last_fail: CryptoResult | None = None
        for rec in candidates:
            status = self._record_status(rec, sim_time_s)
            if status == STATUS_KEY_REVOKED:
                last_fail = _crypto_fail(
                    STATUS_KEY_UNAVAILABLE,
                    key_id=rec.key_id,
                    key_epoch=rec.key_epoch,
                    local_id=local_id,
                    claimed_src=peer_id,
                )
                continue
            if status == STATUS_KEY_EXPIRED:
                last_fail = _crypto_fail(
                    STATUS_KEY_EXPIRED,
                    key_id=rec.key_id,
                    key_epoch=rec.key_epoch,
                    local_id=local_id,
                    claimed_src=peer_id,
                )
                continue
            if status != STATUS_OK:
                last_fail = _crypto_fail(
                    status,
                    key_id=rec.key_id,
                    key_epoch=rec.key_epoch,
                    local_id=local_id,
                    claimed_src=peer_id,
                )
                continue
            result = self._aead.decrypt(
                local_id,
                peer_id,
                session_id,
                ciphertext,
                aad,
                key=rec.material,
                nonce=nonce,
                key_id=rec.key_id,
                key_epoch=rec.key_epoch,
            )
            if result.status == STATUS_OK:
                return result
            last_fail = result

        if last_fail is not None:
            return last_fail
        return _crypto_fail(STATUS_AUTH_FAIL, local_id=local_id, claimed_src=peer_id)

    def _record(
        self,
        peer_id: int,
        session_id: str,
        *,
        key_epoch: int | None = None,
    ) -> _KeyRecord | None:
        state = self._links.get((peer_id, session_id))
        if state is None:
            return None
        epoch = state.current_epoch if key_epoch is None else key_epoch
        return state.by_epoch.get(epoch)

    @staticmethod
    def _decrypt_candidates(
        state: _LinkState,
        *,
        key_id: str | None,
        key_epoch: int | None,
    ) -> list[_KeyRecord]:
        if key_epoch is not None:
            rec = state.by_epoch.get(key_epoch)
            return [rec] if rec is not None else []
        if key_id is not None:
            found = [rec for rec in state.by_epoch.values() if rec.key_id == key_id]
            if found:
                return found
        ordered = [state.current_epoch] + sorted(
            (epoch for epoch in state.by_epoch if epoch != state.current_epoch),
            reverse=True,
        )
        return [state.by_epoch[epoch] for epoch in ordered if epoch in state.by_epoch]

    @staticmethod
    def _is_expired(rec: _KeyRecord, sim_time_s: float | None) -> bool:
        if rec.expires_at_s is None or sim_time_s is None:
            return False
        return sim_time_s >= rec.expires_at_s

    def _record_status(self, rec: _KeyRecord, sim_time_s: float | None) -> str:
        if rec.revoked:
            return STATUS_KEY_REVOKED
        if self._is_expired(rec, sim_time_s):
            return STATUS_KEY_EXPIRED
        return STATUS_OK

    def _encrypt_block_status(self, rec: _KeyRecord, sim_time_s: float | None) -> str | None:
        status = self._record_status(rec, sim_time_s)
        if status == STATUS_OK:
            return None
        if status == STATUS_KEY_REVOKED:
            return STATUS_KEY_UNAVAILABLE
        return status

    def _event(
        self,
        event: str,
        peer_id: int | None,
        session_id: str | None,
        key_id: str | None,
        key_epoch: int | None,
        status: str,
        sim_time_s: float | None,
    ) -> KeyEvent:
        return KeyEvent(
            event=event,
            local_id=self.local_id,
            peer_id=peer_id,
            session_id=session_id,
            key_id=key_id,
            key_epoch=key_epoch,
            status=status,
            sim_time_s=sim_time_s,
        )


def _crypto_fail(
    status: str,
    *,
    key_id: str | None = None,
    key_epoch: int | None = None,
    local_id: int | None = None,
    claimed_src: int | None = None,
) -> CryptoResult:
    return CryptoResult(
        status=status,
        key_id=key_id,
        key_epoch=key_epoch,
        ciphertext=None,
        plaintext=None,
        nonce=None,
        auth=AuthResult(
            status=status,
            key_id=key_id,
            key_epoch=key_epoch,
            alg=ALG_AES_256_GCM,
            local_id=local_id,
            claimed_src=claimed_src,
        ),
    )
