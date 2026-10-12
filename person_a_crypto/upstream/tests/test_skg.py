from __future__ import annotations

import sys
from dataclasses import fields, is_dataclass
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.aead import AeadService
from crypto.key_provider import KeyProvider
from crypto.observations import synthesize_reciprocal_rssi
from crypto.skg import SkgEngine, SkgResult
from crypto.types import STATUS_KEY_UNAVAILABLE, STATUS_OK, STATUS_SKG_FAIL

SESSION = "link-3-7-s1"
PROBE = "prb-00042"
AAD = b"src=3,dst=7,seq=1,msg_type=data,key_epoch=1,direction=3->7"
PLAINTEXT = b"skg-payload"


def _run_skg(alice: SkgEngine, bob: SkgEngine, obs_a, obs_b) -> tuple[SkgResult, SkgResult]:
    seen_a = alice.on_local_observation(obs_a)
    seen_b = bob.on_local_observation(obs_b)
    if seen_a.status != STATUS_OK or seen_b.status != STATUS_OK:
        return seen_a, seen_b
    rec_a = alice.make_reconcile_blob(obs_a.probe_id)
    rec_b = bob.make_reconcile_blob(obs_b.probe_id)
    got_a = alice.apply_reconcile_blob(obs_a.probe_id, rec_b)
    got_b = bob.apply_reconcile_blob(obs_b.probe_id, rec_a)
    if got_a.status != STATUS_OK or got_b.status != STATUS_OK:
        return got_a, got_b
    conf_a = alice.make_confirm_blob(obs_a.probe_id)
    conf_b = bob.make_confirm_blob(obs_b.probe_id)
    done_a = alice.apply_confirm_blob(obs_a.probe_id, conf_b)
    done_b = bob.apply_confirm_blob(obs_b.probe_id, conf_a)
    return done_a, done_b


def _collect_bytes(obj: object) -> list[bytes]:
    found: list[bytes] = []
    if isinstance(obj, (bytes, bytearray)):
        found.append(bytes(obj))
        return found
    if is_dataclass(obj) and not isinstance(obj, type):
        for item in fields(obj):
            found.extend(_collect_bytes(getattr(obj, item.name)))
    return found


def test_reciprocal_observations_agree_and_encrypt_roundtrip() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(3, 7, SESSION, PROBE, seed=42)
    assert obs3.probe_id == obs7.probe_id == PROBE
    assert obs3.measurement != obs7.measurement

    done3, done7 = _run_skg(skg3, skg7, obs3, obs7)
    assert done3.status == STATUS_OK
    assert done7.status == STATUS_OK
    assert done3.key_id == done7.key_id
    assert kp3.get_status(7, SESSION) == STATUS_OK
    assert kp7.get_status(3, SESSION) == STATUS_OK

    enc = kp3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert enc.status == STATUS_OK
    dec = kp7.decrypt(7, 3, SESSION, enc.ciphertext, AAD, nonce=enc.nonce, key_id=enc.key_id)
    assert dec.status == STATUS_OK
    assert dec.plaintext == PLAINTEXT


def test_scrambled_measurement_is_skg_fail_and_no_key() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(3, 7, SESSION, PROBE, seed=7, peer_scrambled=True)
    done3, done7 = _run_skg(skg3, skg7, obs3, obs7)
    assert done3.status == STATUS_SKG_FAIL
    assert done7.status == STATUS_SKG_FAIL
    assert kp3.get_status(7, SESSION) == STATUS_KEY_UNAVAILABLE
    assert kp7.get_status(3, SESSION) == STATUS_KEY_UNAVAILABLE
    failed = kp3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert failed.status == STATUS_KEY_UNAVAILABLE
    assert failed.plaintext is None
    assert failed.ciphertext is None


def test_missing_observation_is_skg_fail() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(3, 7, SESSION, PROBE, seed=3, local_missing=True)
    assert obs3.missing is True
    done3, done7 = _run_skg(skg3, skg7, obs3, obs7)
    assert done3.status == STATUS_SKG_FAIL
    assert kp3.get_status(7, SESSION) == STATUS_KEY_UNAVAILABLE
    assert kp7.get_status(3, SESSION) == STATUS_KEY_UNAVAILABLE


def test_public_blob_and_results_do_not_contain_session_key() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(3, 7, SESSION, PROBE, seed=11)
    seen3 = skg3.on_local_observation(obs3)
    seen7 = skg7.on_local_observation(obs7)
    rec3 = skg3.make_reconcile_blob(PROBE)
    rec7 = skg7.make_reconcile_blob(PROBE)
    skg3.apply_reconcile_blob(PROBE, rec7)
    skg7.apply_reconcile_blob(PROBE, rec3)
    conf3 = skg3.make_confirm_blob(PROBE)
    conf7 = skg7.make_confirm_blob(PROBE)
    done3 = skg3.apply_confirm_blob(PROBE, conf7)
    done7 = skg7.apply_confirm_blob(PROBE, conf3)
    assert done3.status == STATUS_OK
    assert done7.status == STATUS_OK

    for obj in (seen3, seen7, rec3, rec7, conf3, conf7, done3, done7, skg3, skg7):
        assert not hasattr(obj, "key")
        assert not hasattr(obj, "candidate_key")
        names = {item.name for item in fields(obj)} if is_dataclass(obj) and not isinstance(obj, type) else set()
        assert "key" not in names
        assert "candidate_key" not in names

    assert rec3.blob is not None and len(rec3.blob) == 8
    assert conf3.blob is not None and len(conf3.blob) == 32
    for blob in _collect_bytes(rec3) + _collect_bytes(conf3) + _collect_bytes(done3):
        if len(blob) != 32:
            continue
        probe = AeadService()
        enc = probe.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=blob)
        dec = kp7.decrypt(7, 3, SESSION, enc.ciphertext, AAD, nonce=enc.nonce)
        assert dec.status != STATUS_OK
        assert dec.plaintext is None
