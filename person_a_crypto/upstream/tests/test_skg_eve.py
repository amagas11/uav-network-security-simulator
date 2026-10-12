"""合成 Eve 离线实验：未用实测、未接入仿真，不是平台 SKG 指标。"""

from __future__ import annotations

import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.aead import AeadService
from crypto.key_provider import KeyProvider
from crypto.observations import synthesize_reciprocal_rssi_with_eve
from crypto.skg import SkgEngine, SkgResult
from crypto.types import STATUS_KEY_UNAVAILABLE, STATUS_OK, STATUS_SKG_FAIL

SESSION = "link-3-7-s1"
PROBE = "prb-00042"
EVE_ID = 99
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


def _eve_against_public_blobs(
    eve: SkgEngine,
    obs_eve,
    rec_legitimate: SkgResult,
    conf_legitimate: SkgResult,
) -> SkgResult:
    seen = eve.on_local_observation(obs_eve)
    if seen.status != STATUS_OK:
        return seen
    rec_eve = eve.make_reconcile_blob(obs_eve.probe_id)
    if rec_eve.status != STATUS_OK:
        return rec_eve
    got = eve.apply_reconcile_blob(obs_eve.probe_id, rec_legitimate)
    if got.status != STATUS_OK:
        return got
    conf_eve = eve.make_confirm_blob(obs_eve.probe_id)
    if conf_eve.status != STATUS_OK:
        return conf_eve
    return eve.apply_confirm_blob(obs_eve.probe_id, conf_legitimate)


def test_legitimate_pair_still_skg_and_encrypts() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7, obs_eve = synthesize_reciprocal_rssi_with_eve(
        3, 7, EVE_ID, SESSION, PROBE, seed=42
    )
    assert obs_eve.probe_id == obs3.probe_id == PROBE
    assert obs_eve.local_id == EVE_ID
    assert obs_eve.measurement != obs3.measurement
    assert obs_eve.measurement != obs7.measurement
    deltas = [abs(a - e) for a, e in zip(obs3.measurement, obs_eve.measurement)]
    assert max(deltas) > 5.0

    done3, done7 = _run_skg(skg3, skg7, obs3, obs7)
    assert done3.status == STATUS_OK
    assert done7.status == STATUS_OK
    enc = kp3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert enc.status == STATUS_OK
    dec = kp7.decrypt(7, 3, SESSION, enc.ciphertext, AAD, nonce=enc.nonce, key_id=enc.key_id)
    assert dec.status == STATUS_OK
    assert dec.plaintext == PLAINTEXT


def test_eve_own_observation_does_not_get_session_key() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    kp_eve = KeyProvider(EVE_ID)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    skg_eve = SkgEngine(EVE_ID, kp_eve)
    obs3, obs7, obs_eve = synthesize_reciprocal_rssi_with_eve(
        3, 7, EVE_ID, SESSION, PROBE, seed=7, correlation="uncorrelated"
    )

    seen3 = skg3.on_local_observation(obs3)
    seen7 = skg7.on_local_observation(obs7)
    assert seen3.status == STATUS_OK and seen7.status == STATUS_OK
    rec3 = skg3.make_reconcile_blob(PROBE)
    rec7 = skg7.make_reconcile_blob(PROBE)
    assert skg3.apply_reconcile_blob(PROBE, rec7).status == STATUS_OK
    assert skg7.apply_reconcile_blob(PROBE, rec3).status == STATUS_OK
    conf3 = skg3.make_confirm_blob(PROBE)
    conf7 = skg7.make_confirm_blob(PROBE)
    assert skg3.apply_confirm_blob(PROBE, conf7).status == STATUS_OK
    assert skg7.apply_confirm_blob(PROBE, conf3).status == STATUS_OK

    eve_done = _eve_against_public_blobs(skg_eve, obs_eve, rec3, conf3)
    assert eve_done.status == STATUS_SKG_FAIL
    assert kp_eve.get_status(3, SESSION) == STATUS_KEY_UNAVAILABLE
    assert kp3.get_status(7, SESSION) == STATUS_OK


def test_eve_cannot_use_public_blobs_as_aes_key() -> None:
    kp3 = KeyProvider(3)
    kp7 = KeyProvider(7)
    skg3 = SkgEngine(3, kp3)
    skg7 = SkgEngine(7, kp7)
    obs3, obs7, _obs_eve = synthesize_reciprocal_rssi_with_eve(
        3, 7, EVE_ID, SESSION, PROBE, seed=11
    )
    seen3 = skg3.on_local_observation(obs3)
    seen7 = skg7.on_local_observation(obs7)
    assert seen3.status == STATUS_OK
    rec3 = skg3.make_reconcile_blob(PROBE)
    rec7 = skg7.make_reconcile_blob(PROBE)
    skg3.apply_reconcile_blob(PROBE, rec7)
    skg7.apply_reconcile_blob(PROBE, rec3)
    conf3 = skg3.make_confirm_blob(PROBE)
    conf7 = skg7.make_confirm_blob(PROBE)
    assert skg3.apply_confirm_blob(PROBE, conf7).status == STATUS_OK
    assert skg7.apply_confirm_blob(PROBE, conf3).status == STATUS_OK

    enc = kp3.encrypt(3, 7, SESSION, PLAINTEXT, AAD)
    assert enc.status == STATUS_OK
    assert rec3.blob is not None and conf3.blob is not None

    probe = AeadService()
    assert rec3.blob is not None and len(rec3.blob) != 32
    for blob in (conf3.blob, conf7.blob):
        if blob is None or len(blob) != 32:
            continue
        forged = probe.encrypt(3, 7, SESSION, PLAINTEXT, AAD, key=blob)
        stolen = kp7.decrypt(7, 3, SESSION, forged.ciphertext, AAD, nonce=forged.nonce)
        assert stolen.status != STATUS_OK
        assert stolen.plaintext is None
        eve_try = probe.decrypt(7, 3, SESSION, enc.ciphertext, AAD, key=blob, nonce=enc.nonce)
        assert eve_try.status != STATUS_OK
        assert eve_try.plaintext is None
