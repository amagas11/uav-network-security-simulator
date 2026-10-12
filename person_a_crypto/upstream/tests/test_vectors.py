from __future__ import annotations

import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crypto.aead import AeadService
from crypto.identity import IdentityStore
from crypto.key_provider import KeyProvider
from crypto.observations import LocalPhyObservation, synthesize_reciprocal_rssi
from crypto.skg import SkgEngine
from crypto.types import STATUS_AUTH_FAIL, STATUS_IDENTITY_FAIL, STATUS_OK, STATUS_SKG_FAIL

VECTORS = _PKG_ROOT / "crypto" / "test_vectors.json"


def _load() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def test_vector_file_is_test_only_and_omits_skg_session_key() -> None:
    data = _load()
    assert data["version"] == "a8-v1"
    assert "TEST_ONLY" in data["note"]
    assert "session_key" not in data["skg"]
    assert "key_hex" not in data["skg"]
    dumped = json.dumps(data)
    assert "candidate_key" not in dumped


def test_aead_first_encrypt_matches_vector() -> None:
    data = _load()["aead"]
    aead = AeadService()
    enc = aead.encrypt(
        data["local_id"],
        data["peer_id"],
        data["session_id"],
        _hex(data["plaintext_hex"]),
        _hex(data["aad_hex"]),
        key=_hex(data["key_hex"]),
        key_epoch=data["key_epoch"],
    )
    assert enc.status == STATUS_OK
    assert enc.key_id == data["key_id"]
    assert enc.nonce == _hex(data["first_nonce_hex"])
    assert enc.ciphertext == _hex(data["first_ciphertext_hex"])
    assert enc.plaintext is None

    dec = aead.decrypt(
        data["peer_id"],
        data["local_id"],
        data["session_id"],
        enc.ciphertext,
        _hex(data["aad_hex"]),
        key=_hex(data["key_hex"]),
        nonce=enc.nonce,
        key_id=enc.key_id,
        key_epoch=enc.key_epoch,
    )
    assert dec.status == STATUS_OK
    assert dec.plaintext == _hex(data["plaintext_hex"])


def test_aead_tamper_and_wrong_direction_match_vector() -> None:
    data = _load()["aead"]
    aead = AeadService()
    enc = aead.encrypt(
        data["local_id"],
        data["peer_id"],
        data["session_id"],
        _hex(data["plaintext_hex"]),
        _hex(data["aad_hex"]),
        key=_hex(data["key_hex"]),
        key_epoch=data["key_epoch"],
    )
    tampered = bytearray(enc.ciphertext)
    tampered[0] ^= 1
    dec_bad = aead.decrypt(
        data["peer_id"],
        data["local_id"],
        data["session_id"],
        bytes(tampered),
        _hex(data["aad_hex"]),
        key=_hex(data["key_hex"]),
        nonce=enc.nonce,
        key_id=enc.key_id,
        key_epoch=enc.key_epoch,
    )
    assert dec_bad.status == data["tamper_status"] == STATUS_AUTH_FAIL
    assert dec_bad.plaintext is None

    wrong = aead.decrypt(
        data["local_id"],
        data["peer_id"],
        data["session_id"],
        enc.ciphertext,
        _hex(data["aad_hex"]),
        key=_hex(data["key_hex"]),
        nonce=enc.nonce,
        key_id=enc.key_id,
        key_epoch=enc.key_epoch,
    )
    assert wrong.status == data["wrong_direction_status"] == STATUS_AUTH_FAIL
    assert wrong.plaintext is None


def test_skg_public_blobs_and_first_encrypt_match_vector() -> None:
    data = _load()["skg"]
    kp3 = KeyProvider(data["local_id"])
    kp7 = KeyProvider(data["peer_id"])
    skg3 = SkgEngine(data["local_id"], kp3)
    skg7 = SkgEngine(data["peer_id"], kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(
        data["local_id"],
        data["peer_id"],
        data["session_id"],
        data["probe_id"],
        n_samples=data["n_samples"],
        seed=data["seed"],
    )
    assert skg3.on_local_observation(obs3).status == STATUS_OK
    assert skg7.on_local_observation(obs7).status == STATUS_OK
    rec3 = skg3.make_reconcile_blob(data["probe_id"])
    rec7 = skg7.make_reconcile_blob(data["probe_id"])
    assert rec3.blob == _hex(data["reconcile_blob_3_hex"])
    assert rec7.blob == _hex(data["reconcile_blob_7_hex"])
    assert skg3.apply_reconcile_blob(data["probe_id"], rec7).status == STATUS_OK
    assert skg7.apply_reconcile_blob(data["probe_id"], rec3).status == STATUS_OK
    conf3 = skg3.make_confirm_blob(data["probe_id"])
    conf7 = skg7.make_confirm_blob(data["probe_id"])
    assert conf3.blob == _hex(data["confirm_blob_3_hex"])
    assert conf7.blob == _hex(data["confirm_blob_7_hex"])
    done3 = skg3.apply_confirm_blob(data["probe_id"], conf7)
    done7 = skg7.apply_confirm_blob(data["probe_id"], conf3)
    assert done3.status == STATUS_OK
    assert done7.status == STATUS_OK
    assert done3.key_id == done7.key_id == data["key_id"]
    assert done3.key_epoch == data["key_epoch"]

    enc = kp3.encrypt(
        data["local_id"],
        data["peer_id"],
        data["session_id"],
        _hex(data["plaintext_hex"]),
        _hex(data["aad_hex"]),
    )
    assert enc.status == STATUS_OK
    assert enc.nonce == _hex(data["first_nonce_hex"])
    assert enc.ciphertext == _hex(data["first_ciphertext_hex"])
    dec = kp7.decrypt(
        data["peer_id"],
        data["local_id"],
        data["session_id"],
        enc.ciphertext,
        _hex(data["aad_hex"]),
        nonce=enc.nonce,
        key_id=enc.key_id,
    )
    assert dec.status == STATUS_OK
    assert dec.plaintext == _hex(data["plaintext_hex"])


def test_scrambled_observations_match_skg_fail_vector() -> None:
    data = _load()
    fail = data["skg_fail_scrambled"]
    skg = data["skg"]
    kp3 = KeyProvider(skg["local_id"])
    kp7 = KeyProvider(skg["peer_id"])
    skg3 = SkgEngine(skg["local_id"], kp3)
    skg7 = SkgEngine(skg["peer_id"], kp7)
    obs3, obs7 = synthesize_reciprocal_rssi(
        skg["local_id"],
        skg["peer_id"],
        skg["session_id"],
        fail["probe_id"],
        seed=fail["seed"],
        peer_scrambled=fail["peer_scrambled"],
    )
    skg3.on_local_observation(obs3)
    skg7.on_local_observation(obs7)
    rec3 = skg3.make_reconcile_blob(fail["probe_id"])
    rec7 = skg7.make_reconcile_blob(fail["probe_id"])
    got3 = skg3.apply_reconcile_blob(fail["probe_id"], rec7)
    got7 = skg7.apply_reconcile_blob(fail["probe_id"], rec3)
    assert got3.status == fail["status_3"] == STATUS_SKG_FAIL
    assert got7.status == fail["status_7"] == STATUS_SKG_FAIL
    assert kp3.encrypt(
        skg["local_id"],
        skg["peer_id"],
        skg["session_id"],
        _hex(data["aead"]["plaintext_hex"]),
        _hex(data["aead"]["aad_hex"]),
    ).status == "key_unavailable"


def test_identity_signature_matches_vector() -> None:
    data = _load()["identity"]
    node3 = IdentityStore.load(data["node3"])
    node7 = IdentityStore.load(data["node7"])
    node7.trust_public(node3.public_material())
    blob = _hex(data["blob_hex"])
    signed = node3.sign_handshake(3, 7, data["session_id"], data["probe_id"], blob)
    assert signed.status == STATUS_OK
    assert signed.signature == _hex(data["signature_3_hex"])
    verified = node7.verify_handshake(
        7,
        3,
        data["session_id"],
        data["probe_id"],
        blob,
        signature=signed.signature,
        identity_id=signed.identity_id,
        public_key_pem=signed.public_key_pem,
    )
    assert verified.status == data["verify_ok_status"] == STATUS_OK

    tampered = bytes(signed.signature[:-1] + bytes([signed.signature[-1] ^ 1]))
    bad = node7.verify_handshake(
        7,
        3,
        data["session_id"],
        data["probe_id"],
        blob,
        signature=tampered,
        identity_id=signed.identity_id,
    )
    assert bad.status == data["tampered_signature_status"] == STATUS_IDENTITY_FAIL


def test_missing_observation_mapping_is_skg_fail() -> None:
    data = _load()["observation_missing"]
    obs = LocalPhyObservation.from_mapping(data["mapping"])
    assert obs.missing is True
    assert obs.measurement == ()
    kp = KeyProvider(3)
    result = SkgEngine(3, kp).on_local_observation(obs)
    assert result.status == data["expected_status"] == STATUS_SKG_FAIL
