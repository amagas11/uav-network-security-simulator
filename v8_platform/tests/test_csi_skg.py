from __future__ import annotations

from pathlib import Path

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.csi import CSI_N_SUBCARRIERS
from swarm_sim.integrations.person_a.bridge import _load_person_a_library


SESSION = "link-1-2-csi"
AAD = b"src=1,dst=2,seq=1,msg_type=data,key_epoch=1,direction=1->2"
PLAINTEXT = b"csi-skg"


def _library():
    root = Path(__file__).resolve().parents[2] / "person_a_crypto" / "upstream"
    return _load_person_a_library(root)


def test_platform_csi_probe_completes_skg_and_encrypts() -> None:
    runtime = PlatformRuntime(RunConfig(seed=11, auto_traffic=False), run_id="csi-skg")
    first, second = runtime.probes.probe(1, 2, session_id=SESSION, measurement_kind="csi")
    assert first.measurement_kind == second.measurement_kind == "csi"
    assert first.measurement is not None and second.measurement is not None
    assert len(first.measurement) == len(second.measurement) == CSI_N_SUBCARRIERS
    assert first.measurement != second.measurement
    assert first.probe_id == second.probe_id

    library = _library()
    status_ok = library.types.STATUS_OK
    providers = {
        1: library.key_provider.KeyProvider(1),
        2: library.key_provider.KeyProvider(2),
    }
    engines = {
        1: library.skg.SkgEngine(1, providers[1]),
        2: library.skg.SkgEngine(2, providers[2]),
    }
    observations = {
        1: library.observations.LocalPhyObservation.from_mapping(first.to_dict()),
        2: library.observations.LocalPhyObservation.from_mapping(second.to_dict()),
    }
    assert engines[1].on_local_observation(observations[1]).status == status_ok
    assert engines[2].on_local_observation(observations[2]).status == status_ok
    rec1 = engines[1].make_reconcile_blob(first.probe_id)
    rec2 = engines[2].make_reconcile_blob(second.probe_id)
    assert engines[1].apply_reconcile_blob(first.probe_id, rec2).status == status_ok
    assert engines[2].apply_reconcile_blob(second.probe_id, rec1).status == status_ok
    conf1 = engines[1].make_confirm_blob(first.probe_id)
    conf2 = engines[2].make_confirm_blob(second.probe_id)
    done1 = engines[1].apply_confirm_blob(first.probe_id, conf2)
    done2 = engines[2].apply_confirm_blob(second.probe_id, conf1)
    assert done1.status == status_ok
    assert done2.status == status_ok
    assert done1.key_id == done2.key_id

    enc = providers[1].encrypt(1, 2, SESSION, PLAINTEXT, AAD)
    assert enc.status == status_ok
    dec = providers[2].decrypt(2, 1, SESSION, enc.ciphertext, AAD, nonce=enc.nonce, key_id=enc.key_id)
    assert dec.status == status_ok
    assert dec.plaintext == PLAINTEXT
