from __future__ import annotations

from swarm_sim.csi import CSI_N_SUBCARRIERS, frequency_response_db, random_tdl_taps
from swarm_sim.domain import Node, NodeRole
from swarm_sim.events import build_event
from swarm_sim.network import FormationTopology
from swarm_sim.phy import PersistentPhyModel
from swarm_sim.simulation import RNGRegistry, RunConfig, RunContext


def _model() -> tuple[PersistentPhyModel, FormationTopology, Node, Node]:
    roles = {0: NodeRole.GCS, 1: NodeRole.LEADER, 2: NodeRole.FOLLOWER}
    topology = FormationTopology(roles)
    sender = Node(1, NodeRole.LEADER, (0.0, 0.0, 100.0), queue_capacity=8)
    receiver = Node(2, NodeRole.FOLLOWER, (80.0, 0.0, 100.0), queue_capacity=8)
    model = PersistentPhyModel(topology, RNGRegistry(7))
    return model, topology, sender, receiver


def test_frequency_response_is_not_flat() -> None:
    import random

    mag_db = frequency_response_db(random_tdl_taps(random.Random(3)))
    assert len(mag_db) == CSI_N_SUBCARRIERS
    assert max(mag_db) - min(mag_db) > 1.0


def test_phy_sample_attaches_reciprocal_csi() -> None:
    model, topology, sender, receiver = _model()
    forward = topology.get_link(1, 2)
    reverse = topology.get_link(2, 1)
    assert forward is not None and reverse is not None

    left = model.sample(forward, sender, receiver, 0.2, decode_attempt=False)
    right = model.sample(reverse, receiver, sender, 0.2, decode_attempt=False)

    assert isinstance(left.observation["rssi_dbm"], float)
    assert len(left.observation["csi_mag_db"]) == CSI_N_SUBCARRIERS
    assert len(right.observation["csi_mag_db"]) == CSI_N_SUBCARRIERS
    assert left.observation["csi_mag_db"] != right.observation["csi_mag_db"]
    assert left.truth["csi_mag_db"] == right.truth["csi_mag_db"]
    assert max(left.truth["csi_mag_db"]) - min(left.truth["csi_mag_db"]) > 1.0


def test_event_phy_carries_csi_mag_db() -> None:
    model, topology, sender, receiver = _model()
    link = topology.get_link(1, 2)
    assert link is not None
    outcome = model.sample(link, sender, receiver, 0.2, decode_attempt=False)
    context = RunContext.create(RunConfig(seed=7), run_id="csi-event")
    event = build_event(context, "PHY_SAMPLE", receiver, phy=outcome.observation)
    assert event["online_features"]["phy"]["csi_mag_db"] == outcome.observation["csi_mag_db"]
    assert event["online_features"]["phy"]["rssi_dbm"] == outcome.observation["rssi_dbm"]
