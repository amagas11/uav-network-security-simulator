from dataclasses import replace

import pytest

from swarm_sim.rff import RffIdentificationResult
from swarm_sim.rff_policy import RffIngressPolicy


def _identity(state="MATCH", **changes):
    result = RffIdentificationResult(state, 2, 2, 1.0, 3.0, 0.8, 0.9, "NEAREST_TEMPLATE_ACCEPTED")
    return replace(result, **changes)


def _decide(policy, identity=None, **changes):
    values = dict(sim_time_s=0.0, identification=identity or _identity(),
        claimed_is_whitelisted=True, predicted_is_whitelisted=True,
        queue_ratio=0.0, packet_rate_pps=1.0)
    values.update(changes)
    return policy.evaluate(**values)


@pytest.mark.parametrize("identity", [
    _identity("MISMATCH", predicted_device_id=3),
    _identity("UNKNOWN", predicted_device_id=None, reason="NO_TEMPLATE_WITHIN_THRESHOLD"),
])
def test_single_qualified_identity_anomaly_drops_without_pressure(identity):
    decision = _decide(RffIngressPolicy(policy_mode="ENFORCE"), identity)
    assert decision.drop and decision.would_drop and decision.confirmed_identity_anomaly
    assert decision.reason == "RFF_IDENTITY_MISMATCH"
    assert decision.policy_state == "NORMAL"


def test_observe_only_never_executes_a_drop():
    decision = _decide(RffIngressPolicy(), _identity("MISMATCH", predicted_device_id=3))
    assert decision.would_drop and not decision.drop


@pytest.mark.parametrize("identity", [
    _identity("LOW_QUALITY", quality=0.1, predicted_device_id=None),
    _identity("AMBIGUOUS", predicted_device_id=None),
    _identity("UNAVAILABLE", quality=None, predicted_device_id=None),
    _identity("UNKNOWN", predicted_device_id=None, reason="NO_ENROLLED_TEMPLATES"),
    _identity("UNKNOWN", claimed_link_sender_id=None, reason="CLAIMED_LINK_SENDER_UNAVAILABLE"),
])
def test_unverified_identity_is_not_accused_and_only_dropped_in_strict_mode(identity):
    policy = RffIngressPolicy(policy_mode="ENFORCE")
    normal = _decide(policy, identity)
    strict = _decide(policy, identity, queue_ratio=0.6)
    assert not normal.drop and not normal.confirmed_identity_anomaly
    assert strict.drop and not strict.confirmed_identity_anomaly
    assert strict.reason == "RFF_STRICT_UNVERIFIED"


def test_strict_whitelist_checks_quality_equality_and_both_memberships():
    policy = RffIngressPolicy(policy_mode="ENFORCE")
    assert not _decide(policy, queue_ratio=0.6).drop
    assert _decide(policy, predicted_is_whitelisted=False).drop
    assert _decide(policy, claimed_is_whitelisted=False).drop
    assert _decide(policy, _identity(predicted_device_id=3)).drop
    assert _decide(policy, _identity(quality=0.1)).drop


def test_pressure_clear_hold_restarts_and_exits_without_new_frames():
    policy = RffIngressPolicy(policy_mode="ENFORCE", strict_hold_s=2)
    assert policy.refresh(sim_time_s=0, queue_ratio=0.6, packet_rate_pps=0)
    assert policy.state == "RFF_STRICT_WHITELIST"
    assert policy.refresh(sim_time_s=1, queue_ratio=0, packet_rate_pps=0) is None
    assert policy.clear_since_s == 1
    policy.refresh(sim_time_s=2, queue_ratio=0, packet_rate_pps=8)
    assert policy.clear_since_s is None
    policy.refresh(sim_time_s=3, queue_ratio=0, packet_rate_pps=0)
    policy.refresh(sim_time_s=4.99, queue_ratio=0, packet_rate_pps=0)
    assert policy.state == "RFF_STRICT_WHITELIST"
    assert policy.refresh(sim_time_s=5, queue_ratio=0, packet_rate_pps=0)
    assert policy.state == "NORMAL"
    assert policy.strict_since_s is None


def test_rate_trigger_is_optional_but_queue_pressure_is_independent():
    policy = RffIngressPolicy(strict_on_rate_alarm=False)
    policy.refresh(sim_time_s=0, queue_ratio=0, packet_rate_pps=100)
    assert policy.state == "NORMAL"
    policy.refresh(sim_time_s=1, queue_ratio=1, packet_rate_pps=0)
    assert policy.state == "RFF_STRICT_WHITELIST"


@pytest.mark.parametrize("changes", [dict(sim_time_s=-1), dict(sim_time_s=float("nan")),
    dict(queue_ratio=1.1), dict(packet_rate_pps=float("inf"))])
def test_invalid_local_measurements_are_rejected(changes):
    with pytest.raises(ValueError):
        _decide(RffIngressPolicy(), **changes)


def test_policy_rejects_time_regression():
    policy = RffIngressPolicy()
    _decide(policy, sim_time_s=1)
    with pytest.raises(ValueError):
        _decide(policy, sim_time_s=0)
