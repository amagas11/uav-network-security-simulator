from copy import deepcopy

from swarm_sim.rff_evaluation import evaluate_rff


def _label(attack_id="a", family="FDI", targets=(1,)):
    return {"attack_id": attack_id, "attack_family": family,
            "impact_start_s": 0.1, "target_node_ids": list(targets)}


def _sample(event_id="rx1", emission="tx1", *, attack_id="a", actual_sender=-1,
            receiver=1, quality=0.9, confirmed=True, dropped=True, decoded=True):
    event = {"event_id": event_id, "event_type": "RX_SUCCESS" if decoded else "RX_FAILURE",
        "message_id": "same-message", "observer_node_id": receiver, "sim_time_s": 0.5,
        "online_features": {"packet": {"claimed_link_sender_id": 2},
            "phy": {"rff_observation": {"quality": quality,
                "extraction_status": "AVAILABLE" if quality >= 0.45 else "LOW_QUALITY"}}},
        "extensions": {"air_emission_ref": emission, "rff_decision": {
            "confirmed_identity_anomaly": confirmed, "drop": dropped,
            "quality": quality, "identity_result": "UNKNOWN" if confirmed else "MATCH"}}}
    transmission = {"emission_id": emission, "attack_id": attack_id,
        "actual_sender_id": actual_sender, "receiver_id": receiver}
    return event, transmission


def _evaluate(events, labels, transmissions, **options):
    return evaluate_rff(events, labels, transmissions=transmissions,
        legitimate_node_ids=[0, 1, 2, 3], enabled=True,
        policy_mode=options.get("policy_mode", "ENFORCE"))


def test_physical_rates_use_causal_external_target_samples_and_deduplicate_events():
    event, transmission = _sample()
    report = _evaluate([event, deepcopy(event)], [_label()], [transmission])
    row = report["by_family"]["FDI"]
    assert row["qualified_attack_samples"] == 1
    assert row["observable_episodes"] == 1
    assert row["detected_episodes"] == 1
    assert row["detection_rate"] == 1.0
    assert row["blocked_samples"] == 1
    assert row["block_rate"] == 1.0
    assert row["mean_detection_delay_s"] == 0.4


def test_same_message_wrong_emission_target_and_attack_do_not_cross_match():
    events, transmissions = zip(
        _sample("rx-other-attack", "tx-b", attack_id="b"),
        _sample("rx-wrong-target", "tx-2", receiver=2),
    )
    report = _evaluate(list(events), [_label()], list(transmissions))
    row = report["by_family"]["FDI"]
    assert row["observable_episodes"] == 0
    assert row["detection_rate"] is None
    assert row["blocked_samples"] == 0


def test_low_quality_protective_drop_is_not_a_detected_attack():
    event, transmission = _sample(quality=0.1, confirmed=False)
    report = _evaluate([event], [_label()], [transmission])
    assert report["protective_unverified_drops"] == 1
    assert report["by_family"]["FDI"]["observable_episodes"] == 0
    assert report["by_family"]["FDI"]["detection_rate"] is None


def test_legal_compromised_radio_and_passive_listener_have_no_detection_denominator():
    event, transmission = _sample(actual_sender=2, confirmed=False, dropped=False)
    report = _evaluate([event], [_label(), _label("e", "EAVESDROPPING")], [transmission])
    assert report["episodes"][0]["unavailable_reason"] == "NO_EXTERNAL_RETRANSMISSION"
    assert report["by_family"]["FDI"]["detection_rate"] is None
    assert report["by_family"]["EAVESDROPPING"]["detection_rate"] is None


def test_missing_receive_is_unobservable_and_failed_decode_cannot_be_blocked():
    event, transmission = _sample(decoded=False, dropped=False)
    report = _evaluate([event], [_label(), _label("missing", "REPLAY")], [transmission])
    row = report["by_family"]["FDI"]
    assert row["detection_rate"] == 1.0
    assert row["defense_opportunities"] == 0
    assert row["block_rate"] is None
    assert report["by_family"]["REPLAY"]["detection_rate"] is None


def test_observe_only_cannot_be_assigned_executed_defense_success():
    event, transmission = _sample(dropped=True)
    report = _evaluate([event], [_label()], [transmission], policy_mode="OBSERVE_ONLY")
    assert report["by_family"]["FDI"]["blocked_samples"] == 0
    assert report["by_family"]["FDI"]["block_rate"] is None


def test_false_positives_count_only_qualified_normal_legal_emissions():
    normal, normal_tx = _sample("normal", "normal-tx", attack_id=None, actual_sender=2)
    low, low_tx = _sample("low", "low-tx", attack_id=None, actual_sender=2, quality=0.1)
    attack, attack_tx = _sample()
    report = _evaluate([normal, low, attack], [_label()], [normal_tx, low_tx, attack_tx])
    assert report["normal_qualified_samples"] == 1
    assert report["false_positive_samples"] == 1
    assert report["false_positive_rate"] == 1.0
