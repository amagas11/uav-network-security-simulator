"""Acceptance evidence for V6P-RL-PLAINTEXT-RISK-001."""

from __future__ import annotations

from swarm_sim.rl import UavDefenseEnv


def _config(*, encrypt: bool, with_eavesdrop: bool) -> dict:
    attacks = []
    if with_eavesdrop:
        attacks = [
            {
                "attack_family": "EAVESDROPPING",
                "attack_subtype": (
                    "CIPHERTEXT_ONLY" if encrypt else "PLAINTEXT_EXPOSURE"
                ),
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.2,
                "end_s": 1.2,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "target_link_ids": ["link-2-1"],
                "parameters": {"receiver_radius_m": 1000.0},
            }
        ]
    return {
        "duration_s": 1.4,
        "auto_traffic": False,
        "attack_specs": attacks,
        "traffic_specs": [
            {
                "source_node_id": 2,
                "target_node_id": 1,
                "packet_type": "MISSION_COMMAND",
                "start_s": 0.2,
                "payload": {"cmd": "FLY_TO", "altitude_m": 100.0},
                "interval_s": 0.2,
                "count": 2,
                "sensitive": True,
                "encrypt": encrypt,
            }
        ],
    }


def _state(*, encrypt: bool, with_eavesdrop: bool) -> dict:
    env = UavDefenseEnv(observer_node_id=2)
    env.reset(6901, _config(encrypt=encrypt, with_eavesdrop=with_eavesdrop))
    assert env.episode is not None
    env.episode.runtime.run_to_completion()
    return env.episode.runtime.rl_observation(2)["security"]


def test_rl_plaintext_risk_is_local_protection_state_not_capture_truth():
    no_attacker = _state(encrypt=False, with_eavesdrop=False)
    attacker = _state(encrypt=False, with_eavesdrop=True)
    protected = _state(encrypt=True, with_eavesdrop=True)

    assert no_attacker["unprotected_sensitive_count"] > 0
    assert no_attacker["plaintext_protection_risk"] > 0
    assert attacker["plaintext_protection_risk"] == no_attacker["plaintext_protection_risk"]
    assert protected["plaintext_protection_risk"] == 0.0
    assert protected["unprotected_sensitive_count"] == 0
    for state in (no_attacker, attacker, protected):
        assert "actual_eavesdrop_capture" not in state
        assert "attacker_present" not in state
        assert "attacker_recovered_plaintext" not in state
