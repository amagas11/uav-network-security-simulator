from __future__ import annotations

from copy import deepcopy

import pytest

from swarm_sim import AttackPlan, PlatformRuntime, RunConfig
from swarm_sim.adapters import MockKeyProvider, TestOnlyAeadCryptoProvider
from swarm_sim.domain import Message
from swarm_sim.events import assert_online_truth_free, find_forbidden_online_fields
from swarm_sim.security import DefenseAction, DefenseRequest


def _plan(family: str, subtype: str, **overrides):
    values = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.2,
        "end_s": 1.2,
    }
    values.update(overrides)
    return AttackPlan(**values)


def _predictions(runtime: PlatformRuntime) -> list[str]:
    return [
        event["extensions"]["model_result"]["predicted_label"]
        for event in runtime.events
        if event["event_type"] == "MODEL_RESULT"
        and event["extensions"]["model_result"]["predicted_label"]
    ]


def test_crypto_uses_aes_gcm_and_detects_tampering():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False), run_id="crypto")
    message = Message(
        message_id="crypto-msg",
        origin_node_id=2,
        final_dst_node_id=1,
        claimed_src_id=2,
        claimed_dst_id=1,
        packet_type="TELEMETRY",
        payload={"altitude_m": 100.0},
        sequence_no=1,
        session_id="s",
        key_epoch=1,
        created_time_s=0.0,
        route=[2, 1],
        sensitive=True,
        encrypt_requested=True,
    )
    frame = runtime.crypto.protect(message, 2, 1, "link-2-1", 0)
    assert frame.encrypted
    assert frame.protected_payload["algorithm"] == "AES-256-GCM"
    assert "altitude_m" not in frame.protected_payload
    assert runtime.crypto.open(frame, 1).payload == message.payload
    tampered = frame.clone_for_replay()
    tampered.protected_payload["ciphertext_b64"] = "AA=="
    assert runtime.crypto.open(tampered, 1).auth_result == "FAIL"


def test_mock_key_provider_is_never_claimed_as_skg():
    provider = MockKeyProvider(42)
    crypto = TestOnlyAeadCryptoProvider(provider)
    assert provider.implementation_status == "TEST_ONLY_NOT_SKG"
    assert crypto.implementation_status == "TEST_ONLY_AEAD_NOT_SKG"


def test_fdi_rejects_external_and_allows_distinct_business_target():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    with pytest.raises(ValueError, match="EXISTING_COMPROMISED_NODE"):
        runtime.schedule_attack(
            _plan("FDI", "COMMAND_REPLACEMENT", attacker_node_id=-1, target_node_ids=[2])
        )
    scheduled = runtime.schedule_attack(
        _plan("FDI", "COMMAND_REPLACEMENT", attacker_node_id=2, target_node_ids=[3])
    )
    assert scheduled["attacker_node_id"] == 2
    assert scheduled["target_node_ids"] == [3]


def test_spoofing_is_detected_from_auth_failure():
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False))
    runtime.schedule_attack(
        _plan("SPOOFING", "KNOWN_ID_CONFLICT", attacker_node_id=-1, target_node_ids=[1])
    )
    runtime.run_to_completion()
    assert "AUTH_FAILURE" in _predictions(runtime)
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["actual_transmitter_id"] == -1
    assert label["outcome"]["detected"] is True


def test_eavesdropping_has_radius_and_ciphertext_outcome_not_fake_detection():
    runtime = PlatformRuntime(RunConfig(duration_s=1.2, auto_traffic=False))
    runtime.schedule_attack(
        _plan(
            "EAVESDROPPING",
            "PASSIVE_CAPTURE",
            attacker_node_id=-1,
            parameters={"receiver_radius_m": 1000.0},
        )
    )
    runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95}, sensitive=True)
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["captured_count"] >= 1
    assert outcome["ciphertext_count"] >= 1
    assert outcome.get("plaintext_exposure_count", 0) == 0
    assert runtime.evaluation_view()["eavesdropping"]["online_detection_rate"] is None


def test_unencrypted_sensitive_payload_can_be_exposed_to_local_eavesdropper():
    runtime = PlatformRuntime(RunConfig(duration_s=1.2, auto_traffic=False))
    runtime.schedule_attack(
        _plan(
            "EAVESDROPPING",
            "PASSIVE_CAPTURE",
            attacker_node_id=-1,
            parameters={"receiver_radius_m": 1000.0},
        )
    )
    runtime.queue_message(
        2, 0, "TELEMETRY", {"altitude_m": 95}, sensitive=True, encrypt=False
    )
    runtime.run_to_completion()
    assert runtime.attack_scheduler.labels()[0]["outcome"]["plaintext_exposure_count"] >= 1


def test_flooding_uses_receiver_total_rate_and_hmac_gate():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=1.6,
            auto_traffic=False,
            queue_capacity=32,
            tx_service_per_step=20,
            rx_service_per_step=20,
        )
    )
    runtime.schedule_attack(
        _plan(
            "DOS",
            "FLOODING",
            attacker_node_id=-1,
            target_node_ids=[1],
            intensity={"value": 100.0, "unit": "pps"},
        )
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["generated_packets"] > 0
    assert label["outcome"]["receiver_total_rate_exceeded"] is True
    assert label["outcome"]["malicious_traffic_blocked"] > 0
    assert "DOS" in _predictions(runtime)
    assert runtime.nodes[1].rate_limited_peer_ids == set()


@pytest.mark.parametrize(
    ("subtype", "parameters"),
    [
        ("COMMAND_REPLACEMENT", {"replacement": {"cmd": "LAND", "altitude_m": 0}}),
        ("TELEMETRY_GRADUAL_DRIFT", {"field": "altitude_m", "delta_per_step": 5}),
        ("OUT_OF_RANGE_VALUE", {"field": "altitude_m", "value": 5000}),
        ("LOGICAL_INCONSISTENCY", {"altitude_m": 120}),
    ],
)
def test_fdi_subtypes_mutate_after_hmac_and_are_rejected(subtype: str, parameters: dict):
    runtime = PlatformRuntime(RunConfig(duration_s=1.0, auto_traffic=False))
    runtime.schedule_attack(
        AttackPlan(
            attack_family="FDI",
            attack_subtype=subtype,
            scheduled_start_s=0,
            impact_start_s=0,
            end_s=0.8,
            attacker_node_id=2,
            target_node_ids=[0],
            parameters=parameters,
        )
    )
    packet_type = "MISSION_COMMAND" if subtype == "COMMAND_REPLACEMENT" else "TELEMETRY"
    runtime.queue_message(
        2,
        0,
        packet_type,
        {"cmd": "REPORT", "altitude_m": 100.0, "flight_state": "FLYING"},
        sensitive=False,
        encrypt=False,
    )
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["injection_stage"] == "POST_HMAC_PRE_TRANSMISSION"
    assert label["truth"]["original_value"] != label["truth"]["modified_value"]
    assert label["outcome"]["application_hmac_rejected"] is True
    assert label["outcome"]["malicious_content_executed"] is False


def test_replay_uses_scoped_capture_and_preserves_message_identity():
    runtime = PlatformRuntime(RunConfig(duration_s=1.6, auto_traffic=False))
    plan = _plan(
        "REPLAY",
        "CAPTURE_AND_REPLAY",
        impact_start_s=0.6,
        end_s=1.2,
        attacker_node_id=-1,
        target_node_ids=[1],
    )
    runtime.schedule_attack(plan)
    message_id = runtime.queue_message(2, 0, "TELEMETRY", {"altitude_m": 95})
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["captured_frame_count"] >= 1
    assert label["truth"]["replayed_message_id"] == message_id
    assert "REPLAY" in _predictions(runtime)


def test_online_truth_guard_rejects_nested_leak():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    event = deepcopy(runtime.events[0])
    event["online_features"]["packet"]["attack_type"] = "FDI"
    with pytest.raises(ValueError, match="forbidden simulator truth"):
        assert_online_truth_free(event)


def test_defense_executor_denies_cross_node_request():
    runtime = PlatformRuntime(RunConfig(auto_traffic=False))
    request = DefenseRequest(
        request_id="bad",
        action=DefenseAction.REAUTH_REKEY_REQUEST,
        requester_node_id=2,
        target_node_id=1,
    )
    result = runtime.defense.execute(request, runtime.nodes[1], 0.0)
    assert result.allowed is False
    assert result.executed is False
    assert result.failure_reason == "REQUESTER_NOT_AUTHORIZED_FOR_NODE"


def test_security_report_caches_while_disconnected_then_reaches_gcs():
    runtime = PlatformRuntime(RunConfig(duration_s=2.2, auto_traffic=False))
    runtime.topology.set_bidirectional_active(1, 2, False)
    runtime._refresh_local_topology()
    runtime.schedule_attack(
        _plan(
            "SPOOFING",
            "UNKNOWN_ID",
            attacker_node_id=-1,
            target_node_ids=[2],
            end_s=0.5,
        )
    )
    runtime.start()
    runtime.step()
    runtime.step()
    assert runtime.reporting.pending_for(2)
    assert not runtime.reporting.gcs_inbox
    runtime.topology.set_bidirectional_active(1, 2, True)
    runtime._refresh_local_topology()
    while runtime.state == runtime.state.RUNNING:
        runtime.step()
    assert runtime.reporting.gcs_inbox
    assert runtime.reporting.gcs_inbox[0]["report_received_time_s"] is not None
