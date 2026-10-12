from __future__ import annotations

from collections import Counter

from fastapi.testclient import TestClient
import pytest

from app.app import app, controller
from swarm_sim import AttackPlan, PlatformRuntime, RunConfig


def _plan(family: str, subtype: str, **values) -> AttackPlan:
    data = {
        "attack_family": family,
        "attack_subtype": subtype,
        "scheduled_start_s": 0.0,
        "impact_start_s": 0.0,
        "end_s": 0.8,
    }
    data.update(values)
    return AttackPlan(**data)


def _security_events(runtime: PlatformRuntime, message_id: str | None = None):
    return [
        event
        for event in runtime.events
        if event["event_type"] == "AUTH_RESULT"
        and (message_id is None or event["message_id"] == message_id)
    ]


def _defense_events(runtime: PlatformRuntime, message_id: str | None = None):
    return [
        event
        for event in runtime.events
        if event["event_type"] == "DEFENSE_RESULT"
        and (message_id is None or event["message_id"] == message_id)
    ]


def test_t1_runtime_spoofing_auth_drop_is_attributed_by_evaluation():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, rx_service_per_step=16),
        run_id="v11-eval-spoof",
    )
    runtime.schedule_attack(
        _plan(
            "SPOOFING",
            "KNOWN_ID_CONFLICT",
            attacker_node_id=-1,
            target_node_ids=[1],
            parameters={"claimed_src_id": 0},
        )
    )
    runtime.run_to_completion()

    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["modified_fields"] == ["claimed_src_id"]
    auth = _security_events(runtime)
    assert any(
        event["online_features"]["security_state"]["application_hmac_result"]
        == "FAIL"
        and event["online_features"]["security_state"][
            "application_hmac_failure_reason"
        ]
        == "HMAC_MISMATCH"
        for event in auth
    )
    defenses = _defense_events(runtime)
    assert any(
        event["extensions"]["defense_result"]["request"]["reason"]
        == "AUTH_FAILURE"
        and event["extensions"]["defense_result"]["request"]["action"]
        == "DROP_PACKET"
        and event["extensions"]["defense_result"]["executed"] is True
        for event in defenses
    )
    episode = runtime.evaluation_view()["episodes"][0]
    assert episode["episode_detected"] is True
    assert episode["action_executed"] is True
    assert episode["executed_defense_count"] >= 1
    assert episode["defense_attempts"]
    assert episode["defense_effective"] is True


def test_t2_runtime_small_post_hmac_fdi_drop_is_attributed_by_evaluation():
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.0, auto_traffic=False, rx_service_per_step=16),
        run_id="v11-eval-fdi",
    )
    runtime.schedule_attack(
        _plan(
            "FDI",
            "TELEMETRY_ABRUPT_CHANGE",
            attacker_node_id=2,
            target_node_ids=[1],
            parameters={"field": "altitude_m", "absolute_offset": 0.1},
        )
    )
    message_id = runtime.queue_message(
        2,
        1,
        "TELEMETRY",
        {"altitude_m": 100.0, "flight_state": "FLYING"},
        encrypt=False,
    )
    runtime.run_to_completion()

    label = runtime.attack_scheduler.labels()[0]
    assert label["truth"]["injection_stage"] == "POST_HMAC_PRE_TRANSMISSION"
    assert label["truth"]["application_hmac_recomputed"] is False
    assert label["truth"]["modified_value"]["altitude_m"] == pytest.approx(100.1)
    auth = _security_events(runtime, message_id)
    assert len(auth) == 1
    assert auth[0]["online_features"]["security_state"][
        "application_hmac_failure_reason"
    ] == "HMAC_MISMATCH"
    defenses = _defense_events(runtime, message_id)
    assert len(defenses) == 1
    assert defenses[0]["extensions"]["defense_result"]["executed"] is True
    assert 2 not in runtime.nodes[1].telemetry_by_source
    episode = runtime.evaluation_view()["episodes"][0]
    assert episode["episode_detected"] is True
    assert episode["action_executed"] is True
    assert episode["executed_defense_count"] >= 1
    assert episode["defense_attempts"]
    assert episode["defense_effective"] is True


def _flood_runtime(*, auto_traffic: bool = False, end_s: float = 0.8):
    runtime = PlatformRuntime(
        RunConfig(
            seed=42,
            duration_s=1.6,
            step_s=0.2,
            auto_traffic=auto_traffic,
            queue_capacity=32,
            tx_service_per_step=4,
            rx_service_per_step=2,
            flooding_packet_rate_threshold_pps=8.0,
        ),
        run_id=f"v11-flood-{int(auto_traffic)}-{end_s}",
    )
    runtime.schedule_attack(
        _plan(
            "DOS",
            "FLOODING",
            end_s=end_s,
            attacker_node_id=-1,
            target_node_ids=[1],
            intensity={"value": 80.0, "unit": "pps"},
        )
    )
    return runtime


def test_t3_t4_flood_arrival_precedes_hmac_and_rejection_precedes_rx_queue():
    runtime = _flood_runtime()
    max_rx_queue = 0
    runtime.start()
    while not runtime.is_terminated:
        runtime.step()
        max_rx_queue = max(max_rx_queue, len(runtime.nodes[1].rx_queue))

    label = runtime.attack_scheduler.labels()[0]
    arrival_events = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS"
        and event["observer_node_id"] == 1
        and event["message_id"] in set(label["truth"]["generated_message_ids"])
    ]
    assert arrival_events
    assert max(
        event["online_features"]["traffic"]["packet_rate_pps"]
        for event in arrival_events
    ) >= runtime.config.flooding_packet_rate_threshold_pps
    assert label["outcome"]["receiver_total_rate_exceeded"] is True
    assert label["outcome"]["application_hmac_rejected"] is True
    assert label["outcome"]["malicious_traffic_blocked"] > 0
    assert max_rx_queue == 0
    assert not runtime.nodes[-1].tx_queue


def test_t5_flood_hmac_gate_preserves_legitimate_service():
    runtime = _flood_runtime()
    legitimate_id = runtime.queue_message(
        2, 1, "STATUS", {"status_code": 1, "value": 7}, encrypt=False
    )
    runtime.run_to_completion()
    assert any(
        message.message_id == legitimate_id
        for message in runtime.nodes[1].delivered_messages
    )
    legitimate_auth = _security_events(runtime, legitimate_id)
    assert len(legitimate_auth) == 1
    assert legitimate_auth[0]["online_features"]["security_state"][
        "application_hmac_result"
    ] == "PASS"
    label = runtime.attack_scheduler.labels()[0]
    assert label["outcome"]["malicious_traffic_blocked"] > 0
    assert not runtime.nodes[1].rate_limited_peer_ids


def test_t6_t7_flood_pps_is_air_tx_attempt_rate_without_post_end_backlog():
    end_s = 0.8
    runtime = _flood_runtime(end_s=end_s)
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    truth = label["truth"]
    generated_ids = set(truth["generated_message_ids"])
    tx_events = [
        event
        for event in runtime.events
        if event["event_type"] == "TX" and event["message_id"] in generated_ids
    ]
    active_ticks = 3  # 0.2, 0.4, 0.6; end_s is exclusive.
    expected = active_ticks * round(80.0 * runtime.config.step_s)
    assert truth["generated_packets"] == expected
    assert truth["transmitted_packets"] == expected
    assert len(tx_events) == expected
    assert Counter(event["sim_time_s"] for event in tx_events) == {
        0.2: 16,
        0.4: 16,
        0.6: 16,
    }
    assert not [event for event in tx_events if event["sim_time_s"] >= end_s]
    rx_events = [
        event
        for event in runtime.events
        if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}
        and event["message_id"] in generated_ids
    ]
    assert not [event for event in rx_events if event["sim_time_s"] >= end_s]
    assert not runtime.nodes[-1].tx_queue
    assert label["outcome"]["queued_backlog_count"] == 0


def test_t8_normal_tx_service_budget_is_unchanged():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.4,
            step_s=0.2,
            auto_traffic=False,
            queue_capacity=32,
            tx_service_per_step=4,
            rx_service_per_step=2,
        ),
        run_id="v11-normal-budget",
    )
    message_ids = {
        runtime.queue_message(2, 1, "STATUS", {"status_code": 1, "value": index})
        for index in range(10)
    }
    runtime.start()
    runtime.step()
    tx = [
        event
        for event in runtime.events
        if event["event_type"] == "TX" and event["message_id"] in message_ids
    ]
    assert len(tx) == runtime.config.tx_service_per_step == 4
    assert len(runtime.nodes[2].tx_queue) == 6


def _official_eaves_body() -> dict[str, object]:
    return {
        "seed": 31,
        "duration_s": 4.0,
        "step_s": 0.1,
        "node_count": 4,
        "auto_traffic": False,
        "auto_advance": False,
        "encrypt_sensitive": True,
        "tx_service_per_step": 32,
        "rx_service_per_step": 32,
        "phy_sample_interval_s": 10.0,
        "attack_specs": [
            {
                "attack_family": "EAVESDROPPING",
                "attack_subtype": "CIPHERTEXT_ONLY",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.1,
                "end_s": 3.8,
                "attacker_node_id": -1,
                "target_node_ids": [1],
                "target_link_ids": ["link-2-1"],
                "parameters": {"receiver_radius_m": 1000.0},
            }
        ],
        "traffic_specs": [
            {
                "source_node_id": 2,
                "target_node_id": 1,
                "packet_type": "STATUS",
                "start_s": 0.1,
                "payload": {"status_code": 1, "value": 42.0},
                "interval_s": 0.2,
                "count": 18,
                "sensitive": True,
                "encrypt": True,
                "session_id": "official-web-eaves-session",
            }
        ],
    }


def test_t9_t10_official_fastapi_uses_real_person_a_skg_and_aead():
    with TestClient(app) as client:
        response = client.post("/api/runs", json=_official_eaves_body())
        assert response.status_code == 201, response.text
        runtime = controller.manager.runtime
        assert runtime is not None
        assert type(runtime.key_provider).__name__ == "PersonAKeyCoordinator"
        assert type(runtime.crypto).__name__ == "PersonACryptoProvider"
        assert type(runtime.security_coordinator).__name__ == "PersonAKeyCoordinator"
        assert runtime.probes.profile == "V8_DEFAULT"
        assert not runtime.security_coordinator._bundle_factory.test_only_preloaded_keys
        for _ in range(40):
            step = client.post("/api/debug/step")
            assert step.status_code == 200, step.text

    control_tx = [
        event
        for event in runtime.events
        if event["event_type"] == "TX"
        and event["online_features"]["packet"]["packet_type"] == "SKG_CONTROL"
    ]
    control_rx = [
        event
        for event in runtime.events
        if event["event_type"] == "RX_SUCCESS"
        and event["online_features"]["packet"]["packet_type"] == "SKG_CONTROL"
    ]
    assert control_tx and control_rx
    assert any(
        handshake.status == "AVAILABLE"
        for handshake in runtime.security_coordinator.handshakes.values()
    )
    encrypted_business = [
        event
        for event in runtime.events
        if event["event_type"] == "TX"
        and event["online_features"]["packet"]["packet_type"] == "STATUS"
        and event["online_features"]["packet"]["encrypted"] is True
    ]
    assert encrypted_business
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["captured_count"] > 0
    assert outcome["ciphertext_count"] > 0
    assert outcome.get("plaintext_exposure_count", 0) == 0
    assert outcome.get("content_recovery_count", 0) == 0
    providers = runtime.run_record()["security_providers"]
    assert providers["key_provider"]["name"] == "PersonAKeyCoordinator"
    assert providers["crypto_provider"]["name"] == "PersonACryptoProvider"


@pytest.mark.parametrize(
    "family,subtype",
    [
        ("SPOOFING", "KNOWN_ID_CONFLICT"),
        ("DOS", "FLOODING"),
        ("FDI", "TELEMETRY_ABRUPT_CHANGE"),
        ("REPLAY", "IMMEDIATE_REPLAY"),
    ],
)
def test_t11_non_eavesdrop_attack_frames_remain_plaintext(family, subtype):
    runtime = PlatformRuntime(
        RunConfig(duration_s=1.2, auto_traffic=False, rx_service_per_step=32),
        run_id=f"v11-plaintext-{family.lower()}",
    )
    values: dict[str, object] = {
        "attacker_node_id": -1,
        "target_node_ids": [1],
    }
    if family == "SPOOFING":
        values["parameters"] = {"claimed_src_id": 0}
    elif family == "DOS":
        values["intensity"] = {"value": 80.0, "unit": "pps"}
    elif family == "FDI":
        values.update(
            attacker_node_id=2,
            parameters={"field": "altitude_m", "absolute_offset": 0.1},
        )
    else:
        values["parameters"] = {"max_capture_age_s": 1.0}
        values["impact_start_s"] = 0.4
    runtime.schedule_attack(_plan(family, subtype, **values))
    if family == "FDI":
        runtime.queue_message(
            2, 1, "TELEMETRY", {"altitude_m": 100.0}, encrypt=False
        )
    elif family == "REPLAY":
        runtime.queue_message(2, 1, "STATUS", {"value": 1}, encrypt=False)
    runtime.run_to_completion()
    assert runtime.config.encrypt_sensitive is False
    assert [event for event in runtime.events if event["event_type"] == "TX"]
    assert not any(
        event["online_features"]["packet"]["encrypted"] is True
        for event in runtime.events
        if event["event_type"] == "TX"
    )


def test_t12_pre_ingress_hmac_cache_does_not_double_consume_replay_window():
    runtime = PlatformRuntime(
        RunConfig(
            duration_s=0.8,
            auto_traffic=False,
            tx_service_per_step=8,
            rx_service_per_step=8,
        ),
        run_id="v11-replay-ingress-cache",
    )
    ids = [
        runtime.queue_message(
            2,
            1,
            "STATUS",
            {"value": sequence},
            sequence_no=sequence,
            session_id="v11-reorder-session",
            encrypt=False,
        )
        for sequence in (100, 101, 103, 102)
    ]
    runtime.run_to_completion()
    auth_counts = Counter(
        event["message_id"] for event in _security_events(runtime)
    )
    assert all(auth_counts[message_id] == 1 for message_id in ids)
    last = _security_events(runtime, ids[-1])[0]["online_features"]["security_state"]
    assert last["application_hmac_result"] == "PASS"
    assert last["replay_check_result"] == "PASS"
