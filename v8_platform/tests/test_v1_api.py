from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.app import app, sim_manager
from swarm_sim.simulation import SCHEMA_VERSION, SOFTWARE_VERSION


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


def _create(client: TestClient, **overrides):
    body = {
        "seed": 42,
        "duration_s": 2,
        "step_s": 0.2,
        "node_count": 4,
        "auto_traffic": True,
        "auto_advance": False,
    }
    body.update(overrides)
    response = client.post("/api/runs", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_health_and_openapi_expose_versioned_service(client):
    assert client.get("/api/health").json() == {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "software_version": SOFTWARE_VERSION,
    }
    assert client.get("/openapi.json").json()["info"]["version"] == "7.0.0"


def test_current_run_endpoint_distinguishes_reachable_idle_service(client):
    previous = sim_manager.runtime
    sim_manager.runtime = None
    try:
        response = client.get("/api/runs/current")
        assert response.status_code == 200
        assert response.json() == {"runtime_available": True, "run": None}
    finally:
        sim_manager.runtime = previous

    created = _create(client)
    current = client.get("/api/runs/current")
    assert current.status_code == 200
    assert current.json() == {
        "runtime_available": True,
        "run": created["run"],
    }


def test_runtime_view_exposes_complete_v3_run_provenance(client):
    _create(
        client,
        frequency_hz=2.45e9,
        bandwidth_hz=10e6,
        attack_specs=[
            {
                "attack_family": "DOS",
                "attack_subtype": "FLOODING",
                "scheduled_start_s": 0.0,
                "impact_start_s": 0.2,
                "end_s": 1.0,
                "attacker_node_id": 2,
                "target_node_ids": [1],
                "intensity": {"value": 20.0, "unit": "pps"},
                "parameters": {"packet_size_bytes": 64},
            }
        ],
    )
    metadata = client.get("/api/runtime").json()["run_metadata"]
    assert metadata["software_version"] == SOFTWARE_VERSION
    assert metadata["schema_version"] == SCHEMA_VERSION
    assert metadata["run_config"]["frequency_hz"] == 2.45e9
    assert metadata["run_config"]["bandwidth_hz"] == 10e6
    assert metadata["attack_plan"][0]["parameters"]["packet_size_bytes"] == 64
    assert metadata["profiles"]["attack_plan_id"]


def test_lifecycle_transitions_are_explicit(client):
    created = _create(client)
    assert created["run"]["state"] == "INITIALIZED"
    assert client.post("/api/runs/start").json()["state"] == "RUNNING"
    assert client.post("/api/runs/pause").json()["state"] == "PAUSED"
    assert client.post("/api/runs/resume").json()["state"] == "RUNNING"
    assert client.post("/api/runs/stop").json()["state"] == "STOPPED"
    assert client.post("/api/runs/reset").json()["state"] == "INITIALIZED"


def test_read_only_polling_does_not_advance_simulation(client):
    _create(client)
    client.post("/api/runs/start")
    before = client.get("/api/runs/status").json()["sim_time_s"]
    assert client.get("/api/runtime").json()["scope"] == "GCS_RECEIVED_RUNTIME_VIEW"
    assert client.get("/api/gcs/topology").json()["scope"] == "GCS_LOCAL_TOPOLOGY"
    client.get("/api/observations/1")
    client.get("/api/evaluation")
    after = client.get("/api/runs/status").json()["sim_time_s"]
    assert after == before


def test_debug_step_is_separate_and_advances_exactly_one_step(client):
    _create(client)
    result = client.post("/api/debug/step").json()
    assert result["status"]["sim_time_s"] == 0.2
    assert result["events_created"] > 0


def test_attack_scheduler_endpoint_validates_time_order(client):
    _create(client)
    invalid = client.post(
        "/api/attacks/schedule",
        json={
            "attack_family": "DOS",
            "attack_subtype": "FLOODING",
            "scheduled_start_s": 1,
            "impact_start_s": 0.5,
            "end_s": 2,
        },
    )
    assert invalid.status_code == 422
    valid = client.post(
        "/api/attacks/schedule",
        json={
            "attack_family": "DOS",
            "attack_subtype": "FLOODING",
            "scheduled_start_s": 0,
            "impact_start_s": 0.2,
            "end_s": 1,
            "target_node_ids": [1],
            "intensity": {"value": 80, "unit": "pps"},
        },
    )
    assert valid.status_code == 201
    assert valid.json()["attack_family"] == "DOS"

    retired = client.post(
        "/api/attacks/schedule",
        json={
            "attack_family": "DOS",
            "attack_subtype": "JAMMING",
            "scheduled_start_s": 0,
            "impact_start_s": 0.2,
            "end_s": 1,
        },
    )
    assert retired.status_code == 422


def test_probe_endpoint_returns_paired_local_observations(client):
    _create(client)
    result = client.post(
        "/api/probes", json={"first_id": 1, "second_id": 2, "sample_count": 8}
    ).json()
    assert result["first"]["probe_id"] == result["second"]["probe_id"]
    assert result["first"]["measurement"] != result["second"]["measurement"]


def test_normal_disturbance_and_rl_observation_endpoints_are_explicit_and_read_only(client):
    _create(client)
    scheduled = client.post(
        "/api/normal-disturbances/schedule",
        json={
            "disturbance_type": "NORMAL_TRAFFIC_BURST",
            "start_s": 0.2,
            "end_s": 1.0,
            "target_node_ids": [1],
            "parameters": {"source_node_id": 2, "packet_rate_pps": 20},
        },
    )
    assert scheduled.status_code == 201
    assert scheduled.json()["disturbance_type"] == "NORMAL_TRAFFIC_BURST"
    before = client.get("/api/runs/status").json()["sim_time_s"]
    observation = client.get("/api/rl/observations/1")
    assert observation.status_code == 200
    assert "recent_2s" in observation.json()
    assert client.get("/api/runs/status").json()["sim_time_s"] == before


def test_runtime_cursor_is_based_only_on_gcs_events(client):
    _create(client)
    client.post("/api/debug/step")
    first = client.get("/api/runtime?cursor=0").json()
    second = client.get(f"/api/runtime?cursor={first['next_cursor']}").json()
    assert all(event["observer_node_id"] == 0 for event in first["events"])
    assert second["events"] == []
    assert first["metrics"]["scope"] == "GCS_RECEIVED_AGGREGATE"


def test_defense_action_returns_authorization_and_execution_fields(client):
    _create(client)
    result = client.post(
        "/api/defense/actions", json={"node_id": 1, "action": "NO_CHANGE"}
    ).json()
    assert result["permission"] == "LOCAL_NODE_POLICY"
    assert result["allowed"] is True
    assert result["executed"] is True


def test_legacy_init_attack_step_and_metrics_remain_available(client):
    init = client.post("/api/init", json={"num_uavs": 4, "duration_s": 2}).json()
    assert init["status"] in {"success", "initialized"}
    queued = client.post(
        "/api/attack",
        json={"type": "FDI", "attack_src": 2, "attack_dst": 0, "malicious_cmd": "LAND"},
    ).json()
    assert queued["status"] in {"success", "queued"}
    assert client.get("/api/step").json()["status"] == "success"
    assert client.get("/api/metrics/summary").status_code == 200
    topology = client.get("/api/topology").json()
    assert topology["scope"] == "LEGACY_SIMULATOR_DEBUG_VIEW"


def test_unknown_node_observation_is_404(client):
    _create(client)
    assert client.get("/api/observations/999").status_code == 404
