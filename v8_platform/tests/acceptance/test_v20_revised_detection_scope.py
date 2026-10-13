"""Explicit detector scope, unchanged arrivals/base security, compatible defaults."""
from copy import deepcopy
import pytest
from app.app import CreateRunRequest
from swarm_sim.runtime import PlatformRuntime
from swarm_sim.security import DeterministicRuleEngine
from tests.acceptance.test_v20_fdi_copies import copied_configuration


@pytest.mark.parametrize("duration,count,end", [(3.2,10,2.4),(5,19,3.8),(10,44,7.4),(20,94,15),(30,144,22.4)])
def test_single_fdi_does_not_invoke_flooding_but_preserves_real_copies(duration,count,end):
    config = copied_configuration(duration,count,end)
    config.flooding_packet_rate_threshold_pps = 12
    config.flooding_detection_enabled = False
    runtime = PlatformRuntime(config)
    runtime.run_to_completion()
    accounting = runtime.packet_accounting.snapshot(runtime.run_id)
    evidence = accounting["causal_evidence"]
    copies = {row["copy"]["message_id"] for row in evidence["derivations"]}
    assert copies and len(copies) == len(evidence["mutations"])
    assert accounting["business"]["generated_business_count"] == count
    assert accounting["business"]["origin_business_sent_count"] == count
    assert accounting["attacks"][0]["counts"]["executed_drop_count"] == len(copies)
    assert all(report["category"] != "DOS" for report in runtime.reporting.gcs_inbox)
    assert not any(row["result"]["request"]["action"] == "INCREASE_MONITORING" for row in evidence["actions"])
    target = [row for row in evidence["transmissions"] if row["receiver_id"] == 1 and row["decoded"]]
    assert len(target) == count + len(copies)
    assert len({row["emission_id"] for row in target}) == len(target)
    assert {row["message_id"] for row in evidence["security_observations"] if row["observer_node_id"] == 1 and row["security_state"].get("application_hmac_failure_reason") == "HMAC_MISMATCH"} == copies
    meta = runtime.run_record()
    assert meta["run_config"]["flooding_detection_enabled"] is False
    assert meta["detection_configuration"]["application_hmac"]["enabled"] is True
    assert meta["detection_configuration"]["flooding"]["enabled"] is False
    rates = runtime.receiver_rate_observations.snapshot()
    assert rates["nodes"] and rates["nodes"][0]["peak_window_rate_pps"] >= 12
    evaluation = runtime.evaluation_view()
    assert evaluation["detector_applicability"]["DOS"]["applicable"] is False


def test_default_api_and_legacy_comprehensive_remain_enabled():
    assert CreateRunRequest().flooding_detection_enabled is True
    config = copied_configuration()
    config.flooding_packet_rate_threshold_pps = 12
    runtime = PlatformRuntime(config)
    runtime.run_to_completion()
    assert any(report["category"] == "DOS" for report in runtime.reporting.gcs_inbox)
    assert runtime.evaluation_view()["detector_applicability"]["DOS"]["applicable"] is True


def test_detector_switch_does_not_change_arrival_statistics():
    enabled = DeterministicRuleEngine(flooding_threshold_pps=8, flooding_detection_enabled=True)
    disabled = DeterministicRuleEngine(flooding_threshold_pps=8, flooding_detection_enabled=False)
    alarms = []
    for index in range(12):
        event, observed = enabled.record_arrival(index / 100)
        silent, observed_disabled = disabled.record_arrival(index / 100)
        assert observed == observed_disabled
        assert silent is None
        if event: alarms.append(event)
    assert len(alarms) == 1


@pytest.mark.parametrize("value", ["false", 0, 1, None])
def test_detection_switch_rejects_ambiguous_api_values(value):
    with pytest.raises(ValueError):
        CreateRunRequest(flooding_detection_enabled=value)
