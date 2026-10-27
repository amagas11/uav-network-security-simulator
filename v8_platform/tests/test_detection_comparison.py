from copy import deepcopy
import json

import pytest

from tools.run_detection_comparison import load_cases, run_case, run_comparison, main, _summary, _check_case
from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.validation import DatasetValidator


CASE_IDS = ["NORMAL_MULTIHOP", "SPOOF_EXTERNAL", "FDI_EXTERNAL_COPY",
            "FDI_EXTERNAL_REPLACEMENT", "REPLAY_EXTERNAL", "FLOODING_EXTERNAL",
            "FDI_INTERNAL_POST_HMAC", "SIGNED_ABNORMAL_TELEMETRY", "LOW_SNR",
            "REPORT_LINK_RECOVERY", "PASSIVE_EAVESDROPPING"]
MODES = ["APPLICATION_ONLY", "PHYSICAL_ONLY", "COMBINED"]


def test_case_catalog_is_complete_and_contains_no_mode_specific_attack_inputs():
    cases = load_cases()
    assert [case["case_id"] for case in cases] == CASE_IDS
    for case in cases:
        assert case["name_zh"] and case["purpose_zh"] and case["check"]
        assert not {"seed", "detection_mode", "rff_enabled", "rff_policy_mode",
                    "application_layer_available"} & case["config"].keys()


@pytest.mark.parametrize("case_id", CASE_IDS)
@pytest.mark.parametrize("mode", MODES)
def test_fixed_case_passes_its_mechanism_and_boundary_checks(case_id, mode):
    case = next(case for case in load_cases() if case["case_id"] == case_id)
    original = deepcopy(case)
    result = run_case(case, mode, 42)
    assert result["checks"]["passed"], result["checks"]
    assert case == original
    assert result["mode"] == mode and result["seed"] == 42
    assert result["application_layer"]["enabled"] is (mode != "PHYSICAL_ONLY")
    if mode == "PHYSICAL_ONLY":
        assert result["application_layer"]["business_auth_samples"] == 0
        assert result["delivery"]["executed_business_messages"] == 0
    if mode == "APPLICATION_ONLY":
        assert result["physical_layer"]["enabled"] is False
        assert result["physical_drops"] == 0
    if case_id == "SIGNED_ABNORMAL_TELEMETRY":
        assert result["capability_gap"] == "NO_SIGNED_BUSINESS_ANOMALY_DETECTOR"


def test_missing_attack_is_not_reported_as_a_passed_attack_demo():
    case = next(case for case in load_cases() if case["case_id"] == "SPOOF_EXTERNAL")
    case["config"]["attack_specs"] = []
    result = run_case(case, "PHYSICAL_ONLY", 42)
    assert result["checks"]["passed"] is False


def test_early_crypto_rejection_is_counted_without_calling_it_an_hmac_failure():
    case = next(case for case in load_cases() if case["case_id"] == "SPOOF_EXTERNAL")
    result = run_case(case, "APPLICATION_ONLY", 42)
    assert result["application_layer"]["crypto_failure_samples"] > 0
    assert result["application_layer"]["hmac_failure_samples"] == 0
    assert result["checks"]["passed"]


def test_unrelated_auth_failure_cannot_prove_attack_rejection():
    case = next(case for case in load_cases() if case["case_id"] == "SPOOF_EXTERNAL")
    runtime = PlatformRuntime(RunConfig.from_dict(dict(case["config"], detection_mode="APPLICATION_ONLY")))
    try:
        runtime.run_to_completion()
        attack_messages = {item["message_id"] for item in runtime.packet_accounting.causal["transmissions"]
                           if item.get("attack_id") and item["actual_sender_id"] == -1}
        auth = [event for event in runtime.events if event["event_type"] == "AUTH_RESULT"
                and event["message_id"] in attack_messages]
        assert auth
        unrelated = deepcopy(auth[0])
        unrelated["event_id"] = "unrelated-auth-failure"
        unrelated["message_id"] = "unrelated-message"
        unrelated["extensions"] = {}
        for event in auth:
            event["online_features"]["security_state"].update(auth_result="PASS",
                application_hmac_result="PASS", replay_check_result="PASS")
        runtime.events.append(unrelated)
        summary = _summary(runtime, case, [])
        assert summary["application_layer"]["crypto_failure_samples"] > 0
        assert not _check_case(runtime, case, summary)["passed"]
    finally:
        runtime.close()


@pytest.mark.parametrize("case_id", ["FDI_EXTERNAL_COPY", "FDI_EXTERNAL_REPLACEMENT"])
def test_external_transmission_alone_does_not_prove_capture_modify_mechanism(case_id):
    case = next(case for case in load_cases() if case["case_id"] == case_id)
    runtime = PlatformRuntime(RunConfig.from_dict(dict(case["config"], detection_mode="PHYSICAL_ONLY")))
    try:
        runtime.run_to_completion()
        for name in ("captures", "mutations", "derivations", "interceptions"):
            runtime.packet_accounting.causal[name].clear()
        assert not _check_case(runtime, case, _summary(runtime, case, []))["passed"]
    finally:
        runtime.close()


@pytest.mark.parametrize("case_id", ["FDI_EXTERNAL_COPY", "FDI_EXTERNAL_REPLACEMENT"])
def test_fdi_modification_must_be_present_in_the_actual_transmitted_frame(case_id):
    case = next(case for case in load_cases() if case["case_id"] == case_id)
    runtime = PlatformRuntime(RunConfig.from_dict(dict(case["config"], detection_mode="PHYSICAL_ONLY")))
    try:
        runtime.run_to_completion()
        for tx in runtime.packet_accounting.causal["transmissions"]:
            if tx["actual_sender_id"] == -1:
                tx["payload_digest"] = "unmodified-or-unrelated-frame"
        assert not _check_case(runtime, case, _summary(runtime, case, []))["passed"]
    finally:
        runtime.close()


def test_delayed_authentication_retains_exact_receive_and_emission_references():
    runtime = PlatformRuntime(RunConfig(duration_s=1.4, auto_traffic=False,
        detection_mode="APPLICATION_ONLY", tx_service_per_step=8, rx_service_per_step=1))
    try:
        for sender in (2, 3, 2):
            runtime.queue_message(sender, 1, "TELEMETRY", {"altitude_m": 100})
        runtime.run_to_completion()
        lookup = {event["event_id"]: event for event in runtime.events}
        auth = [event for event in runtime.events if event["event_type"] == "AUTH_RESULT"
                and event["online_features"]["packet"]["packet_type"] == "TELEMETRY"]
        assert len(auth) == 3
        for event in auth:
            receive = lookup[event["extensions"]["source_event_ids"][0]]
            assert receive["event_type"] == "RX_SUCCESS"
            assert receive["message_id"] == event["message_id"]
            assert receive["observer_node_id"] == event["observer_node_id"]
            emission = event["extensions"]["air_emission_ref"]
            assert emission == receive["extensions"]["air_emission_ref"]
            assert lookup[emission]["event_type"] == "TX"
    finally:
        runtime.close()


@pytest.mark.parametrize("case_id", ["FDI_EXTERNAL_COPY", "FDI_EXTERNAL_REPLACEMENT"])
@pytest.mark.parametrize("mode", MODES)
def test_both_external_fdi_mechanisms_export_valid_datasets(tmp_path, case_id, mode):
    case = next(case for case in load_cases() if case["case_id"] == case_id)
    result = run_case(case, mode, 42, dataset_dir=tmp_path)
    assert result["schema_validation"]["valid"], result["schema_validation"]["errors"]


def test_legacy_single_stage_schema_remains_accepted(tmp_path):
    case = load_cases()[0]
    run_case(case, "APPLICATION_ONLY", 42, dataset_dir=tmp_path)
    path = tmp_path / "schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    schema["objects"]["AttackTruth"]["fields"]["injection_stage"]["enum"] = ["POST_HMAC_PRE_TRANSMISSION"]
    path.write_text(json.dumps(schema), encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert report.valid, report.errors


def test_unknown_fdi_stage_still_fails_validation(tmp_path):
    case = next(case for case in load_cases() if case["case_id"] == "FDI_EXTERNAL_COPY")
    run_case(case, "PHYSICAL_ONLY", 42, dataset_dir=tmp_path)
    path = tmp_path / "labels.jsonl"
    labels = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    labels[0]["truth"]["injection_stage"] = "UNSUPPORTED_FDI_STAGE"
    path.write_text("".join(json.dumps(label) + "\n" for label in labels), encoding="utf-8")
    report = DatasetValidator().validate(tmp_path)
    assert not report.valid
    assert any("injection_stage" in error for error in report.errors)


def test_comparison_exports_valid_datasets_and_human_readable_report(tmp_path):
    summary = run_comparison(tmp_path, case_ids=["NORMAL_MULTIHOP", "REPLAY_EXTERNAL"], seeds=[42])
    assert summary["all_passed"] and summary["run_count"] == 6
    assert (tmp_path / "comparison_summary.json").is_file()
    assert (tmp_path / "comparison.csv").is_file()
    assert (tmp_path / "comparison_report.md").is_file()
    rows = summary["runs"]
    assert len({row["scenario_fingerprint"] for row in rows if row["case_id"] == "REPLAY_EXTERNAL"}) == 1
    assert all(row["schema_validation"]["valid"] for row in rows)
    assert all((tmp_path / row["result_path"]).is_file() for row in rows)
    assert len(list(tmp_path.glob("*/events.jsonl"))) == 6
    with pytest.raises(ValueError, match="OUTPUT_DIRECTORY_NOT_EMPTY"):
        run_comparison(tmp_path, case_ids=["NORMAL_MULTIHOP"])


def test_report_link_recovery_has_receiver_cache_and_delayed_center_delivery():
    case = next(case for case in load_cases() if case["case_id"] == "REPORT_LINK_RECOVERY")
    result = run_case(case, "PHYSICAL_ONLY", 42)
    checkpoint = result["link_checkpoints"][0]
    assert checkpoint["local_cached_reports"] > 0
    assert checkpoint["gcs_reports"] == 0
    assert result["reports"]["received_count"] > 0
    assert result["reports"]["first_received_time_s"] >= checkpoint["sim_time_s"]


@pytest.mark.parametrize("options", [
    {"case_ids": ["UNKNOWN"]}, {"modes": ["UNKNOWN"]}, {"seeds": []}, {"seeds": [True]},
])
def test_invalid_comparison_selection_fails_before_creating_output(tmp_path, options):
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        run_comparison(output, **options)
    assert not output.exists()


def test_cli_runs_without_web_server_or_dataset_export(tmp_path, capsys):
    result = main(["--output-dir", str(tmp_path), "--case", "NORMAL_MULTIHOP",
                   "--mode", "PHYSICAL_ONLY", "--seed", "42", "--no-export"])
    assert result == 0
    summary = json.loads((tmp_path / "comparison_summary.json").read_text(encoding="utf-8"))
    assert summary["run_count"] == 1 and summary["all_passed"]
    assert "NORMAL_MULTIHOP" in capsys.readouterr().out
