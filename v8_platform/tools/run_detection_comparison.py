"""Run checked-in cases across detection modes without a web server."""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from swarm_sim import PlatformRuntime, RunConfig
from swarm_sim.simulation import DETECTION_MODE_SETTINGS
from swarm_sim.validation import DatasetValidator


CASE_FILE = Path(__file__).resolve().parents[1] / "config" / "detection_comparison_cases.json"
MANAGEMENT_TYPES = {"SECURITY_REPORT", "SECURITY_SUMMARY", "SKG_CONTROL"}
CHECKS = {"NORMAL_MULTIHOP", "EXTERNAL_ATTACK", "FLOODING", "INTERNAL_POST_HMAC",
          "SIGNED_CONTENT_GAP", "LOW_QUALITY", "REPORT_RECOVERY", "PASSIVE_BOUNDARY"}


def load_cases(path: str | Path = CASE_FILE) -> list[dict[str, Any]]:
    catalog = json.loads(Path(path).read_text(encoding="utf-8"))
    if catalog.get("suite_version") != "DETECTION_COMPARISON_V1":
        raise ValueError("UNSUPPORTED_COMPARISON_CATALOG")
    cases = []
    seen = set()
    for source in catalog["cases"]:
        case = deepcopy(source)
        identity = case["case_id"]
        if not isinstance(identity, str) or re.fullmatch(r"[A-Z][A-Z0-9_]*", identity) is None or identity in seen:
            raise ValueError("INVALID_OR_DUPLICATE_CASE_ID")
        seen.add(identity)
        if case["check"] not in CHECKS:
            raise ValueError("UNSUPPORTED_CASE_CHECK")
        case["config"] = {**deepcopy(catalog["base_config"]), **case["config"]}
        if {"seed", "detection_mode", "rff_enabled", "rff_policy_mode", "application_layer_available"} & case["config"].keys():
            raise ValueError("CASE_MUST_NOT_OVERRIDE_COMPARISON_MODE_OR_SEED")
        config = RunConfig.from_dict(case["config"])
        for action in case.get("link_actions", []):
            if (not isinstance(action.get("active"), bool)
                    or not 0 <= action["at_s"] < config.duration_s
                    or abs(action["at_s"] / config.step_s - round(action["at_s"] / config.step_s)) > 1e-9):
                raise ValueError("INVALID_LINK_ACTION")
        cases.append(case)
    if not cases:
        raise ValueError("EMPTY_COMPARISON_CATALOG")
    return cases


def _summary(runtime: PlatformRuntime, case: dict[str, Any], checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    events = runtime.events
    receives = [event for event in events if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}]
    decisions = [event["extensions"]["rff_decision"] for event in receives
                 if "rff_decision" in event["extensions"]]
    auth = [event for event in events if event["event_type"] == "AUTH_RESULT"
            and event["online_features"]["packet"]["packet_type"] is not None
            and event["online_features"]["packet"]["packet_type"] not in MANAGEMENT_TYPES]
    hmac_failures = sum(event["online_features"]["security_state"]["application_hmac_result"] == "FAIL" for event in auth)
    crypto_failures = sum(event["online_features"]["security_state"]["auth_result"] == "FAIL"
        and event["online_features"]["security_state"]["application_hmac_result"] != "FAIL" for event in auth)
    replay_rejections = sum(event["online_features"]["security_state"]["replay_check_result"]
                            not in {None, "PASS", "UNAVAILABLE"} for event in auth)
    reports = runtime.reporting.gcs_inbox
    times = [report["report_received_time_s"] for report in reports if report.get("report_received_time_s") is not None]
    executed = [message for node in runtime.nodes.values() for message in node.delivered_messages
                if message.packet_type not in MANAGEMENT_TYPES]
    scenario = {"config": case["config"], "link_actions": case.get("link_actions", [])}
    return {
        "case_id": case["case_id"], "name_zh": case["name_zh"], "purpose_zh": case["purpose_zh"],
        "mode": runtime.config.effective_detection_mode, "seed": runtime.config.seed,
        "run_id": runtime.run_id,
        "scenario_fingerprint": hashlib.sha256(json.dumps(scenario, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
        "detection_configuration": runtime.run_record()["detection_configuration"],
        "application_layer": {
            "enabled": runtime.config.application_layer_available,
            "business_auth_samples": len(auth), "hmac_failure_samples": hmac_failures,
            "crypto_failure_samples": crypto_failures,
            "replay_rejection_samples": replay_rejections,
        },
        "physical_layer": runtime.evaluation_view()["physical_layer"],
        "physical_confirmed_samples": sum(item["confirmed_identity_anomaly"] for item in decisions),
        "physical_drops": sum(item["drop"] for item in decisions),
        "delivery": {"executed_business_messages": len(executed),
                     "opaque_delivered_frames": sum(node.opaque_delivered_count for node in runtime.nodes.values())},
        "reports": {"received_count": len(reports), "first_received_time_s": min(times) if times else None,
                    "by_category": dict(Counter(report["category"] for report in reports)),
                    "records": deepcopy(reports)},
        "link_checkpoints": checkpoints,
        "capability_gap": "NO_SIGNED_BUSINESS_ANOMALY_DETECTOR" if case["check"] == "SIGNED_CONTENT_GAP" else None,
    }


def _check_external_fdi(runtime: PlatformRuntime, case_id: str, attack_ids: set[str], require: Any) -> None:
    expected = {"FDI_EXTERNAL_COPY": "CAPTURE_MODIFY_INJECT",
                "FDI_EXTERNAL_REPLACEMENT": "ON_PATH_INTERCEPTION_REPLACEMENT"}.get(case_id)
    if expected is None:
        return
    ledger = runtime.packet_accounting.causal
    captures = [item for item in ledger["captures"] if item.get("attack_id") in attack_ids]
    mutations = {item["message_id"]: item for item in ledger["mutations"]
                 if item.get("attack_id") in attack_ids and item.get("stage") == expected}
    transmissions = ledger["transmissions"]
    signatures = {item["message_id"]: item for item in ledger["signatures"]}
    require("fdi_capture_and_payload_mutation_exist", captures and mutations,
            {"captures": len(captures), "mutations": len(mutations)})

    def preserved(original, replacement, modified_id, capture_time):
        mutation = mutations.get(modified_id)
        signature = signatures.get(original["message_id"])
        return bool(mutation and signature and signature["signed"] and original["signed"]
            and original["hmac_digest"] == signature["hmac_digest"] == replacement["hmac_digest"]
            and all(original[key] == replacement[key] for key in (
                "claimed_src_id", "packet_type", "sequence_no", "created_time_s", "session_id", "key_epoch"))
            and original["payload_digest"] != replacement["payload_digest"]
            and mutation["original_payload"] != mutation["payload"] and mutation["changed_fields"]
            and mutation["hmac_recomputed"] is False
            and signature["signed_time_s"] <= capture_time <= mutation["modified_time_s"])

    if expected == "CAPTURE_MODIFY_INJECT":
        records = [item for item in ledger["derivations"] if item["copy"].get("attack_id") in attack_ids]
        proofs = []
        for item in records:
            original, copy = item["original"], item["copy"]
            proofs.append(preserved(original, copy, copy["message_id"], item["capture_time_s"])
                and original["message_id"] != copy["message_id"]
                and any(capture["message_id"] == original["message_id"]
                        and capture["capture_time_s"] == item["capture_time_s"] for capture in captures)
                and any(tx["message_id"] == original["message_id"] and tx["receiver_id"] == copy["receiver_id"]
                        and tx["actual_sender_id"] == original["sender_id"]
                        and tx["payload_digest"] == original["payload_digest"] for tx in transmissions)
                and any(tx["message_id"] == copy["message_id"] and tx.get("attack_id") in attack_ids
                        and tx["actual_sender_id"] == item["attacker_id"] and tx["receiver_id"] == copy["receiver_id"]
                        and tx["payload_digest"] == copy["payload_digest"] and tx["hmac_digest"] == copy["hmac_digest"]
                        and tx["sent_time_s"] >= item["modified_time_s"] for tx in transmissions))
        require("fdi_copy_preserves_auth_and_original_continues", records and all(proofs), len(records))
    else:
        emissions = {item["emission_id"]: item for item in transmissions}
        records = [item for item in ledger["interceptions"] if item.get("attack_id") in attack_ids]
        proofs = []
        for item in records:
            original = item["original_frame"]
            replacement = item.get("replacement_frame")
            original_tx = emissions.get(item["original_emission_id"])
            replacement_tx = emissions.get(item.get("replacement_emission_id"))
            target_tx = [tx for tx in transmissions if tx["message_id"] == item["message_id"]
                         and tx["receiver_id"] == item["target_id"]]
            proofs.append(bool(replacement and original_tx and replacement_tx
                and preserved(original, replacement, item["message_id"], item["capture_time_s"])
                and item["original_target_delivery_suppressed"] is True
                and original_tx["receiver_id"] == item["attacker_id"]
                and original_tx["payload_digest"] == original["payload_digest"]
                and original_tx["hmac_digest"] == original["hmac_digest"]
                and replacement_tx["actual_sender_id"] == item["attacker_id"]
                and replacement_tx["payload_digest"] == replacement["payload_digest"]
                and replacement_tx["hmac_digest"] == replacement["hmac_digest"]
                and replacement_tx.get("attack_id") in attack_ids
                and replacement_tx["sent_time_s"] >= mutations[item["message_id"]]["modified_time_s"]
                and any(capture["frame_emission_id"] == item["original_emission_id"] for capture in captures)
                and len(target_tx) == 1 and target_tx[0]["emission_id"] == item["replacement_emission_id"]))
        require("fdi_replacement_preserves_auth_and_suppresses_original", records and all(proofs), len(records))


def _check_case(runtime: PlatformRuntime, case: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    checks = []

    def require(name: str, condition: Any, evidence: Any = None) -> None:
        checks.append({"name": name, "passed": bool(condition), "evidence": evidence})

    events = runtime.events
    rx = [event for event in events if event["event_type"] in {"RX_SUCCESS", "RX_FAILURE"}]
    require("radio_path_executed", rx and any(event["event_type"] == "TX" for event in events), len(rx))
    physical = runtime.config.rff_enabled
    application = runtime.config.application_layer_available
    require("business_visibility_respected", application or (
        summary["application_layer"]["business_auth_samples"] == 0
        and summary["delivery"]["executed_business_messages"] == 0))
    require("disabled_rff_has_no_decisions", physical or not any("rff_decision" in event["extensions"] for event in rx))
    labels = runtime.attack_scheduler.labels()
    kind = case["check"]
    if kind in {"EXTERNAL_ATTACK", "FLOODING", "REPORT_RECOVERY"}:
        attack_ids = {label["attack_id"] for label in labels}
        targets = {node for label in labels for node in label["target_node_ids"]}
        transmissions = runtime.packet_accounting.causal["transmissions"]
        emissions = {item["emission_id"] for item in transmissions
                     if item.get("attack_id") in attack_ids and item["actual_sender_id"] < 0 and item["receiver_id"] in targets}
        owned = [event for event in rx if event["extensions"].get("air_emission_ref") in emissions]
        require("external_attack_reached_configured_target", owned, len(owned))
        if physical:
            eligible = [event for event in owned if event["event_type"] == "RX_SUCCESS"
                        and event["online_features"]["phy"]["rff_observation"]["extraction_status"] == "AVAILABLE"]
            require("qualified_external_samples_exist", eligible, len(eligible))
            require("physical_ingress_rejects_external_samples", eligible and all(
                event["extensions"]["rff_decision"]["drop"] for event in eligible))
        if application and not physical:
            receive_ids = {event["event_id"] for event in owned}
            rejected_auth = set()
            for event in events:
                if event["event_type"] != "AUTH_RESULT" or event["observer_node_id"] not in targets:
                    continue
                extension = event["extensions"]
                if (extension.get("air_emission_ref") not in emissions
                        or not receive_ids.intersection(extension.get("source_event_ids", []))):
                    continue
                state = event["online_features"]["security_state"]
                if (state["auth_result"] == "FAIL" or state["application_hmac_result"] == "FAIL"
                        or state["replay_check_result"] not in {None, "PASS", "UNAVAILABLE"}):
                    rejected_auth.add(event["event_id"])
            result_ids = {event["extensions"]["model_result"]["result_id"] for event in events
                          if event["event_type"] == "MODEL_RESULT"
                          and rejected_auth.intersection(event["extensions"].get("model_result", {}).get("evidence_event_ids", []))}
            drops = [event for event in events if event["event_type"] == "DEFENSE_RESULT"
                     and event["extensions"].get("decision_audit", {}).get("model_result_id") in result_ids
                     and event["extensions"]["defense_result"].get("executed") is True
                     and event["extensions"]["defense_result"]["request"]["action"] == "DROP_PACKET"]
            require("application_auth_or_replay_rejects_attack", drops,
                    {"attack_rejection_auth_ids": sorted(rejected_auth),
                     "attack_drop_event_ids": [event["event_id"] for event in drops]})
        _check_external_fdi(runtime, case["case_id"], attack_ids, require)
    if kind == "NORMAL_MULTIHOP":
        delivered = summary["delivery"]["executed_business_messages"] if application else summary["delivery"]["opaque_delivered_frames"]
        require("three_normal_messages_reach_destination", delivered == 3, delivered)
        if physical:
            business_rx = [event for event in rx if event["message_id"] in runtime.packet_accounting.messages
                           and runtime.packet_accounting.messages[event["message_id"]].get("business")]
            require("current_hop_id_matches_at_both_receivers", {event["observer_node_id"] for event in business_rx} == {0, 1}
                and all(event["online_features"]["security_state"]["rff_identity_result"] == "MATCH" for event in business_rx))
    elif kind == "FLOODING":
        actions = runtime.packet_accounting.causal["actions"]
        if application:
            require("total_arrival_rate_alarm_executed", any(item["category"] == "DOS" for item in actions))
        if physical:
            require("strict_whitelist_entered", any(event["extensions"].get("rff_decision", {}).get("policy_state")
                == "RFF_STRICT_WHITELIST" for event in rx))
            require("strict_whitelist_recovers_without_new_attack", runtime.nodes[1].rff_policy_state == "NORMAL")
    elif kind == "INTERNAL_POST_HMAC":
        require("internal_payload_was_actually_modified", runtime.packet_accounting.causal["mutations"])
        if physical:
            require("legal_radio_not_falsely_claimed_detected", summary["physical_layer"]["by_family"]["FDI"]["detection_rate"] is None
                    and summary["physical_confirmed_samples"] == 0)
        if application:
            require("post_hmac_mutation_rejected_by_auth", summary["application_layer"]["hmac_failure_samples"] > 0)
    elif kind == "SIGNED_CONTENT_GAP":
        require("normal_auth_does_not_detect_signed_bad_content", summary["application_layer"]["hmac_failure_samples"] == 0)
        require("matching_radio_does_not_detect_signed_bad_content", summary["physical_confirmed_samples"] == 0)
        if application:
            require("current_business_rule_gap_is_observable", runtime.nodes[1].telemetry_by_source.get(2, {}).get("altitude_m") == 5000)
    elif kind == "LOW_QUALITY":
        require("normal_attenuation_reduces_observed_sinr", any(event["online_features"]["phy"].get("sinr_db", 100) < 20 for event in rx))
        if physical:
            low = [event for event in rx if event["online_features"]["phy"]["rff_observation"]["extraction_status"] == "LOW_QUALITY"]
            require("low_quality_observations_exist", low, len(low))
            require("low_quality_not_confirmed_as_attack", all(not event["extensions"]["rff_decision"]["confirmed_identity_anomaly"] for event in low))
    elif kind == "REPORT_RECOVERY":
        checkpoints = summary["link_checkpoints"]
        require("receiver_cached_before_link_recovery", checkpoints and checkpoints[0]["local_cached_reports"] > 0)
        require("center_had_no_teleported_reports", checkpoints and checkpoints[0]["gcs_reports"] == 0)
        source_reports = [report for report in runtime.reporting.gcs_inbox if report["source_node_id"] == case["report_source_node_id"]]
        require("source_reports_arrive_only_after_recovery", source_reports and all(
            report["report_received_time_s"] >= checkpoints[0]["sim_time_s"] for report in source_reports))
    elif kind == "PASSIVE_BOUNDARY":
        require("passive_capture_actually_happened", labels and labels[0]["outcome"].get("captured_count", 0) > 0)
        require("passive_listener_emitted_no_attack_frames", not any(
            item["actual_sender_id"] < 0 for item in runtime.packet_accounting.causal["transmissions"]))
        require("passive_listener_not_claimed_rff_detection", summary["physical_confirmed_samples"] == 0)
    return {"passed": all(check["passed"] for check in checks), "items": checks}


def run_case(case: dict[str, Any], mode: str, seed: int, *, dataset_dir: str | Path | None = None) -> dict[str, Any]:
    if mode not in DETECTION_MODE_SETTINGS or not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ValueError("INVALID_COMPARISON_MODE_OR_SEED")
    config = RunConfig.from_dict({**deepcopy(case["config"]), "detection_mode": mode, "seed": seed})
    runtime = PlatformRuntime(config)
    checkpoints = []
    try:
        actions = sorted(deepcopy(case.get("link_actions", [])), key=lambda action: action["at_s"])
        runtime.start()
        while runtime.context.clock.now_s < config.duration_s - 1e-9:
            while actions and actions[0]["at_s"] <= runtime.context.clock.now_s + 1e-9:
                action = actions.pop(0)
                if action["active"]:
                    checkpoints.append({"sim_time_s": runtime.context.clock.now_s,
                        "local_cached_reports": len(runtime.nodes[case["report_source_node_id"]].local_security_cache),
                        "gcs_reports": len(runtime.reporting.gcs_inbox)})
                runtime.set_bidirectional_link_active(action["first_id"], action["second_id"], action["active"])
            runtime.step()
        result = _summary(runtime, case, checkpoints)
        result["checks"] = _check_case(runtime, case, result)
        result["schema_validation"] = {"valid": None, "status": "NOT_REQUESTED"}
        if dataset_dir is not None:
            runtime.export_dataset(dataset_dir)
            result["schema_validation"] = DatasetValidator().validate(dataset_dir).to_dict()
        return result
    finally:
        runtime.close()


def run_comparison(output_dir: str | Path, *, case_ids: list[str] | None = None,
                   modes: list[str] | None = None, seeds: list[int] | None = None,
                   export_datasets: bool = True) -> dict[str, Any]:
    cases = load_cases()
    wanted = set(case_ids) if case_ids is not None else {case["case_id"] for case in cases}
    modes = list(DETECTION_MODE_SETTINGS) if modes is None else list(modes)
    seeds = [42] if seeds is None else list(seeds)
    if not wanted or wanted - {case["case_id"] for case in cases}:
        raise ValueError("UNKNOWN_OR_EMPTY_CASE_SELECTION")
    if not modes or any(mode not in DETECTION_MODE_SETTINGS for mode in modes) or len(set(modes)) != len(modes):
        raise ValueError("INVALID_MODE_SELECTION")
    if not seeds or any(not isinstance(seed, int) or isinstance(seed, bool) or seed < 0 for seed in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("INVALID_SEED_SELECTION")
    root = Path(output_dir)
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("OUTPUT_DIRECTORY_NOT_EMPTY")
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases:
        if case["case_id"] not in wanted:
            continue
        for seed in seeds:
            for mode in modes:
                name = f"{case['case_id']}-{mode}-seed-{seed}"
                run_dir = root / name
                row = run_case(case, mode, seed, dataset_dir=run_dir if export_datasets else None)
                run_dir.mkdir(parents=True, exist_ok=True)
                row["result_path"] = f"{name}/result.json"
                (run_dir / "result.json").write_text(json.dumps(row, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                rows.append(row)
    summary = {
        "suite_version": "DETECTION_COMPARISON_V1", "run_count": len(rows),
        "verification_scope": "MECHANISM_AND_DATASET" if export_datasets else "MECHANISM_ONLY",
        "all_passed": all(row["checks"]["passed"] and (row["schema_validation"]["valid"] is True or not export_datasets) for row in rows),
        "limitations": ["SIMULATED_FEATURES_NOT_REAL_IQ", "NO_SIGNED_BUSINESS_ANOMALY_DETECTOR",
                        "JAMMING_NOT_SUPPORTED_BY_CURRENT_ATTACK_ENUM",
                        "SAME_INPUTS_AND_SEED_NOT_IDENTICAL_AIR_EVENTS_AFTER_DEFENSE"],
        "runs": rows,
    }
    (root / "comparison_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    columns = ["case_id", "mode", "seed", "checks_passed", "schema_valid", "crypto_failures", "hmac_failures", "replay_rejections",
               "rff_confirmed", "rff_drops", "center_reports", "capability_gap"]
    with (root / "comparison.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(zip(columns, [row["case_id"], row["mode"], row["seed"], row["checks"]["passed"],
                row["schema_validation"]["valid"], row["application_layer"]["crypto_failure_samples"], row["application_layer"]["hmac_failure_samples"],
                row["application_layer"]["replay_rejection_samples"], row["physical_confirmed_samples"],
                row["physical_drops"], row["reports"]["received_count"], row["capability_gap"]])))
    lines = ["# 检测模式对比结果", "", f"实验数：{len(rows)}；全部检查通过：{summary['all_passed']}。",
        "检查通过表示实际机制符合该用例的验证目标，不表示所有攻击都被检出。", "",
        "| 用例 | 模式 | 种子 | 检查 | 封装认证失败 | HMAC失败 | 重放拒绝 | 射频异常 | 射频丢弃 | 中心报告 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        app = row["application_layer"]
        lines.append(f"| {row['name_zh']} | {row['mode']} | {row['seed']} | {row['checks']['passed']} | "
            f"{app['crypto_failure_samples']} | {app['hmac_failure_samples']} | {app['replay_rejection_samples']} | {row['physical_confirmed_samples']} | "
            f"{row['physical_drops']} | {row['reports']['received_count']} |")
    lines += ["", "## 边界与阅读说明", "",
        "- 当前缺少对正常认证后的异常业务内容进行独立识别的规则；对应边界用例检查通过不代表检测成功。",
        "- 当前攻击枚举只支持 Flooding，不支持独立 Jamming 用例；不能声称射频白名单能消除干扰。",
        "- 被动窃听、合法硬件内部攻击及无合格观测的物理检测率为不可评估，不填成成功率。",
        "- 物理模式的透明到达不等同于业务执行成功；管理协议认证与未知业务解析分开处理。",
        "- 各模式使用同一用例输入和种子；防御改变报告与后续流量，因此不保证每次空口观测完全相同。",
        "- HMAC、重放和射频计数是各层实际事件数，不是可相加的攻击数或检测率。",
        "- 每次运行的 result.json 保存检查依据、实际中心报告和物理评估分母；未导出数据时 schema_validation.valid 为 null。"]
    (root / "comparison_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--mode", action="append", choices=list(DETECTION_MODE_SETTINGS), dest="modes")
    parser.add_argument("--seed", action="append", type=int, dest="seeds")
    parser.add_argument("--no-export", action="store_true")
    args = parser.parse_args(argv)
    summary = run_comparison(args.output_dir, case_ids=args.case_ids, modes=args.modes,
                             seeds=args.seeds, export_datasets=not args.no_export)
    for row in summary["runs"]:
        print(f"{row['case_id']} {row['mode']} seed={row['seed']} checks={row['checks']['passed']}")
    print(f"runs={summary['run_count']} all_passed={summary['all_passed']} output={args.output_dir}")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
