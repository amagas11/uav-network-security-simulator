"""Schema-driven dataset validation over untrusted JSONL input."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from copy import deepcopy
from datetime import datetime
import json
import math
from pathlib import Path
import re
from typing import Any

from .attacks import ATTACK_FAMILIES, ATTACK_SUBTYPES
from .dataset import schema_v1
from .domain import EventType, NodeRole
from .events import find_forbidden_online_fields, find_label_proxies
from .leakage import DatasetLeakageAudit
from .simulation import (
    RunConfig,
    SCHEMA_VERSION,
    plan_collection_id,
    runtime_semantic_fingerprint,
)


@dataclass(slots=True)
class ValidationReport:
    valid: bool
    errors: list[str]
    warnings: list[str]
    counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_jsonl(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        errors.append(f"missing file: {path.name}")
        return rows
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        errors.append(f"{path.name}: cannot read UTF-8 JSONL ({exc})")
        return rows
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError("record must be an object")
            rows.append(value)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            errors.append(f"{path.name}:{line_number}: invalid JSON object ({exc})")
    return rows


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _matches_type(value: Any, expected: str) -> bool:
    alternatives = expected.split("|")
    if len(alternatives) > 1:
        return any(_matches_type(value, item) for item in alternatives)
    if expected.startswith("array<") and expected.endswith(">"):
        if not isinstance(value, list):
            return False
        item_type = expected[6:-1]
        return all(_matches_type(item, item_type) for item in value)
    checks = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": _is_number,
        "boolean": lambda item: isinstance(item, bool),
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "null": lambda item: item is None,
    }
    predicate = checks.get(expected)
    return bool(predicate and predicate(value))


def _validate_object(
    value: Any,
    object_name: str,
    path: str,
    contract: dict[str, Any],
    errors: list[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path}: must be an object")
        return False
    descriptors = contract.get("objects", {}).get(object_name, {}).get("fields", {})
    if not descriptors:
        errors.append(f"schema contract is missing object definition {object_name}")
        return False
    valid = True
    additional_properties = bool(
        contract.get("objects", {}).get(object_name, {}).get(
            "additional_properties", False
        )
    )
    if not additional_properties:
        for unknown in sorted(set(value) - set(descriptors)):
            errors.append(f"{path}.{unknown}: unknown frozen-contract field")
            valid = False
    for name, descriptor in descriptors.items():
        field_path = f"{path}.{name}"
        if name not in value:
            if descriptor.get("required", False):
                errors.append(f"{field_path}: missing required field")
                valid = False
            continue
        item = value[name]
        if item is None:
            if not descriptor.get("nullable", False):
                errors.append(f"{field_path}: field is not nullable")
                valid = False
            continue
        expected = str(descriptor.get("type", ""))
        if not _matches_type(item, expected):
            errors.append(f"{field_path}: must have type {expected}")
            valid = False
            continue
        enumeration = descriptor.get("enum")
        if enumeration is not None and item not in enumeration:
            errors.append(f"{field_path}: unknown enum value {item!r}")
            valid = False
        if _is_number(item):
            if not math.isfinite(float(item)):
                errors.append(f"{field_path}: must be a finite number")
                valid = False
                continue
            if "minimum" in descriptor and item < descriptor["minimum"]:
                errors.append(f"{field_path}: must be >= {descriptor['minimum']}")
                valid = False
            if "maximum" in descriptor and item > descriptor["maximum"]:
                errors.append(f"{field_path}: must be <= {descriptor['maximum']}")
                valid = False
            if "exclusiveMinimum" in descriptor and item <= descriptor["exclusiveMinimum"]:
                errors.append(f"{field_path}: must be > {descriptor['exclusiveMinimum']}")
                valid = False
            if "exclusiveMaximum" in descriptor and item >= descriptor["exclusiveMaximum"]:
                errors.append(f"{field_path}: must be < {descriptor['exclusiveMaximum']}")
                valid = False
        pattern = descriptor.get("pattern")
        if pattern and isinstance(item, str) and re.fullmatch(pattern, item) is None:
            errors.append(f"{field_path}: does not match required pattern")
            valid = False
        object_ref = descriptor.get("object_ref")
        if object_ref and isinstance(item, dict):
            valid = _validate_object(item, object_ref, field_path, contract, errors) and valid
        item_ref = descriptor.get("item_ref")
        if item_ref and isinstance(item, list):
            for index, child in enumerate(item):
                valid = _validate_object(
                    child, item_ref, f"{field_path}[{index}]", contract, errors
                ) and valid
    if object_name == "RffObservation":
        vector = value.get("feature_vector")
        if isinstance(vector, list):
            expected_size = 0 if value.get("extraction_status") == "UNAVAILABLE" else 8
            if len(vector) != expected_size:
                errors.append(f"{path}.feature_vector: expected {expected_size} features")
                valid = False
            if any(not _is_number(item) or not math.isfinite(item) for item in vector):
                errors.append(f"{path}.feature_vector: features must be finite numbers")
                valid = False
    return valid


def _pre_rff_schema(contract: dict[str, Any], *, include_rate_filter: bool = True) -> dict[str, Any]:
    """Accept the exact historical contract, without relaxing other fields."""
    legacy = deepcopy(contract)
    objects = legacy["objects"]
    objects.pop("RffObservation", None)
    objects["runs"]["fields"].pop("rff_simulation", None)
    for name in list(objects["RunConfig"]["fields"]):
        if name.startswith("rff_"):
            objects["RunConfig"]["fields"].pop(name)
    objects["online_features.packet"]["fields"].pop("claimed_link_sender_id", None)
    objects["online_features.phy"]["fields"].pop("rff_observation", None)
    for name in ("rff_predicted_device_id", "rff_claimed_link_sender_id",
                 "rff_distance", "rff_threshold", "rff_reason"):
        objects["online_features.security_state"]["fields"].pop(name, None)
    if not include_rate_filter:
        objects["runs"]["fields"].pop("detection_configuration", None)
        objects["RunConfig"]["fields"].pop("flooding_detection_enabled", None)
    return legacy


def _named_references(value: Any, names: set[str]) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []

    def walk(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{path}.{key}" if path else key
                if key in names:
                    found.append((child_path, child))
                walk(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(value, "")
    return found


class DatasetValidator:
    """Validate a complete export and report ordinary corruption as errors."""

    ONLINE_GROUPS = {
        "packet",
        "phy",
        "traffic",
        "node_state",
        "topology",
        "security_state",
        "resource_state",
    }

    def validate(self, dataset_dir: str | Path) -> ValidationReport:
        root = Path(dataset_dir)
        errors: list[str] = []
        warnings: list[str] = []
        contract = schema_v1()
        schema_path = root / "schema.json"
        if not schema_path.exists():
            errors.append("missing file: schema.json")
        else:
            try:
                supplied = json.loads(schema_path.read_text(encoding="utf-8"))
                if not isinstance(supplied, dict):
                    raise TypeError("schema root must be an object")
                if supplied.get("schema_version") != SCHEMA_VERSION:
                    errors.append("schema.json has unsupported schema_version")
                if supplied not in (
                    contract, _pre_rff_schema(contract),
                    _pre_rff_schema(contract, include_rate_filter=False),
                ):
                    errors.append("schema.json does not match the frozen schema contract")
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
                errors.append(f"schema.json is invalid: {exc}")

        runs = _read_jsonl(root / "runs.jsonl", errors)
        events = _read_jsonl(root / "events.jsonl", errors)
        labels = _read_jsonl(root / "labels.jsonl", errors)
        rf_manifest = _read_jsonl(root / "rf_manifest.jsonl", errors)
        if not (root / "rf_samples").is_dir():
            errors.append("missing directory: rf_samples")

        run_ids: set[str] = set()
        run_by_id: dict[str, dict[str, Any]] = {}
        attack_ids_by_run: dict[str, set[str]] = {}
        for index, run in enumerate(runs, 1):
            path = f"runs.jsonl:{index}"
            _validate_object(run, "runs", path, contract, errors)
            run_id = run.get("run_id")
            if not isinstance(run_id, str) or not run_id:
                errors.append(f"{path}.run_id: must be a non-empty string")
            elif run_id in run_ids:
                errors.append(f"{path}.run_id: duplicate run_id {run_id}")
            else:
                run_ids.add(run_id)
                run_by_id[run_id] = run
            if run.get("schema_version") != SCHEMA_VERSION:
                errors.append(f"{path}.schema_version: wrong schema_version")
            roles = run.get("node_roles")
            if isinstance(roles, dict):
                allowed_roles = {role.value for role in NodeRole}
                if any(
                    not isinstance(value, str) or value not in allowed_roles
                    for value in roles.values()
                ):
                    errors.append(f"{path}.node_roles: invalid role value")
                node_count = run.get("node_count")
                legitimate_roles = run.get("legitimate_node_roles")
                legitimate_count = run.get("legitimate_node_count")
                non_external = {
                    key: value for key, value in roles.items() if value != "EXTERNAL"
                }
                if isinstance(node_count, int) and len(non_external) != node_count:
                    errors.append(
                        f"{path}.node_count: must equal the number of non-EXTERNAL roles"
                    )
                if legitimate_count != node_count:
                    errors.append(
                        f"{path}.legitimate_node_count: must equal node_count"
                    )
                if isinstance(legitimate_roles, dict) and legitimate_roles != non_external:
                    errors.append(
                        f"{path}.legitimate_node_roles: must equal non-EXTERNAL node_roles"
                    )
                externals = run.get("external_participants")
                if isinstance(externals, list):
                    declared = {
                        str(item.get("node_id"))
                        for item in externals
                        if isinstance(item, dict) and item.get("role") == "EXTERNAL"
                    }
                    actual = {
                        str(key) for key, value in roles.items() if value == "EXTERNAL"
                    }
                    if declared != actual:
                        errors.append(
                            f"{path}.external_participants: must exactly declare EXTERNAL node_roles"
                        )
            maturity = run.get("dataset_maturity")
            providers = run.get("security_providers")
            if maturity == "FORMAL" and isinstance(providers, dict):
                for provider_name, provider in providers.items():
                    status = (
                        str(provider.get("status", "UNKNOWN"))
                        if isinstance(provider, dict)
                        else "UNKNOWN"
                    )
                    if (
                        "TEST" in status
                        or "SIMULATED" in status
                        or status in {"INTERFACE_READY", "UNKNOWN"}
                    ):
                        errors.append(
                            f"{path}.dataset_maturity: FORMAL is incompatible with {provider_name} status {status}"
                        )

            attack_plan = run.get("attack_plan")
            normal_plan = run.get("normal_disturbance_plan")
            profiles = run.get("profiles")
            if isinstance(run_id, str):
                attack_ids_by_run[run_id] = {
                    str(plan.get("attack_id"))
                    for plan in (attack_plan if isinstance(attack_plan, list) else [])
                    if isinstance(plan, dict)
                    and isinstance(plan.get("attack_id"), str)
                }
            if (
                isinstance(attack_plan, list)
                and all(isinstance(plan, dict) for plan in attack_plan)
                and isinstance(profiles, dict)
            ):
                expected = plan_collection_id("attack-plan", attack_plan, identity_field="attack_id")
                if profiles.get("attack_plan_id") != expected:
                    errors.append(f"{path}.profiles.attack_plan_id: does not match attack plan")
            if (
                isinstance(normal_plan, list)
                and all(isinstance(plan, dict) for plan in normal_plan)
                and isinstance(profiles, dict)
            ):
                expected = plan_collection_id("normal-plan", normal_plan, identity_field="profile_id")
                if profiles.get("normal_disturbance_plan_id") != expected:
                    errors.append(f"{path}.profiles.normal_disturbance_plan_id: does not match normal plan")

            for plan_index, plan in enumerate(attack_plan if isinstance(attack_plan, list) else []):
                if not isinstance(plan, dict):
                    continue
                family = plan.get("attack_family")
                subtype = plan.get("attack_subtype")
                if isinstance(family, str) and family in ATTACK_SUBTYPES and subtype not in ATTACK_SUBTYPES[family]:
                    errors.append(f"{path}.attack_plan[{plan_index}]: subtype does not belong to family")
                scheduled = plan.get("scheduled_start_s")
                impact = plan.get("impact_start_s")
                end = plan.get("end_s")
                if all(_is_number(item) for item in (scheduled, impact, end)) and not 0 <= scheduled <= impact < end:
                    errors.append(f"{path}.attack_plan[{plan_index}]: invalid attack interval")
                if plan.get("attacker_node_id") is None:
                    errors.append(
                        f"{path}.attack_plan[{plan_index}].attacker_node_id: unresolved"
                    )
                targets = plan.get("target_node_ids")
                links = plan.get("target_link_ids")
                if isinstance(targets, list) and len(targets) != 1:
                    errors.append(
                        f"{path}.attack_plan[{plan_index}].target_node_ids: V5 requires exactly one resolved target"
                    )
                if isinstance(links, list) and len(links) > 1:
                    errors.append(
                        f"{path}.attack_plan[{plan_index}].target_link_ids: MULTI_TARGET_NOT_SUPPORTED_V6"
                    )

            for plan_index, plan in enumerate(normal_plan if isinstance(normal_plan, list) else []):
                if not isinstance(plan, dict):
                    continue
                start = plan.get("start_s")
                end = plan.get("end_s")
                if _is_number(start) and _is_number(end) and not 0 <= start < end:
                    errors.append(f"{path}.normal_disturbance_plan[{plan_index}]: invalid interval")

            config = run.get("run_config")
            fingerprint = run.get("config_fingerprint")
            if isinstance(fingerprint, str) and not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                errors.append(f"{path}.config_fingerprint: must be SHA-256 hex")
            if isinstance(config, dict) and isinstance(attack_plan, list) and isinstance(normal_plan, list):
                try:
                    parsed = RunConfig.from_dict(config)
                    expected_fingerprint = parsed.semantic_fingerprint(
                        attack_plans=attack_plan,
                        normal_disturbance_plans=normal_plan,
                        include_rff=any(name.startswith("rff_") for name in config),
                    )
                    calibration_hash = (
                        run.get("profiles", {}).get("calibration_profile_hash")
                        if isinstance(run.get("profiles"), dict)
                        else None
                    )
                    if (
                        "model_assets" in run
                        or calibration_hash is not None
                        or "probe_profile" in run
                    ):
                        expected_fingerprint = runtime_semantic_fingerprint(
                            expected_fingerprint,
                            calibration_profile_hash=calibration_hash,
                            model_assets=(
                                run.get("model_assets")
                                if isinstance(run.get("model_assets"), dict)
                                else None
                            ),
                            probe_profile=(
                                str(run.get("probe_profile"))
                                if "probe_profile" in run
                                else None
                            ),
                        )
                    if fingerprint != expected_fingerprint:
                        errors.append(f"{path}.config_fingerprint: semantic fingerprint mismatch")
                except (TypeError, ValueError) as exc:
                    errors.append(f"{path}.run_config: invalid configuration ({exc})")

        event_ids: set[str] = set()
        message_ids: set[tuple[str, str]] = set()
        tx_message_ids: set[tuple[str, str]] = set()
        event_reference_checks: list[tuple[str, Any]] = []
        message_reference_checks: list[tuple[str, str, str]] = []
        last_time_by_observer: dict[tuple[str, int], float] = {}
        for index, event in enumerate(events, 1):
            path = f"events.jsonl:{index}"
            _validate_object(event, "events", path, contract, errors)
            if event.get("schema_version") != SCHEMA_VERSION:
                errors.append(f"{path}.schema_version: wrong schema_version")
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                errors.append(f"{path}.event_id: must be a non-empty string")
            elif event_id in event_ids:
                errors.append(f"{path}.event_id: duplicate event_id {event_id}")
            else:
                event_ids.add(event_id)
            run_id = event.get("run_id")
            if not isinstance(run_id, str) or run_id not in run_ids:
                errors.append(f"{path}.run_id: unknown run_id")
            event_type = event.get("event_type")
            if (
                not isinstance(event_type, str)
                or event_type not in {item.value for item in EventType}
            ):
                errors.append(f"{path}.event_type: unsupported event_type")
            run = run_by_id.get(str(run_id))
            roles = run.get("node_roles") if isinstance(run, dict) else None
            observer = event.get("observer_node_id")
            observer_role = event.get("observer_role")
            if isinstance(roles, dict) and isinstance(observer, int):
                expected_role = roles.get(str(observer))
                if expected_role is None:
                    errors.append(f"{path}.observer_node_id: node is not declared by run")
                elif observer_role != expected_role:
                    errors.append(
                        f"{path}.observer_role: {observer_role!r} does not match run role {expected_role!r}"
                    )

            current = event.get("sim_time_s")
            observer = event.get("observer_node_id")
            if _is_number(current) and isinstance(observer, int) and not isinstance(observer, bool):
                key = (str(run_id), observer)
                previous = last_time_by_observer.get(key)
                if previous is not None and current < previous:
                    errors.append(f"{path}.sim_time_s: observer time moved backwards")
                last_time_by_observer[key] = float(current)
                run = run_by_id.get(str(run_id))
                duration = run.get("duration_s") if run else None
                if _is_number(duration) and current > duration + 1e-9:
                    errors.append(f"{path}.sim_time_s: exceeds run duration")

            message_id = event.get("message_id")
            if isinstance(message_id, str) and message_id:
                message_key = (str(run_id), message_id)
                message_ids.add(message_key)
                if event_type == "TX":
                    tx_message_ids.add(message_key)
                elif event_type in {"RX_SUCCESS", "RX_FAILURE", "AUTH_RESULT"}:
                    message_reference_checks.append((path, *message_key))

            features = event.get("online_features")
            if not isinstance(features, dict):
                errors.append(f"{path}.online_features: must be an object")
            else:
                missing_groups = self.ONLINE_GROUPS - features.keys()
                if missing_groups:
                    errors.append(f"{path}.online_features: missing groups {sorted(missing_groups)}")
                unknown_groups = features.keys() - self.ONLINE_GROUPS
                if unknown_groups:
                    errors.append(
                        f"{path}.online_features: unknown frozen groups {sorted(unknown_groups)}"
                    )
                forbidden = find_forbidden_online_fields(features)
                if forbidden:
                    errors.append(f"{path}.online_features: forbidden online fields {forbidden}")
                proxies = find_label_proxies(event)
                if proxies:
                    errors.append(f"{path}: online label/scenario proxy at {proxies}")
                for group in self.ONLINE_GROUPS & features.keys():
                    _validate_object(
                        features[group],
                        f"online_features.{group}",
                        f"{path}.online_features.{group}",
                        contract,
                        errors,
                    )

            availability = event.get("availability")
            if not isinstance(availability, dict):
                errors.append(f"{path}.availability: must be an object")
            else:
                required_availability = {"payload_available", "phy_available", "sensor_available", "missing_reason"}
                missing = required_availability - availability.keys()
                if missing:
                    errors.append(f"{path}.availability: missing fields {sorted(missing)}")
                for name in ("payload_available", "phy_available", "sensor_available"):
                    if name in availability and not isinstance(availability[name], bool):
                        errors.append(f"{path}.availability.{name}: must be boolean")
                missing_reason = availability.get("missing_reason")
                if missing_reason is not None and not isinstance(missing_reason, str):
                    errors.append(f"{path}.availability.missing_reason: must be string or null")

            if event_type == "MODEL_RESULT":
                extensions = event.get("extensions")
                model = extensions.get("model_result") if isinstance(extensions, dict) else None
                if _validate_object(model, "model_result", f"{path}.extensions.model_result", contract, errors):
                    if model.get("observer_node_id") != event.get("observer_node_id"):
                        errors.append(
                            f"{path}.extensions.model_result.observer_node_id: must match event observer"
                        )
                    if model.get("run_id") != event.get("run_id"):
                        errors.append(
                            f"{path}.extensions.model_result.run_id: must match event run"
                        )
                    event_reference_checks.append(
                        (f"{path}.extensions.model_result.evidence_event_ids", model.get("evidence_event_ids", []))
                    )
            phy = (
                features.get("phy", {}) if isinstance(features, dict) else {}
            )
            decode_success = phy.get("decode_success") if isinstance(phy, dict) else None
            if event_type == "RX_FAILURE" and decode_success is not False:
                errors.append(f"{path}.online_features.phy.decode_success: RX_FAILURE requires false")
            if event_type == "RX_SUCCESS" and decode_success is not True:
                errors.append(f"{path}.online_features.phy.decode_success: RX_SUCCESS requires true")
            if event_type == "TX" and decode_success is not None:
                errors.append(f"{path}.online_features.phy.decode_success: TX has no receiver decode result")
            for ref_path, refs in _named_references(
                event.get("extensions", {}), {"source_event_ids"}
            ):
                event_reference_checks.append((f"{path}.{ref_path}", refs))

        for path, run_id, message_id in message_reference_checks:
            if (run_id, message_id) not in tx_message_ids:
                errors.append(f"{path}.message_id: no TX event for {message_id}")

        label_ids: set[str] = set()
        attack_ids: set[str] = set()
        for index, label in enumerate(labels, 1):
            path = f"labels.jsonl:{index}"
            _validate_object(label, "labels", path, contract, errors)
            if label.get("schema_version") != SCHEMA_VERSION:
                errors.append(f"{path}.schema_version: wrong schema_version")
            label_run_id = label.get("run_id")
            if not isinstance(label_run_id, str) or label_run_id not in run_ids:
                errors.append(f"{path}.run_id: unknown run_id")
            family = label.get("attack_family")
            subtype = label.get("attack_subtype")
            if not isinstance(family, str) or family not in ATTACK_FAMILIES:
                errors.append(f"{path}.attack_family: unsupported attack family")
            elif (
                not isinstance(subtype, str)
                or subtype not in ATTACK_SUBTYPES[family]
            ):
                errors.append(f"{path}.attack_subtype: subtype does not match family")
            label_id = label.get("label_id")
            if not isinstance(label_id, str) or not label_id:
                errors.append(f"{path}.label_id: must be a non-empty string")
            elif label_id in label_ids:
                errors.append(f"{path}.label_id: duplicate label_id")
            else:
                label_ids.add(label_id)
            attack_id = label.get("attack_id")
            if not isinstance(attack_id, str) or not attack_id:
                errors.append(f"{path}.attack_id: must be a non-empty string")
            elif attack_id in attack_ids:
                errors.append(f"{path}.attack_id: duplicate attack_id")
            else:
                attack_ids.add(attack_id)
                planned = attack_ids_by_run.get(str(label_run_id), set())
                if attack_id not in planned:
                    errors.append(
                        f"{path}.attack_id: not present in the run attack_plan"
                    )
            scheduled = label.get("scheduled_start_s")
            impact = label.get("impact_start_s")
            end = label.get("end_s")
            if all(_is_number(item) for item in (scheduled, impact, end)) and not 0 <= scheduled <= impact < end:
                errors.append(f"{path}: invalid attack interval")
            truth = label.get("truth")
            affected = truth.get("affected_message_ids", []) if isinstance(truth, dict) else []
            if isinstance(affected, list):
                for message_id in affected:
                    if isinstance(message_id, str) and (str(label.get("run_id")), message_id) not in message_ids:
                        errors.append(f"{path}.truth.affected_message_ids: unknown message_id {message_id}")
            if isinstance(truth, dict):
                planned = attack_ids_by_run.get(str(label_run_id), set())
                run = run_by_id.get(str(label_run_id), {})
                matching_plan = next(
                    (
                        item
                        for item in run.get("attack_plan", [])
                        if isinstance(item, dict)
                        and item.get("attack_id") == attack_id
                    ),
                    None,
                )
                if isinstance(matching_plan, dict):
                    for field in (
                        "attack_family",
                        "attack_subtype",
                        "attacker_node_id",
                        "target_node_ids",
                        "target_link_ids",
                        "parameters",
                    ):
                        if label.get(field) != matching_plan.get(field):
                            errors.append(
                                f"{path}.{field}: does not match resolved run attack_plan"
                            )
                    if truth.get("resolved_plan") != matching_plan:
                        errors.append(
                            f"{path}.truth.resolved_plan: does not match run attack_plan"
                        )
                contributors = truth.get("contributing_attack_ids", [])
                if isinstance(contributors, list):
                    for contributor in contributors:
                        if not isinstance(contributor, str) or contributor not in planned:
                            errors.append(
                                f"{path}.truth.contributing_attack_ids: unknown attack_id {contributor}"
                            )
                compound = truth.get("compound_attribution", [])
                if isinstance(compound, list):
                    for row_index, row in enumerate(compound):
                        if not isinstance(row, dict):
                            continue
                        message_id = row.get("message_id")
                        if isinstance(message_id, str) and (
                            str(label_run_id), message_id
                        ) not in message_ids:
                            errors.append(
                                f"{path}.truth.compound_attribution[{row_index}].message_id: unknown message_id {message_id}"
                            )
            outcome = label.get("outcome")
            if isinstance(outcome, dict):
                if outcome.get("reached_target") and not outcome.get("injected"):
                    errors.append(
                        f"{path}.outcome: reached_target requires injected=true"
                    )
                if outcome.get("malicious_content_executed") and not outcome.get(
                    "reached_target"
                ):
                    errors.append(
                        f"{path}.outcome: malicious_content_executed requires reached_target=true"
                    )
                if outcome.get("attack_effective") and not outcome.get(
                    "reached_target"
                ):
                    errors.append(
                        f"{path}.outcome: target-side attack_effective requires reached_target=true"
                    )
            for ref_path, refs in _named_references(
                truth if isinstance(truth, dict) else {},
                {"evidence_event_ids", "relevant_evidence_event_ids", "source_event_ids"},
            ):
                event_reference_checks.append((f"{path}.truth.{ref_path}", refs))

        sample_ids: set[str] = set()
        rf_root = (root / "rf_samples").resolve()
        for index, sample in enumerate(rf_manifest, 1):
            path = f"rf_manifest.jsonl:{index}"
            _validate_object(sample, "rf_manifest", path, contract, errors)
            sample_id = sample.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id:
                errors.append(f"{path}.sample_id: must be a non-empty string")
            elif sample_id in sample_ids:
                errors.append(f"{path}.sample_id: duplicate sample_id")
            else:
                sample_ids.add(sample_id)
            capture_start = sample.get("capture_start_utc")
            if capture_start is not None:
                try:
                    if not isinstance(capture_start, str):
                        raise TypeError
                    parsed = datetime.fromisoformat(capture_start.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError
                except (TypeError, ValueError):
                    errors.append(f"{path}.capture_start_utc: must be ISO-8601 with timezone")
            file_path = sample.get("file_path")
            if isinstance(file_path, str) and file_path:
                referenced = (rf_root / file_path).resolve()
                try:
                    referenced.relative_to(rf_root)
                except ValueError:
                    errors.append(f"{path}.file_path: escapes rf_samples")
                else:
                    if not referenced.is_file():
                        errors.append(f"{path}.file_path: sample file not found")
        if not rf_manifest:
            warnings.append("RF manifest is empty; no IQ/model claims may be made")

        for index, event in enumerate(events, 1):
            features = event.get("online_features")
            phy = features.get("phy") if isinstance(features, dict) else None
            ref = phy.get("rf_sample_ref") if isinstance(phy, dict) else None
            if isinstance(ref, str) and ref not in sample_ids:
                errors.append(f"events.jsonl:{index}.online_features.phy.rf_sample_ref: unknown rf_sample_ref {ref}")

        for path, references in event_reference_checks:
            if not isinstance(references, list) or not all(isinstance(item, str) for item in references):
                errors.append(f"{path}: must be an array of event ID strings")
                continue
            for reference in references:
                if reference not in event_ids:
                    errors.append(f"{path}: unknown event_id {reference}")

        leakage = DatasetLeakageAudit.audit_events(events)
        errors.extend(f"leakage audit: {error}" for error in leakage.errors)

        return ValidationReport(
            valid=not errors,
            errors=errors,
            warnings=warnings,
            counts={
                "runs": len(runs),
                "events": len(events),
                "labels": len(labels),
                "rf_manifest": len(rf_manifest),
            },
        )
