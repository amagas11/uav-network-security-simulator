"""Acceptance evidence for V6P-EAVES-CONTROL-001."""

from __future__ import annotations

from pathlib import Path

import pytest

from swarm_sim import PlatformRuntime, RunConfig, ScenarioMechanismValidator
from swarm_sim.validation import DatasetValidator


CASES = (
    ("NONSENSITIVE_PLAINTEXT_CONTROL", False, False),
    ("CIPHERTEXT_ONLY", True, True),
    ("PLAINTEXT_EXPOSURE", True, False),
)


def _runtime(subtype: str, sensitive: bool, encrypted: bool) -> PlatformRuntime:
    return PlatformRuntime(
        RunConfig.from_dict(
            {
                "seed": 6801,
                "duration_s": 2.0,
                "step_s": 0.2,
                "auto_traffic": False,
                "tx_service_per_step": 32,
                "rx_service_per_step": 32,
                "attack_specs": [
                    {
                        "attack_family": "EAVESDROPPING",
                        "attack_subtype": subtype,
                        "scheduled_start_s": 0.0,
                        "impact_start_s": 0.2,
                        "end_s": 1.6,
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
                        "packet_type": "STATUS" if not sensitive else "MISSION_COMMAND",
                        "start_s": 0.2,
                        "payload": (
                            {"status_code": 1, "value": 12.0}
                            if not sensitive
                            else {"cmd": "FLY_TO", "altitude_m": 100.0}
                        ),
                        "interval_s": 0.2,
                        "count": 5,
                        "sensitive": sensitive,
                        "encrypt": encrypted,
                    }
                ],
            }
        ),
        run_id=f"eaves-three-way-{subtype.lower()}",
    )


@pytest.mark.parametrize("subtype,sensitive,encrypted", CASES)
def test_eavesdropping_three_way_mechanism_and_dataset(
    tmp_path: Path, subtype: str, sensitive: bool, encrypted: bool
):
    runtime = _runtime(subtype, sensitive, encrypted)
    runtime.run_to_completion()
    label = runtime.attack_scheduler.labels()[0]
    outcome = label["outcome"]

    assert outcome["captured_count"] > 0
    if subtype == "NONSENSITIVE_PLAINTEXT_CONTROL":
        assert outcome["ordinary_plaintext_count"] > 0
        assert outcome.get("ciphertext_count", 0) == 0
        assert outcome.get("plaintext_exposure_count", 0) == 0
    elif subtype == "CIPHERTEXT_ONLY":
        assert outcome["ciphertext_count"] > 0
        assert outcome.get("plaintext_exposure_count", 0) == 0
        assert outcome["protection_effective"] is True
    else:
        assert outcome["plaintext_exposure_count"] > 0

    mechanism = ScenarioMechanismValidator.validate(
        runtime, f"EAVESDROPPING_{subtype}"
    )
    assert mechanism.passed, (mechanism.errors, mechanism.evidence)
    output = tmp_path / subtype.lower()
    runtime.export_dataset(output)
    assert DatasetValidator().validate(output).valid


def test_passive_capture_uses_content_semantics_not_ciphertext_alias():
    runtime = _runtime("PASSIVE_CAPTURE", False, False)
    runtime.run_to_completion()
    outcome = runtime.attack_scheduler.labels()[0]["outcome"]
    assert outcome["ordinary_plaintext_count"] > 0
    assert outcome.get("ciphertext_count", 0) == 0
    assert outcome.get("plaintext_exposure_count", 0) == 0
