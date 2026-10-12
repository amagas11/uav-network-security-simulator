import pytest

from app.app import CreateRunRequest
from swarm_sim import RunConfig


DOS_DEFENSE_DEFAULTS = {
    "flooding_severe_rate_multiplier": 1.5,
    "flooding_sustained_overload_s": 0.5,
    "flooding_recovery_rate_multiplier": 0.7,
    "flooding_recovery_hold_s": 2.0,
    "flooding_token_refill_rate_pps": 8.0,
    "flooding_token_bucket_capacity": 12.0,
}


@pytest.mark.parametrize("config_type", [RunConfig, CreateRunRequest])
def test_dos_defense_defaults_match_across_configuration_surfaces(config_type):
    config = config_type()

    for field_name, expected in DOS_DEFENSE_DEFAULTS.items():
        assert getattr(config, field_name) == expected


@pytest.mark.parametrize("config_type", [RunConfig, CreateRunRequest])
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        pytest.param("flooding_severe_rate_multiplier", -1.0, id="severe-negative"),
        pytest.param("flooding_severe_rate_multiplier", 0.0, id="severe-zero"),
        pytest.param("flooding_severe_rate_multiplier", 0.99, id="severe-below-one"),
        pytest.param("flooding_severe_rate_multiplier", False, id="severe-false"),
        pytest.param("flooding_severe_rate_multiplier", True, id="severe-true"),
        pytest.param("flooding_sustained_overload_s", -1.0, id="overload-negative"),
        pytest.param("flooding_sustained_overload_s", 0.0, id="overload-zero"),
        pytest.param("flooding_sustained_overload_s", False, id="overload-false"),
        pytest.param("flooding_sustained_overload_s", True, id="overload-true"),
        pytest.param("flooding_recovery_rate_multiplier", -1.0, id="recovery-negative"),
        pytest.param("flooding_recovery_rate_multiplier", 0.0, id="recovery-zero"),
        pytest.param("flooding_recovery_rate_multiplier", 1.0, id="recovery-one"),
        pytest.param("flooding_recovery_rate_multiplier", 1.01, id="recovery-above-one"),
        pytest.param("flooding_recovery_rate_multiplier", False, id="recovery-false"),
        pytest.param("flooding_recovery_rate_multiplier", True, id="recovery-true"),
        pytest.param("flooding_recovery_hold_s", -1.0, id="hold-negative"),
        pytest.param("flooding_recovery_hold_s", 0.0, id="hold-zero"),
        pytest.param("flooding_recovery_hold_s", False, id="hold-false"),
        pytest.param("flooding_recovery_hold_s", True, id="hold-true"),
        pytest.param("flooding_token_refill_rate_pps", -1.0, id="refill-negative"),
        pytest.param("flooding_token_refill_rate_pps", 0.0, id="refill-zero"),
        pytest.param("flooding_token_refill_rate_pps", False, id="refill-false"),
        pytest.param("flooding_token_refill_rate_pps", True, id="refill-true"),
        pytest.param("flooding_token_bucket_capacity", -1.0, id="capacity-negative"),
        pytest.param("flooding_token_bucket_capacity", 0.0, id="capacity-zero"),
        pytest.param("flooding_token_bucket_capacity", False, id="capacity-false"),
        pytest.param("flooding_token_bucket_capacity", True, id="capacity-true"),
    ],
)
def test_dos_defense_configuration_rejects_invalid_values(
    config_type, field_name, invalid_value
):
    with pytest.raises(ValueError):
        config_type(**{field_name: invalid_value})


@pytest.mark.parametrize("config_type", [RunConfig, CreateRunRequest])
@pytest.mark.parametrize("field_name", DOS_DEFENSE_DEFAULTS)
@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="positive-infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
    ],
)
def test_dos_defense_configuration_rejects_non_finite_values(
    config_type, field_name, invalid_value
):
    with pytest.raises(ValueError):
        config_type(**{field_name: invalid_value})
