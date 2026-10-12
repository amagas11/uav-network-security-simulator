"""Explicit bounded sensor measurement, not a fabricated flight trajectory."""
import math


def validate_measurement_model(model, packet_type):
    if model is None:
        return
    if not isinstance(model, dict) or set(model) != {'name', 'amplitude_m', 'period_s'}:
        raise ValueError('INVALID_TELEMETRY_MEASUREMENT_MODEL')
    if model['name'] != 'BOUNDED_ALTITUDE_SENSOR' or packet_type.upper() != 'TELEMETRY':
        raise ValueError('UNSUPPORTED_TELEMETRY_MEASUREMENT_MODEL')
    for key in ('amplitude_m', 'period_s'):
        value = model[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('INVALID_TELEMETRY_MEASUREMENT_PARAMETER')
    if not 0 < model['amplitude_m'] <= .5 or model['period_s'] <= 0:
        raise ValueError('TELEMETRY_MEASUREMENT_OUT_OF_RANGE')


def measured_payload(payload, model, node, now_s, seed):
    result = dict(payload)
    if model is None:
        return result
    # No RNG draws: this cannot perturb PHY/crypto/attack randomness.
    phase = 2 * math.pi * (int(seed) % 97) / 97
    error = model['amplitude_m'] * math.sin(2 * math.pi * now_s / model['period_s'] + phase)
    result.update(altitude_m=round(node.position_xyz_m[2] + error, 6),
                  flight_state=str(node.flight_state))
    return result
