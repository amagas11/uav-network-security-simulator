"""Explicit V17 demo resource guard; no detector/attack decision changes."""
import math
from .packet_accounting import active_tick_count
from types import SimpleNamespace


def validate_demo_budget(data):
    if data.get('demo_profile') != 'V17':
        raise ValueError('UNKNOWN_DEMO_PROFILE')
    duration, step = data['duration_s'], data['step_s']
    if not math.isfinite(duration) or not math.isfinite(step) or not 3.2 <= duration <= 30 or step not in (0.1, 0.2):
        raise ValueError('V17_DURATION_RESOURCE_BUDGET')
    if abs(duration / step - round(duration / step)) > 1e-8:
        raise ValueError('V17_DURATION_REQUIRES_INTEGER_TICKS')
    for plan in data.get('attack_specs', []):
        if not 0 <= plan['impact_start_s'] < plan['end_s'] <= duration:
            raise ValueError('V17_ATTACK_INTERVAL_INVALID')
        if plan['attack_family'] == 'DOS':
            rate = float(plan.get('intensity', {}).get('value', 60))
            ticks = active_tick_count(SimpleNamespace(duration_s=duration, step_s=step), plan)
            if not 9 <= rate <= 500 or math.floor(ticks * rate * step + 1e-9) > 5000:
                raise ValueError('V17_FLOODING_RESOURCE_BUDGET_5000')
            if plan['end_s'] > duration - 0.4 + 1e-8:
                raise ValueError('V17_FLOODING_REQUIRES_OBSERVATION_BUFFER')
    if sum(s.get('count', 1) for s in data.get('traffic_specs', [])) > 1000:
        raise ValueError('V17_BUSINESS_RESOURCE_BUDGET_1000')
