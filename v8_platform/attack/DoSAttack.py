import json

from .AttackBase import AttackBase


class DoSAttack(AttackBase):
    """Legacy facade for the sole supported DoS subtype: Flooding."""

    def __init__(self):
        super().__init__("DoS_Flooding")

    def execute(self, packet, context=None):
        # The production runtime creates the configured burst. This facade
        # preserves an ordinary business-shaped packet without label proxies.
        malicious_packet = json.loads(json.dumps(packet))
        pps = float((context or {}).get("packet_rate_pps", 80.0))
        return malicious_packet, {
            "type": "Flooding",
            "desc": f"Receiver-total load at {pps:.1f} packet/s",
            "packet_rate_pps": pps,
        }
