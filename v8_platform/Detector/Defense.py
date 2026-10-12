# --- 3. 动态防御模块 (Dynamic Defense) ---
class DynamicDefenseSystem:
    def __init__(self):
        self.name = "AdaptiveDefense"

    def mitigate(self, detection_result, packet, state, channel_metadata=None):
        action = "pass"
        processed_packet = packet

        if detection_result == 1:
            processed_packet = None
            action = "drop"

        return action, processed_packet