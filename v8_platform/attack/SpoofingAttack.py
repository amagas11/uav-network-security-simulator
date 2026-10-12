
import json
from .AttackBase import AttackBase

# --- 3.1 报文伪装攻击 (Spoofing) - 增强版 ---
class SpoofingAttack(AttackBase):
    def __init__(self):
        super().__init__("Spoofing")

    def execute(self, packet, context=None):
        """
        context 参数结构:
        {
            "fake_src": 99,  # 伪装成哪个节点 (可选,默认99)
            # Spoofing only changes the declared source device identity.
        }
        """
        mal_pkt = json.loads(json.dumps(packet))
        payload = mal_pkt['payload_obj']

        # 从 context 中获取伪装参数
        if context:
            fake_src = context.get('fake_src', 99)
        else:
            # 默认行为：伪装成节点 99
            fake_src = 99

        # 执行伪装
        original_src = payload['src']
        payload['src'] = fake_src

        # Payload, destination, type, sequence, timestamp and tag remain
        # unchanged; the pre-existing application HMAC can no longer match.
        desc = f"Src {original_src}->{fake_src}"

        return mal_pkt, {
            "type": "IntegrityFail",
            "desc": desc,
            "original_src": original_src,
            "fake_src": fake_src
        }
