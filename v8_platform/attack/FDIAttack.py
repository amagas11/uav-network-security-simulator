
import json
from .AttackBase import AttackBase

# --- 3.4 FDI (恶意注入) 攻击 - 增强版 ---
class FDIAttack(AttackBase):
    def __init__(self):
        super().__init__("FDI_Injection")

    def execute(self, packet, context=None):
        """
        context 参数结构:
        {
            "malicious_cmd": "LAND",           # 恶意指令类型
            "malicious_params": {              # 恶意指令参数
                "alt": 0,
                "mode": "emergency_crash"
            },
            "keep_signature": False            # 是否保留原签名 (默认False,用于测试绕过检测)
        }
        """
        mal_pkt = json.loads(json.dumps(packet))
        payload = mal_pkt['payload_obj']

        # 保存原始指令用于日志
        original_cmd = payload['data'].get('cmd', 'UNKNOWN')
        original_params = payload['data'].get('params', {})

        if context and 'malicious_cmd' in context:
            # 使用前端指定的恶意指令
            mal_cmd = context['malicious_cmd']
            mal_params = context.get('malicious_params', {})

            # 替换载荷内容
            payload['data']['cmd'] = mal_cmd
            payload['data']['params'] = mal_params

            # The application HMAC was generated before this mutation and is
            # deliberately preserved. FDI never receives K_device.

            desc = f"{original_cmd}({original_params}) -> {mal_cmd}({mal_params})"
        else:
            # 默认行为：强制降落
            payload['data']['cmd'] = "LAND"
            payload['data']['params'] = {"alt": 0, "mode": "emergency_crash"}
            #payload['signature'] = "INVALID_SIGNATURE"
            desc = f"{original_cmd} -> LAND(emergency)"

        return mal_pkt, {
            "type": "IntegrityFail",
            "desc": desc,
            "original_cmd": original_cmd,
            "malicious_cmd": payload['data']['cmd']
        }
