import json
from .AttackBase import AttackBase

# --- 3.2 窃听攻击 (Eavesdropping) ---
class EavesdroppingAttack(AttackBase):
    def __init__(self):
        super().__init__("Eavesdropping")
        self.is_listening = False  # 监听开关
        self.captured_packets = []  # 存储窃听到的报文
        self.max_buffer_size = 20  # 最多存 20 条
        self.listen_start_time = None
        self.listen_duration = 10.0  # 默认监听 10 秒
        self.encrypted_count = 0   # 遇到加密包的次数
        self.plaintext_count = 0   # 成功窃取明文的次数

    def start_listening(self, duration=10.0, sim_time_s=0.0):
        """启动监听模式"""
        self.is_listening = True
        self.listen_start_time = float(sim_time_s)
        self.listen_duration = duration
        self.captured_packets = []  # 清空旧数据
        self.encrypted_count = 0
        self.plaintext_count = 0
        return {"status": "listening_started", "duration": duration}

    def stop_listening(self):
        self.is_listening = False
        return {
            "status": "listening_stopped",
            "captured_count": len(self.captured_packets),
            "plaintext_count": self.plaintext_count,
            "encrypted_count": self.encrypted_count
        }

    def sniff(self, packet, sim_time_s=None):
        """
        被动监听: 每个时间步调用
        ★ 加密防御效果:
          - 明文报文 → 完整记录所有字段 (窃听成功)
          - 加密报文 → 只能记录元数据 (src/dst/seq), 无法读取指令内容 (窃听失败)
        """
        if not self.is_listening:
            return None
        # 检查是否超时
        now_s = sim_time_s
        if now_s is None:
            now_s = packet.get("payload_obj", {}).get("simulation_time_s")
        if now_s is not None and float(now_s) - self.listen_start_time > self.listen_duration:
            self.is_listening = False
            return {
                "status": "timeout",
                "captured": len(self.captured_packets),
                "plaintext": self.plaintext_count,
                "encrypted": self.encrypted_count
            }
        payload = packet.get('payload_obj', {})
        algorithm = payload.get('data', {}).get('algorithm')
        is_encrypted = (
            payload.get('is_encrypted', False)
            and algorithm != "BASE64_TEST_ENCODING_NOT_ENCRYPTION"
        )
        if is_encrypted:
            # ★ 加密报文: 只能获取外层元数据, 无法读取指令内容
            self.encrypted_count += 1
            captured = {
                "seq": packet.get('seq', -1),
                "payload_obj": {
                    "ver": payload.get('ver'),
                    "seq": payload.get('seq'),
                    "src": payload.get('src'),
                    "dst": payload.get('dst'),
                    "timestamp": payload.get('timestamp'),
                    "is_encrypted": True,
                    "data": {
                        "encrypted": True,
                        "content": "[ENCRYPTED - Cannot Read]",
                        "algorithm": payload.get('data', {}).get('algorithm', 'Unknown'),
                    },
                    "signature": "[ENCRYPTED]"
                },
                "_sniff_result": "encrypted"  # ★ 标记窃听结果
            }
            self.captured_packets.append(captured)
            if len(self.captured_packets) > self.max_buffer_size:
                self.captured_packets.pop(0)
            return {
                "status": "sniffing_encrypted",
                "buffer": len(self.captured_packets),
                "msg": "报文已加密, 无法读取内容"
            }
        else:
            # 明文报文: 完整记录 (窃听成功)
            self.plaintext_count += 1
            saved_pkt = json.loads(json.dumps(packet))
            saved_pkt["_sniff_result"] = "plaintext"  # ★ 标记窃听结果
            self.captured_packets.append(saved_pkt)
            if len(self.captured_packets) > self.max_buffer_size:
                self.captured_packets.pop(0)
            return {
                "status": "sniffing_plaintext",
                "buffer": len(self.captured_packets),
                "msg": "明文报文, 窃听成功"
            }
    def execute(self, packet, context=None):
        """
        攻击模式: 返回窃听统计
        """
        return packet, {
            "type": "Passive",
            "desc": (f"Captured {len(self.captured_packets)} packets "
                     f"(plaintext: {self.plaintext_count}, "
                     f"encrypted: {self.encrypted_count})"),
            "success": self.plaintext_count > 0,
            "plaintext_count": self.plaintext_count,
            "encrypted_count": self.encrypted_count,
            "data": self.captured_packets
        }
