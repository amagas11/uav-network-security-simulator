import json
from .AttackBase import AttackBase
import random

# --- 3.5 重放攻击 (Replay) - 增强版 ---
class ReplayAttack(AttackBase):
    def __init__(self, seed=0):
        super().__init__("Replay")
        self.is_listening = False
        self.captured_packets = []
        self.max_buffer_size = 20
        self.listen_start_time = None
        self.listen_duration = 10.0
        self.rng = random.Random(seed)

    def start_listening(self, duration=10.0, sim_time_s=0.0):
        """启动监听模式（与 Eavesdropping 相同）"""
        self.is_listening = True
        self.listen_start_time = float(sim_time_s)
        self.listen_duration = duration
        self.captured_packets = []
        return {"status": "listening_started", "duration": duration}

    def stop_listening(self):
        """手动停止监听"""
        self.is_listening = False
        return {
            "status": "listening_stopped",
            "captured_count": len(self.captured_packets)
        }

    def sniff(self, packet, sim_time_s=None):
        """被动监听：每个时间步调用"""
        if not self.is_listening:
            return None

        # 检查是否超时
        now_s = sim_time_s
        if now_s is None:
            now_s = packet.get("payload_obj", {}).get("simulation_time_s")
        if now_s is not None and float(now_s) - self.listen_start_time > self.listen_duration:
            self.is_listening = False
            return {"status": "timeout", "captured": len(self.captured_packets)}

        # 存储所有报文（不管加密与否）
        saved_pkt = json.loads(json.dumps(packet))
        self.captured_packets.append(saved_pkt)

        if len(self.captured_packets) > self.max_buffer_size:
            self.captured_packets.pop(0)

        return {"status": "sniffing", "buffer": len(self.captured_packets)}

    def execute(self, packet, context=None):
        """
        攻击模式：从缓存中随机取一个旧包重放
        """
        if not self.captured_packets:
            # 不再返回原包，而是抛出明确的失败信号
            return packet, {
                "type": "ReplayFail",
                "desc": "Buffer Empty - Must sniff first",
                "effective": False
            }
        # 随机选一个旧包
        old_pkt = self.rng.choice(self.captured_packets)
        return old_pkt, {
            "type": "Replay",
            "desc": f"Replaying Seq {old_pkt['payload_obj']['seq']}",
            "effective": True
        }
