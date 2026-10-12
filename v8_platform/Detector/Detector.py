from collections import deque
from tools.calculate_signature import calculate_signature
# --- 2. 统一检测模块 (Unified Detector) ---
class UnifiedDetector:
    def __init__(self):
        self.name = "MultiLayerDetector"
        self.seen_seqs = deque(maxlen=1000)  # 只保留最近 1000 个序号
        self.dos_snr_threshold = 5.0  # ★ DoS 检测 SNR 阈值 (dB)

    def detect(self, packet, channel_metadata, context, defense_config=None):
        if defense_config is None:
            defense_config = {
                "DoS": True,
                "Spoofing": True,
                "FDI": True,
                "Replay": True,
            }
        payload = packet.get('payload_obj', {})
        cmd = payload.get('data', {}).get('cmd', '')

        #evidence = {}

        # --- 1. DoS 干扰检测 ---
        if defense_config.get("DoS", True):
            snr = channel_metadata.get('snr_db', 0)
            # ★ 检测逻辑: SNR 低于阈值 → 判定为干扰
            if snr < self.dos_snr_threshold:
                return 1, {
                    "type": "DoS",
                    "reason": "Channel Jamming (SNR below threshold)",
                    "metric": f"SNR={snr}dB < threshold={self.dos_snr_threshold}dB"
                }
        # --- 2. Spoofing/FDI 完整性检测（签名验证）---
        # 只要 Spoofing 或 FDI 其中一个开启，就执行签名检测
        if defense_config.get("Spoofing", True) or defense_config.get("FDI", True):
            received_sig = payload.get('signature', "")
            calculated_sig = calculate_signature(payload)
            if calculated_sig != received_sig:
                return 1, {
                    "type": "Integrity",
                    "reason": "Integrity Violation",
                    "metric": "Hash Mismatch"
                }
        # --- 3. Replay 重放检测 ---
        seq = payload.get('seq', -1)
        replay_identity = (
            payload.get('src'), payload.get('dst'), payload.get('session_id'),
            payload.get('key_epoch'), seq,
        )
        if defense_config.get("Replay", True):

            timestamp = payload.get('timestamp', 0)
            # 检查序号是否重复
            if replay_identity in self.seen_seqs:
                return 1, {
                    "type": "Replay",
                    "reason": "Replay Detected (Duplicate Seq)",
                    "metric": f"Seq={seq}"
                }
            # 检查时间戳是否过期
            now_s = context.get('sim_time_s') if isinstance(context, dict) else None
            time_diff = float(now_s) - float(timestamp) if now_s is not None else None
            if time_diff is not None and time_diff > 5.0:
                return 1, {
                    "type": "Replay",
                    "reason": "Replay Detected (Stale Timestamp)",
                    "metric": f"Age={time_diff:.1f}s"
                }
        # ★ 无论防御是否开启，都记录序号（确保未来能检测重放）
        if replay_identity not in self.seen_seqs:
            self.seen_seqs.append(replay_identity)
        return 0, {}
