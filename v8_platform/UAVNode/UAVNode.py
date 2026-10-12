import json
import os
import numpy as np

from Detector.Defense import DynamicDefenseSystem
from Detector.Detector import UnifiedDetector


# ==========================================
# 第二部分：5G 物理层模型 (3GPP Channel Model)
# ==========================================

class UAVNode:
    def __init__(self, node_id, pos=(0, 0, 0)):
        self.node_id = node_id

        # === 1. 通信物理属性 ===
        self.tx_power_dbm = 23.0
        self.antenna_gain_dbi = 5.0
        self.rx_buffer = []
        # === 2. 空间物理属性 (使用 numpy) ===
        # 当前位置 [x, y, z]
        self.position = np.array(pos, dtype=float)
        # === 3. 无人机内部状态 (State Machine) ===
        self.internal_state = {
            # --- 基础状态 ---
            "battery_level": 100.0,  # 电量 %
            "flight_mode": "DISARMED",  # 状态: DISARMED, TAKING_OFF, LANDING, HOVERING, FLYING, PATROLLING
            "network_slice": "URLLC",  # 默认控制切片为 URLLC (高可靠低延迟)
            "video_on": False,  # 摄像头开关 (本轮指令去掉了视频流，先设为False)

            # --- 导航控制状态 (新增) ---
            "target_position": np.array(pos, dtype=float),  # 目标位置
            "waypoints": []  # 航点队列 list of np.array
        }
        # === 4. 安全模块集成 ===
        # 必须在这里实例化你在外部定义的检测器和防御器
        self.detector = UnifiedDetector()
        self.defense = DynamicDefenseSystem()

        # === 5. 新增：针对各类攻击的防御开关 ===
        self.defense_config = {
            "DoS": True,         # 干扰检测（SNR检测）
            "Spoofing": True,    # 身份伪装检测（签名验证）
            "FDI": True,         # 恶意注入检测（签名验证）
            "Replay": True,      # 重放攻击检测（序号+时间戳）
            "Eavesdropping": True,
        }
        # === 6. 新增：存储最近一次检测结果，供日志读取 ===
        self.last_detection_result = {
            "detected": False,
            "evidence": {}
        }
        # ★ 新增：拓扑引用（在 init_environment 中赋值）
        self.network_topo = None
        # ★ 新增：最近一次 DoS 检测结果
        self.last_dos_detection = {
            "detected": False,
            "link_id": None,
            "snr": 0.0,
            "blocked": False
        }

    def observe_link_quality(self, link_id, snr):
        """
        观测链路信道质量，无论报文是否成功接收都会被调用。

        检测逻辑：SNR 低于阈值 → 判定为干扰
        防御逻辑：如果 DoS 防御开启 → 封锁该链路
        """
        SNR_THRESHOLD = 5.0  # DoS 检测阈值 (dB)
        dos_detected = snr < SNR_THRESHOLD
        link_blocked = False
        if dos_detected:
            if self.defense_config.get("DoS", True) and self.network_topo:
                # 防御开启：封锁该链路
                self.network_topo.report_bad_link(link_id)
                link_blocked = True
                print(f"  > [UAV-{self.node_id}] DoS 检测: Link-{link_id} SNR={snr:.1f}dB < {SNR_THRESHOLD}dB, 已封锁!")
            else:
                print(f"  > [UAV-{self.node_id}] DoS 检测: Link-{link_id} SNR={snr:.1f}dB 异常, 但防御未开启")
        self.last_dos_detection = {
            "detected": dos_detected,
            "link_id": link_id,
            "snr": round(snr, 1),
            "blocked": link_blocked
        }
        return dos_detected

    def secure_receive(self, packet, channel_metadata):

        packet = UAVNode.decrypt_packet(packet)
        # 1. 统一检测
        # 注意：这里传入 self.internal_state 是为了让防御模块能读取/修改状态（比如切信道）
        detect_result, evidence = self.detector.detect(
            packet, channel_metadata, self.internal_state, self.defense_config
        )
        # 2. 存储检测结果（供外部日志读取）
        self.last_detection_result = {
            "detected": detect_result == 1,
            "evidence": evidence
        }
        # 3. 动态防御 (传入 channel_metadata)
        action, filtered_packet = self.defense.mitigate(
            detect_result, packet, self.internal_state, channel_metadata
        )

        status_str = "Unknown"
        if action == "pass":
            if filtered_packet:
                self.rx_buffer.append(filtered_packet)
                self.execute_command(filtered_packet['payload_obj']['data'])
                status_str = "Processed"
        elif action == "drop":
            status_str = f"Dropped ({evidence.get('type', 'Unknown')})"

        return status_str

    def execute_command(self, cmd_data):
        # 参数验证
        if not isinstance(cmd_data, dict):
            print(f"  > [Error] 无效的指令格式: {cmd_data}")
            return

        cmd = cmd_data.get('cmd')
        if not cmd:
            print(f"  > [Error] 缺少 cmd 字段")
            return

        params = cmd_data.get('params', {})

        if cmd in {"HEARTBEAT", "TELEMETRY", "VIDEO_FRAME", "ALERT"}:
            return

        # 获取当前坐标 (x, y, z)
        current_pos = self.position

        print(f"  > [UAV-{self.node_id}] 处理指令: {cmd}")
        # --- 1. 起飞 (TAKEOFF) ---
        if cmd == "TAKEOFF":
            target_alt = float(params['alt'])
            # 保持水平坐标，只改变高度 Z
            new_target = np.array([current_pos[0], current_pos[1], target_alt])

            self._update_nav_state("TAKING_OFF", new_target)
            self.internal_state["network_slice"] = "URLLC"  # 关键控制
        # --- 2. 降落 (LAND) ---
        elif cmd == "LAND":
            # 保持水平坐标，高度 Z 归零
            new_target = np.array([current_pos[0], current_pos[1], 0.0])

            self._update_nav_state("LANDING", new_target)
            self.internal_state["video_on"] = False  # 降落关闭视频
            self.internal_state["waypoints"] = []  # 清空巡航任务
        # --- 3. 悬停 (HOVER) ---
        elif cmd == "HOVER":
            # 锁定当前位置为目标
            new_target = current_pos.copy()

            self._update_nav_state("HOVERING", new_target)
            self.internal_state["waypoints"] = []  # 清空巡航任务
        # --- 4. 飞往单点 (FLY_TO) ---
        elif cmd == "FLY_TO":
            # 完整的三维目标
            pt = params['target']
            new_target = np.array(pt, dtype=float)

            self._update_nav_state("FLYING", new_target)
            self.internal_state["waypoints"] = []  # 清空巡航任务
        # --- 5. 航点巡航 (FLY_WAYPOINTS) ---
        elif cmd == "FLY_WAYPOINTS":
            points = params['points']
            lent = len(points)
            if lent > 0:
                # 转换航点列表为 numpy 数组列表
                waypoint_queue = [np.array(p, dtype=float) for p in points]

                # 设置最后一个点为当前目标
                target = waypoint_queue[lent - 1]

                self._update_nav_state("PATROLLING", target)
                self.internal_state["waypoints"] = waypoint_queue  # 保存完整队列
            else:
                print(f"  > [Warn] 收到空航点，忽略")
        elif cmd == "VIDEO_STREAM":
            action = params.get('action')

            if action == "start":
                # 获取参数
                res = params.get('res', '1080p')
                fps = params.get('fps', 30)
                coding = params.get('coding', 'H.264')

                # 更新状态
                self.internal_state["video_on"] = True
                self.internal_state["video_res"] = f"{res}@{fps}fps ({coding})"

                # [关键] 开启 4K 视频时，自动切换到大带宽切片 (eMBB)
                if res == "4K":
                    self.internal_state["network_slice"] = "eMBB"
                else:
                    self.internal_state["network_slice"] = "eMBB-Lite"

                print(
                    f"    -> [Camera] 开启视频流: {self.internal_state['video_res']} | 切片: {self.internal_state['network_slice']}")

            elif action == "stop":
                self.internal_state["video_on"] = False
                self.internal_state["video_res"] = "None"
                # 关闭视频后，切回高可靠切片用于控制
                self.internal_state["network_slice"] = "URLLC"

                print(f"    -> [Camera] 视频流已关闭 | 切片回退: URLLC")

    def _update_nav_state(self, mode, target_pos):
        """辅助函数：更新导航状态"""
        self.internal_state["flight_mode"] = mode
        self.internal_state["target_position"] = target_pos

        # 格式化打印以便调试
        tgt_str = f"({target_pos[0]:.1f}, {target_pos[1]:.1f}, {target_pos[2]:.1f})"
        print(f"    -> 状态变更为 [{mode}], 目标: {tgt_str}")

    def encrypt_packet(self, packet):
        """
        ★ 发送前加密处理

        当 defense_config["Eavesdropping"] == True 时:
          1. 将 payload 中的 data 字段替换为密文
          2. 保留旧版 is_encrypted 兼容标记
          3. 明确标注为测试编码，不提供机密性

        仿真简化:
          - 不做加密，只进行 Base64 测试编码；禁止用于安全实验结论
          - 接收方通过 decrypt_packet 还原
          - 窃听者看到的是不可读的密文
        """
        import base64

        payload = packet.get('payload_obj', {})

        # 检查是否已加密 (避免重复加密)
        if payload.get('is_encrypted', False):
            return packet

        # 检查发送方是否开启了加密防御
        if not self.defense_config.get("Eavesdropping", False):
            return packet  # 未开启, 明文发送

        # --- 执行加密 ---
        # 1. 保存原始明文数据
        plaintext_data = json.dumps(payload.get('data', {}))

        # 2. 旧版可逆测试编码；这不是加密
        salt = os.urandom(8).hex()  # 16字符的随机盐
        encrypted_blob = base64.b64encode(
            (salt + plaintext_data).encode('utf-8')
        ).decode('utf-8')

        # 3. 替换明文为密文
        payload['data'] = {
            "encrypted": True,
            "cipher": encrypted_blob,
            "algorithm": "BASE64_TEST_ENCODING_NOT_ENCRYPTION",
            "security_level": "NONE",
            "key_id": None,
            "salt": salt
        }
        payload['is_encrypted'] = True

        # 4. 重新计算签名 (加密后的数据也要签名, 确保完整性)
        #payload['signature'] = calculate_signature(payload)

        print(f"    [Legacy Encoding] UAV-{self.node_id} 已执行 Base64 测试编码（非加密）")

        return packet

    @staticmethod
    def decrypt_packet(packet):
        """
        ★ 接收方解密处理

        还原 encrypt_packet 加密的内容
        旧版兼容: Base64 测试解码 + 去盐（非密码学解密）
        """
        import base64

        payload = packet.get('payload_obj', {})

        if not payload.get('is_encrypted', False):
            return packet  # 未加密, 无需处理

        encrypted_data = payload.get('data', {})
        if not encrypted_data.get('encrypted', False):
            return packet

        try:
            cipher = encrypted_data.get('cipher', '')
            salt = encrypted_data.get('salt', '')

            # 解密: base64 解码后去掉盐值
            decrypted_str = base64.b64decode(cipher.encode('utf-8')).decode('utf-8')
            # 去掉前面的盐 (16字符)
            plaintext_str = decrypted_str[len(salt):]

            # 还原原始数据
            original_data = json.loads(plaintext_str)
            payload['data'] = original_data
            payload['is_encrypted'] = False  # 标记为已解密

            # 重新计算签名 (解密后重签, 用于后续完整性验证)
            #payload['signature'] = calculate_signature(payload)

        except Exception as e:
            print(f"    [Crypto] 解密失败: {e}")
            # 解密失败, 保持密文状态

        return packet
