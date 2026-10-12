import random
import numpy as np
from .calculate_signature import calculate_signature


def generate_realtime_packet(seq_id, num_nodes=10, *, seed=0, sim_time_s=None):
    """
    实时生成一个合法的控制报文
    """
    cmd_types = ["TAKEOFF", "LAND", "HOVER", "FLY_TO", "VIDEO_STREAM"]
    probs = [0.05, 0.05, 0.40, 0.35, 0.15]  # 概率权重和必须为 1.0
    rng = random.Random(f"{seed}:{seq_id}:legacy-packet")
    np_rng = np.random.default_rng((int(seed) * 1_000_003 + int(seq_id)) % (2**32))
    cmd_type = np_rng.choice(cmd_types, p=probs)
    cmd_data = {}

    # 生成合法的参数
    if cmd_type == "TAKEOFF":
        alt = max(10.0, float(np_rng.normal(loc=100.0, scale=30.0)))
        cmd_data = {"cmd": "TAKEOFF", "params": {"alt": round(alt, 1)}}
    elif cmd_type == "LAND":
        cmd_data = {"cmd": "LAND", "params": {"alt": 0}}
    elif cmd_type == "HOVER":
        cmd_data = {"cmd": "HOVER", "params": {"mode": "hold"}}
    elif cmd_type == "FLY_TO":
        target_x = max(0.0, float(np_rng.normal(loc=250.0, scale=100.0)))
        target_y = max(0.0, float(np_rng.normal(loc=250.0, scale=100.0)))
        target_z = max(10.0, float(np_rng.normal(loc=100.0, scale=30.0)))
        cmd_data = {"cmd": "FLY_TO", "params": {"target": [round(target_x, 1), round(target_y, 1), round(target_z, 1)]}}
    elif cmd_type == "VIDEO_STREAM":
        cmd_data = {"cmd": "VIDEO_STREAM", "params": {"action": rng.choice(["start", "stop"])}}

    # 随机源和目的
    src = rng.randint(0, num_nodes - 1)
    dst = rng.randint(0, num_nodes - 1)
    while dst == src: dst = rng.randint(0, num_nodes - 1)

    payload = {
        "ver": 1,
        "seq": seq_id,
        "src": src,
        "dst": dst,
        "timestamp": float(seq_id if sim_time_s is None else sim_time_s),
        "is_encrypted": False,
        "data": cmd_data,
        "signature": ""
    }

    # 计算签名
    payload["signature"] = calculate_signature(payload)

    return {
        "seq": seq_id,
        "payload_obj": payload
    }
