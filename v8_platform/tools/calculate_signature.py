import hashlib
import json

# ==========================================
# 工具函数：计算签名
# ==========================================


def calculate_signature(payload_data):
    """
    对 payload 中的关键字段进行 SHA-256 哈希计算，模拟数字签名。
    """
    # 提取关键字段，排除 'signature' 本身
    # 我们对 src, dst, timestamp, data 进行签名
    sign_content = {
        "src": payload_data["src"],
        "dst": payload_data["dst"],
        "seq": payload_data.get("seq", 0),
        "timestamp": payload_data["timestamp"],
        "data": payload_data["data"]
    }
    # 保证 json 序列化顺序一致，否则 hash 会变
    content_str = json.dumps(sign_content, sort_keys=True)
    return hashlib.sha256(content_str.encode('utf-8')).hexdigest()