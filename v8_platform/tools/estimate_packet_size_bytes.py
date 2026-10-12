import json

# ==========================================
# 工具函数 - 报文大小估算
# ==========================================


def estimate_packet_size_bytes(packet):
    """
    估算报文在 5G NR 协议栈中的实际传输大小 (字节)

    包含各协议层开销:
    - SDAP (Service Data Adaptation Protocol)
    - PDCP (Packet Data Convergence Protocol)
    - RLC  (Radio Link Control)
    - MAC  (Medium Access Control)
    - IP/UDP 层
    """
    payload_obj = packet.get('payload_obj', {})
    declared_payload_bytes = payload_obj.get('payload_size_bytes')
    if isinstance(declared_payload_bytes, (int, float)) and declared_payload_bytes > 0:
        payload_bytes = int(declared_payload_bytes)
    else:
        payload_str = json.dumps(payload_obj)
        payload_bytes = len(payload_str.encode('utf-8'))
    # 5G NR 协议栈开销 (3GPP TS 38.323 / 38.322 / 38.321)
    sdap_header = 1  # SDAP header
    pdcp_header = 4  # PDCP header (含 SN + HFN)
    rlc_header = 4  # RLC AM header (含 SN + P/SI)
    mac_header = 8  # MAC subheader + padding
    crc_bytes = 3  # TB CRC-24A
    # IP/传输层开销
    ip_header = 40  # IPv6 header
    udp_header = 8  # UDP header
    total_overhead = (sdap_header + pdcp_header + rlc_header +
                      mac_header + crc_bytes + ip_header + udp_header)
    return payload_bytes + total_overhead
