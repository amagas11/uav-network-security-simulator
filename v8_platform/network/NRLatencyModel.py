import random


# Part 3: NRLatencyModel 类 - 5G NR 时延计算
class NRLatencyModel:
    """
    5G NR 端到端时延计算模型
    标准依据:
      - 3GPP TR 38.913   (时延需求定义)
      - 3GPP TS 38.300   (协议栈时延分析)
      - 3GPP TS 38.214   (HARQ 时序)
    时延组成:
      T_e2e = T_prop + T_tx + T_proc_ue + T_proc_gnb + T_sched
            + T_queue + T_harq + T_security + T_core
    """
    C = 3e8  # 光速 (m/s)
    # ---- 各切片时延参数 (ms) ----
    SLICE_DELAY_PARAMS = {
        "URLLC": {
            "ue_proc_ms":      0.20,    # UE 编解码处理
            "gnb_proc_ms":     0.20,    # gNB 编解码处理
            "sched_ms":        0.125,   # mini-slot 调度 (2 symbol)
            "harq_rtt_ms":     1.0,     # HARQ 往返
            "max_harq_retx":   1,       # 最大重传次数
            "core_ms":         0.50,    # 核心网 (MEC 边缘部署)
            "security_ms":     0.10,    # 安全校验
            "target_ms":       1.0,     # 目标时延
        },
        "eMBB": {
            "ue_proc_ms":      0.50,
            "gnb_proc_ms":     0.50,
            "sched_ms":        0.50,    # 普通 slot 调度
            "harq_rtt_ms":     4.0,
            "max_harq_retx":   4,
            "core_ms":         2.0,
            "security_ms":     0.20,
            "target_ms":       10.0,
        },
        "eMBB-Lite": {
            "ue_proc_ms":      0.50,
            "gnb_proc_ms":     0.50,
            "sched_ms":        0.50,
            "harq_rtt_ms":     4.0,
            "max_harq_retx":   4,
            "core_ms":         1.5,
            "security_ms":     0.15,
            "target_ms":       8.0,
        },
    }

    def calc_propagation_ms(self, distance_m: float) -> float:
        """传播时延  =  d / c   (UAV 场景: 1 km ≈ 0.003 ms)"""
        if distance_m <= 0:
            return 0.0
        return (distance_m / self.C) * 1000.0

    def calc_transmission_ms(self, pkt_bytes: int,
                             throughput_bps: float) -> float:
        """传输时延  =  L / R"""
        if throughput_bps <= 0:
            return 999.0          # 链路不可用
        return (pkt_bytes * 8 / throughput_bps) * 1000.0

    def calc_queuing_ms(self, load: float,
                        network_slice: str = "URLLC") -> float:
        """
        排队时延 (简化 M/M/1 模型)
          T_q = ρ / [μ(1-ρ)]
        URLLC 采用抢占式调度, 排队时延极小
        """
        load = min(max(load, 0.01), 0.99)
        if network_slice == "URLLC":
            base = 0.02 * load / (1 - load)
        else:
            base = 0.30 * load / (1 - load)
        jitter = random.gauss(0, 0.02)
        return max(0.0, base + jitter)

    def calc_harq_delay_ms(self, bler: float,
                           max_retx: int,
                           harq_rtt_ms: float) -> float:
        """
        HARQ 重传期望时延
          E[N_retx] = Σ_{i=1}^{max} i × BLER^i × (1-BLER)
        再乘以 RTT
        """
        exp_retx = 0.0
        for i in range(1, max_retx + 1):
            exp_retx += i * (bler ** i) * (1 - bler)
        # 如果全部失败的概率
        exp_retx += max_retx * (bler ** (max_retx + 1))
        return exp_retx * harq_rtt_ms

    def calculate(self, *,
                  distance_m: float,
                  packet_size_bytes: int,
                  throughput_bps: float,
                  bler: float,
                  num_hops: int = 1,
                  network_slice: str = "URLLC",
                  network_load: float = 0.3,
                  is_attacked: bool = False) -> dict:
        """
        计算端到端总时延并返回详细拆解
        Returns:
            dict:
              - breakdown    : 各分量 (ms)
              - per_hop_ms   : 单跳时延
              - total_ms     : 总时延
              - jitter_ms    : 抖动
              - meets_target : 是否满足切片时延要求
        """
        p = self.SLICE_DELAY_PARAMS.get(
            network_slice, self.SLICE_DELAY_PARAMS["URLLC"])
        # ---- 各分量 ----
        t_prop = self.calc_propagation_ms(distance_m)
        t_tx = self.calc_transmission_ms(packet_size_bytes, throughput_bps)
        t_ue = p["ue_proc_ms"]
        t_gnb = p["gnb_proc_ms"]
        t_sched = p["sched_ms"] + random.uniform(0, p["sched_ms"] * 0.15)
        t_queue = self.calc_queuing_ms(network_load, network_slice)
        t_harq = self.calc_harq_delay_ms(bler, p["max_harq_retx"],
                                             p["harq_rtt_ms"])
        t_sec = p["security_ms"] * (2.0 if is_attacked else 1.0)
        t_core = p["core_ms"]
        # ---- 单跳时延 ----
        single_hop = (t_prop + t_tx + t_ue + t_gnb +
                      t_sched + t_queue + t_harq + t_sec)
        # ---- 多跳累积 (存储转发) ----
        per_hop_extra = t_prop + t_tx + t_gnb          # 每增加一跳的额外开销
        total_ms = single_hop + per_hop_extra * max(0, num_hops - 1) + t_core
        # ---- 抖动 ----
        jitter = abs(random.gauss(0, total_ms * 0.05))
        total_with_jitter = total_ms + jitter
        target = p["target_ms"]
        meets  = total_with_jitter <= target
        return {
            "breakdown": {
                "propagation_ms":       round(t_prop, 6),
                "transmission_ms":      round(t_tx, 6),
                "ue_processing_ms":     round(t_ue, 4),
                "gnb_processing_ms":    round(t_gnb, 4),
                "scheduling_ms":        round(t_sched, 4),
                "queuing_ms":           round(t_queue, 4),
                "harq_retx_ms":         round(t_harq, 4),
                "security_processing_ms": round(t_sec, 4),
                "core_network_ms":      round(t_core, 4),
            },
            "per_hop_extra_ms":  round(per_hop_extra, 4),
            "num_hops":          num_hops,
            "single_hop_ms":     round(single_hop, 4),
            "total_delay_ms":    round(total_ms, 4),
            "jitter_ms":         round(jitter, 4),
            "total_with_jitter_ms": round(total_with_jitter, 4),
            "target_delay_ms":   target,
            "meets_requirement": meets,
            "network_slice":     network_slice,
        }