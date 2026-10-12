import math

# Part 2: NRThroughputModel 类 - 5G NR 吞吐量计算

class NRThroughputModel:
    """
    5G NR 吞吐量计算模型
    核心标准依据:
      - 3GPP TS 38.306 Section 4.1.2  (最大数据速率公式)
      - 3GPP TS 38.214 Table 5.1.3.1-1 (MCS 表)
      - 3GPP TS 38.101-1 Table 5.3.2-1 (带宽-RB 映射)
    核心公式:
      data_rate = 10^{-6} × v_layers × Q_m × f × R_max
                  × (N_RB × 12 × 14 / T_slot_s) × (1 - OH)
    简化后:
      throughput = (RE/s) × Q_m × R × v_layers × (1 - OH) × (1 - BLER)
    """
    # ---- MCS Table 1 for PDSCH (3GPP TS 38.214 Table 5.1.3.1-1) ----
    # 格式: (MCS索引, 调制阶数 Q_m, 目标码率×1024, 频谱效率 bps/Hz)
    MCS_TABLE = [
        ( 0, 2,  120, 0.2344),  # QPSK   - 低 SNR
        ( 1, 2,  157, 0.3066),
        ( 2, 2,  193, 0.3770),
        ( 3, 2,  251, 0.4902),
        ( 4, 2,  308, 0.6016),
        ( 5, 2,  379, 0.7402),
        ( 6, 2,  449, 0.8770),
        ( 7, 2,  526, 1.0273),
        ( 8, 2,  602, 1.1758),
        ( 9, 2,  679, 1.3262),
        (10, 4,  340, 1.3281),  # 16QAM  - 中 SNR
        (11, 4,  378, 1.4766),
        (12, 4,  434, 1.6953),
        (13, 4,  490, 1.9141),
        (14, 4,  553, 2.1602),
        (15, 4,  616, 2.4063),
        (16, 4,  658, 2.5703),
        (17, 6,  438, 2.5664),  # 64QAM  - 高 SNR
        (18, 6,  466, 2.7305),
        (19, 6,  517, 3.0293),
        (20, 6,  567, 3.3223),
        (21, 6,  616, 3.6094),
        (22, 6,  666, 3.9023),
        (23, 6,  719, 4.2129),
        (24, 6,  772, 4.5234),
        (25, 6,  822, 4.8164),
        (26, 6,  873, 5.1152),
        (27, 6,  910, 5.3320),
        (28, 6,  948, 5.5547),
    ]
    # SINR → MCS 映射阈值 (dB)
    # 来源: 链路级仿真 (AWGN + LDPC, target BLER 10%)
    SINR_THRESHOLDS = [
        -6.7, -4.7, -2.3,  0.2,  2.4,  4.3,  5.9,  8.1, 10.3, 11.7,
        11.8, 13.0, 14.8, 16.1, 17.8, 19.8, 20.4,
        20.6, 21.6, 23.0, 24.5, 25.7, 27.2, 28.5, 30.0, 31.2, 33.0, 34.0
    ]
    # ---- 网络切片资源配置 ----
    SLICE_CONFIGS = {
        "URLLC": {
            "bandwidth_mhz": 20,
            "scs_khz":        30,
            "num_rb":          51,      # 20 MHz @ 30 kHz SCS
            "mimo_layers":      1,
            "overhead":         0.18,   # 控制信道 + DMRS 开销
            "desc": "超可靠低时延 (控制指令)"
        },
        "eMBB": {
            "bandwidth_mhz": 100,
            "scs_khz":        30,
            "num_rb":         273,      # 100 MHz @ 30 kHz SCS
            "mimo_layers":      4,
            "overhead":         0.14,
            "desc": "增强移动宽带 (4K 视频)"
        },
        "eMBB-Lite": {
            "bandwidth_mhz": 40,
            "scs_khz":        30,
            "num_rb":         106,      # 40 MHz @ 30 kHz SCS
            "mimo_layers":      2,
            "overhead":         0.14,
            "desc": "轻量宽带 (1080p 视频)"
        },
    }
    SC_PER_RB = 12   # 每 RB 子载波数
    SYM_PER_SLOT = 14   # 每时隙 OFDM 符号数

    def select_mcs(self, sinr_db: float) -> dict:
        """根据 SINR 选择最优 MCS 等级"""
        if sinr_db < self.SINR_THRESHOLDS[0]:
            return {
                "mcs_index": -1,
                "modulation_order": 0,
                "code_rate": 0.0,
                "spectral_efficiency": 0.0,
                "modulation_name": "N/A (Link Failure)"
            }
        sel = 0
        for i, thr in enumerate(self.SINR_THRESHOLDS):
            if sinr_db >= thr:
                sel = i
            else:
                break
        entry = self.MCS_TABLE[sel]
        mod_map = {2: "QPSK", 4: "16QAM", 6: "64QAM", 8: "256QAM"}
        return {
            "mcs_index":            entry[0],
            "modulation_order":     entry[1],
            "code_rate":            round(entry[2] / 1024, 4),
            "spectral_efficiency":  entry[3],
            "modulation_name":      mod_map.get(entry[1], f"{entry[1]}QAM")
        }

    def _slot_duration_ms(self, scs_khz: int) -> float:
        """时隙时长 (ms)  —  T_slot = 1 / 2^μ  ms"""
        mu = int(math.log2(scs_khz / 15))
        return 1.0 / (2 ** mu)

    def calculate(self, sinr_db: float, bler: float,
                  network_slice: str = "URLLC",
                  num_hops: int = 1) -> dict:
        """
        计算链路 / 端到端吞吐量
        返回字典包含:
          - mcs          : MCS 信息
          - slice        : 切片配置
          - resource_grid: 资源网格参数
          - throughput   : 吞吐量各项指标 (峰值 / 有效 / Shannon)
        """
        cfg = self.SLICE_CONFIGS.get(network_slice,
                                     self.SLICE_CONFIGS["URLLC"])
        mcs = self.select_mcs(sinr_db)
        # 信号过弱 → 零吞吐
        if mcs["mcs_index"] == -1:
            return self._zero_result(mcs, cfg, network_slice)
        num_rb = cfg["num_rb"]
        mimo = cfg["mimo_layers"]
        scs = cfg["scs_khz"]
        oh = cfg["overhead"]
        slot_ms = self._slot_duration_ms(scs)
        slot_s = slot_ms / 1000.0
        # RE / s  (Resource Elements per second)
        re_per_s = num_rb * self.SC_PER_RB * self.SYM_PER_SLOT / slot_s
        re_eff = re_per_s * (1 - oh)
        # 峰值吞吐量 (bps)
        peak_bps = re_eff * mcs["modulation_order"] * mcs["code_rate"] * mimo
        # 有效吞吐量 (考虑 BLER)
        eff_bps = peak_bps * (1 - bler)
        # 多跳衰减 (存储转发, 频谱复用受限)
        hop_factor = 1.0 / max(num_hops, 1)
        eff_bps_e2e = eff_bps * hop_factor
        # Shannon 上界  C = B × log2(1 + SNR) × MIMO
        bw_hz = cfg["bandwidth_mhz"] * 1e6
        snr_lin = 10 ** (sinr_db / 10.0)
        shannon_bps = (bw_hz * math.log2(1 + max(snr_lin, 1e-10))
                       * mimo) if snr_lin > 0 else 0
        # 单时隙 TBS
        re_slot = num_rb * self.SC_PER_RB * self.SYM_PER_SLOT
        re_slot_eff = int(re_slot * (1 - oh))
        tbs_bits = int(re_slot_eff * mcs["modulation_order"] * mcs["code_rate"] * mimo)
        return {
            "mcs": mcs,
            "slice": {
                "name":           network_slice,
                "bandwidth_mhz":  cfg["bandwidth_mhz"],
                "num_rb":         num_rb,
                "mimo_layers":    mimo,
                "scs_khz":        scs,
                "overhead_pct":   round(oh * 100, 1),
            },
            "resource_grid": {
                "slot_duration_ms":    round(slot_ms, 4),
                "slots_per_second":    round(1000.0 / slot_ms, 0),
                "re_per_second":       int(re_per_s),
                "re_effective":        int(re_eff),
                "tbs_bits_per_slot":   tbs_bits,
            },
            "throughput": {
                "peak_mbps":           round(peak_bps / 1e6, 3),
                "effective_mbps":      round(eff_bps_e2e / 1e6, 3),
                "effective_kbps":      round(eff_bps_e2e / 1e3, 1),
                "effective_bps":       round(eff_bps_e2e, 0),
                "shannon_capacity_mbps": round(shannon_bps / 1e6, 3),
                "bler_loss_pct":       round(bler * 100, 4),
                "multihop_factor":     round(hop_factor, 4),
                "num_hops":            num_hops,
                "utilization_pct":     round(
                    eff_bps_e2e / shannon_bps * 100, 2
                ) if shannon_bps > 0 else 0.0,
            }
        }

    def _zero_result(self, mcs, cfg, ns):
        return {
            "mcs": mcs,
            "slice": {"name": ns, "bandwidth_mhz": cfg["bandwidth_mhz"],
                      "num_rb": cfg["num_rb"], "mimo_layers": cfg["mimo_layers"],
                      "scs_khz": cfg["scs_khz"],
                      "overhead_pct": round(cfg["overhead"]*100,1)},
            "resource_grid": {"slot_duration_ms": 0, "slots_per_second": 0,
                              "re_per_second": 0, "re_effective": 0,
                              "tbs_bits_per_slot": 0},
            "throughput": {"peak_mbps": 0, "effective_mbps": 0,
                           "effective_kbps": 0, "effective_bps": 0,
                           "shannon_capacity_mbps": 0, "bler_loss_pct": 100,
                           "multihop_factor": 0, "num_hops": 0,
                           "utilization_pct": 0}
        }