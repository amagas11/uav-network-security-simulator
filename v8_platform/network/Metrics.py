from collections import deque
import numpy as np
# Part 4: NetworkMetricsTracker 类 - 性能指标追踪
class NetworkMetricsTracker:
    """
    网络性能指标追踪器
    功能:
      - 记录每帧的吞吐量 / 时延
      - 提供聚合统计 (均值 / 分位数 / 最大最小值)
      - 按节点 / 链路 / 切片 维度拆分
      - 导出时序数据供前端绘图
    """
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        # ---- 全局时序 ----
        self.throughput_series = deque(maxlen=max_history)   # (seq, mbps)
        self.latency_series = deque(maxlen=max_history)    # (seq, ms)
        # ---- 按切片聚合 ----
        self.slice_data = {
            "URLLC":     {"count": 0, "tp_sum": 0.0, "lat_sum": 0.0,
                          "lat_list": [], "meets": 0},
            "eMBB":      {"count": 0, "tp_sum": 0.0, "lat_sum": 0.0,
                          "lat_list": [], "meets": 0},
            "eMBB-Lite": {"count": 0, "tp_sum": 0.0, "lat_sum": 0.0,
                          "lat_list": [], "meets": 0},
        }
        # ---- 按节点聚合 ----
        self.node_tx = {}   # {node_id: {"count":0,"tp_sum":0,"lat_sum":0}}
        self.node_rx = {}
        # ---- 按链路聚合 ----
        self.link_data = {}  # {link_id: {"count":0,"tp_sum":0,"lat_sum":0}}
        # ---- 全局计数 ----
        self.total_records = 0
        self.success_records = 0

    def record(self, seq: int, src_id: int, dst_id: int,
               link_id, network_slice: str,
               throughput_mbps: float, latency_ms: float,
               meets_target: bool, is_success: bool):
        """记录一帧的性能数据"""
        self.total_records += 1
        if is_success:
            self.success_records += 1
        # 时序
        self.throughput_series.append({"seq": seq, "mbps": throughput_mbps})
        self.latency_series.append({"seq": seq, "ms": latency_ms})
        # 切片
        s = self.slice_data.get(network_slice)
        if s:
            s["count"] += 1
            s["tp_sum"] += throughput_mbps
            s["lat_sum"] += latency_ms
            s["lat_list"].append(latency_ms)
            if len(s["lat_list"]) > self.max_history:
                s["lat_list"] = s["lat_list"][-self.max_history:]
            if meets_target:
                s["meets"] += 1
        # 节点 TX
        if src_id not in self.node_tx:
            self.node_tx[src_id] = {"count": 0, "tp_sum": 0.0, "lat_sum": 0.0}
        self.node_tx[src_id]["count"] += 1
        self.node_tx[src_id]["tp_sum"] += throughput_mbps
        self.node_tx[src_id]["lat_sum"] += latency_ms
        # 节点 RX
        if dst_id not in self.node_rx:
            self.node_rx[dst_id] = {"count": 0, "tp_sum": 0.0, "lat_sum": 0.0}
        self.node_rx[dst_id]["count"] += 1
        self.node_rx[dst_id]["tp_sum"] += throughput_mbps
        self.node_rx[dst_id]["lat_sum"] += latency_ms
        # 链路
        if link_id is not None:
            if link_id not in self.link_data:
                self.link_data[link_id] = {"count": 0, "tp_sum": 0.0,
                                           "lat_sum": 0.0}
            self.link_data[link_id]["count"] += 1
            self.link_data[link_id]["tp_sum"] += throughput_mbps
            self.link_data[link_id]["lat_sum"] += latency_ms

    def get_summary(self) -> dict:
        """
        获取全局聚合统计
        返回:
          - overall   : 全局均值 / 分位数
          - per_slice : 各切片统计
        """
        if self.total_records == 0:
            return {"status": "no_data"}
        # 全局
        tp_vals  = [d["mbps"] for d in self.throughput_series]
        lat_vals = [d["ms"]   for d in self.latency_series]
        overall = {
            "total_records":    self.total_records,
            "success_records":  self.success_records,
            "packet_loss_rate": round(
                1 - self.success_records / self.total_records, 4
            ) if self.total_records > 0 else 0,
            "throughput": {
                "avg_mbps": round(np.mean(tp_vals), 3),
                "min_mbps": round(min(tp_vals), 3),
                "max_mbps": round(max(tp_vals), 3),
                "std_mbps": round(float(np.std(tp_vals)), 3),
            },
            "latency": {
                "avg_ms":  round(np.mean(lat_vals), 4),
                "min_ms":  round(min(lat_vals), 4),
                "max_ms":  round(max(lat_vals), 4),
                "p50_ms":  round(float(np.percentile(lat_vals, 50)), 4),
                "p95_ms":  round(float(np.percentile(lat_vals, 95)), 4),
                "p99_ms":  round(float(np.percentile(lat_vals, 99)), 4),
                "std_ms":  round(float(np.std(lat_vals)), 4),
            },
        }
        # 各切片
        per_slice = {}
        for sname, sd in self.slice_data.items():
            if sd["count"] == 0:
                per_slice[sname] = {"count": 0, "avg_throughput_mbps": 0,
                                    "avg_latency_ms": 0,
                                    "target_met_pct": 0}
                continue
            lat_arr = sd["lat_list"] if sd["lat_list"] else [0]
            per_slice[sname] = {
                "count":               sd["count"],
                "avg_throughput_mbps": round(sd["tp_sum"]  / sd["count"], 3),
                "avg_latency_ms":     round(sd["lat_sum"] / sd["count"], 4),
                "p95_latency_ms":     round(float(np.percentile(lat_arr, 95)), 4),
                "target_met_pct":     round(sd["meets"] / sd["count"] * 100, 2),
            }
        return {"overall": overall, "per_slice": per_slice}

    def get_time_series(self, last_n: int = 100) -> dict:
        """获取最近 N 帧的时序数据,供前端图表使用"""
        tp  = list(self.throughput_series)[-last_n:]
        lat = list(self.latency_series)[-last_n:]
        return {
            "throughput": tp,
            "latency":    lat,
            "count":      len(tp),
        }

    def get_node_stats(self, node_id: int = None) -> dict:
        """
        获取节点维度统计
        如果 node_id 为 None, 返回全部节点;
        否则返回指定节点
        """
        def _avg(d):
            c = d["count"]
            if c == 0:
                return {"count": 0, "avg_throughput_mbps": 0,
                        "avg_latency_ms": 0}
            return {
                "count":              c,
                "avg_throughput_mbps": round(d["tp_sum"] / c, 3),
                "avg_latency_ms":     round(d["lat_sum"] / c, 4),
            }
        if node_id is not None:
            return {
                "node_id": node_id,
                "as_sender":   _avg(self.node_tx.get(node_id,
                                    {"count":0,"tp_sum":0,"lat_sum":0})),
                "as_receiver": _avg(self.node_rx.get(node_id,
                                    {"count":0,"tp_sum":0,"lat_sum":0})),
            }
        result = {}
        all_ids = set(list(self.node_tx.keys()) + list(self.node_rx.keys()))
        for nid in sorted(all_ids):
            result[nid] = {
                "as_sender":   _avg(self.node_tx.get(nid,
                                    {"count":0,"tp_sum":0,"lat_sum":0})),
                "as_receiver": _avg(self.node_rx.get(nid,
                                    {"count":0,"tp_sum":0,"lat_sum":0})),
            }
        return result
    # ------------------------------------------------------------------
    def get_link_stats(self) -> dict:
        """获取链路维度统计"""
        result = {}
        for lid, d in self.link_data.items():
            c = d["count"]
            result[lid] = {
                "count": c,
                "avg_throughput_mbps": round(d["tp_sum"] / c, 3) if c else 0,
                "avg_latency_ms": round(d["lat_sum"] / c, 4) if c else 0,
            }
        return result
    # ------------------------------------------------------------------
    def reset(self):
        """重置所有统计"""
        self.__init__(self.max_history)