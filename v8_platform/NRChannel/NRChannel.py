import math
import random

import numpy as np

from network.NRLatencyModel import NRLatencyModel
from network.NRThroughputModel import NRThroughputModel
from tools.estimate_packet_size_bytes import estimate_packet_size_bytes


try:
    import matlab
    import matlab.engine
    print("[Init] MATLAB Engine API loaded.")
except ImportError:
    matlab = None


class NRChannel:
    """Static A2A channel with FSPL, shadowing, Rician fading, and SINR."""

    def __init__(self, topology, src_node, dst_node, matlab_eng):
        self.topo = topology
        self.src_node = src_node
        self.dst_node = dst_node
        self.eng = matlab_eng

        self.frequency_hz = 3.5e9
        self.noise_floor_dbm = -89.0
        self.shadowing_std_db = 2.0
        self.rician_k_db = 10.0

        self.distance = 0.0
        self.snr = 0.0
        self.last_channel_meta = {}
        self.last_propagation_meta = {}

        self.throughput_model = NRThroughputModel()
        self.latency_model = NRLatencyModel()
        self.last_performance_meta = {}

    def _calculate_static_channel_components(self):
        """Return FSPL, shadowing, Rician gain, and total loss in dB."""
        self.distance = float(np.linalg.norm(
            self.src_node.position - self.dst_node.position))
        distance_m = max(self.distance, 1.0)
        speed_of_light = 299_792_458.0
        fspl_db = 20.0 * math.log10(
            4.0 * math.pi * distance_m * self.frequency_hz / speed_of_light)
        shadowing_db = random.gauss(0.0, self.shadowing_std_db)

        k_linear = 10.0 ** (self.rician_k_db / 10.0)
        los_component = math.sqrt(k_linear / (k_linear + 1.0))
        scatter_scale = math.sqrt(1.0 / (2.0 * (k_linear + 1.0)))
        channel_gain = los_component + scatter_scale * complex(
            random.gauss(0.0, 1.0), random.gauss(0.0, 1.0))
        rician_gain_db = 20.0 * math.log10(max(abs(channel_gain), 1e-12))
        total_loss_db = fspl_db + shadowing_db - rician_gain_db
        return fspl_db, shadowing_db, rician_gain_db, total_loss_db

    def _store_propagation_meta(self, fspl_db, shadowing_db,
                                rician_gain_db, total_loss_db, model):
        self.last_propagation_meta = {
            "propagation_model": model,
            "fspl_db": round(float(fspl_db), 3),
            "shadowing_db": round(float(shadowing_db), 3),
            "rician_fading_gain_db": round(float(rician_gain_db), 3),
            "rician_k_factor_db": self.rician_k_db,
            "total_path_loss_db": round(float(total_loss_db), 3),
        }

    def calculate_path_loss_matlab(self):
        """Calculate static A2A path loss with a MATLAB or Python backend."""
        if self.eng is None or matlab is None:
            components = self._calculate_static_channel_components()
            self._store_propagation_meta(*components, model="python_static_a2a")
            return components[-1]

        try:
            pos_tx = matlab.double(self.src_node.position.tolist())
            pos_rx = matlab.double(self.dst_node.position.tolist())
            self.distance = float(np.linalg.norm(
                self.src_node.position - self.dst_node.position))
            fspl_db, shadowing_db, rician_gain_db = self.eng.calc_uav_channel(
                pos_tx, pos_rx, float(self.frequency_hz), nargout=3)
            total_loss_db = (
                float(fspl_db) + float(shadowing_db) - float(rician_gain_db))
            self._store_propagation_meta(
                fspl_db, shadowing_db, rician_gain_db, total_loss_db,
                model="matlab_static_a2a")
            return total_loss_db
        except Exception:
            components = self._calculate_static_channel_components()
            self._store_propagation_meta(*components, model="python_static_a2a")
            return components[-1]

    @staticmethod
    def _dbm_to_mw(power_dbm):
        return 10.0 ** (power_dbm / 10.0)

    def calculate_sinr(self, path_loss, interference_power_dbm=None):
        tx_p = self.src_node.tx_power_dbm
        tx_g = self.src_node.antenna_gain_dbi
        rx_g = self.dst_node.antenna_gain_dbi
        rx_power = tx_p + tx_g + rx_g - path_loss

        signal_mw = self._dbm_to_mw(rx_power)
        noise_mw = self._dbm_to_mw(self.noise_floor_dbm)
        interference_mw = (
            self._dbm_to_mw(interference_power_dbm)
            if interference_power_dbm is not None else 0.0
        )
        sinr = 10.0 * math.log10(signal_mw / (noise_mw + interference_mw))
        return rx_power, sinr

    def calculate_bler_ldpc(self, sinr):
        return 1.0 / (1.0 + math.exp(0.5 * (sinr - 10)))

    def transmit(self, packet_data):
        path_links = self.topo.get_path(
            self.src_node.node_id, self.dst_node.node_id)
        if not path_links:
            self.last_channel_meta = {
                "distance_m": 0,
                "snr_db": 0,
                "sinr_db": 0,
                "path_loss_db": 0,
                "rssi_dbm": 0,
                "per": 1.0,
                "link_id": None,
                "full_path": [],
                "route_desc": "No Route",
                "link_interference_above_noise_db": 0,
            }
            self.last_performance_meta = {
                "throughput": self.throughput_model._zero_result(
                    {"mcs_index": -1, "modulation_order": 0, "code_rate": 0,
                     "spectral_efficiency": 0, "modulation_name": "N/A"},
                    self.throughput_model.SLICE_CONFIGS["URLLC"], "URLLC"),
                "latency": {
                    "breakdown": {}, "total_delay_ms": 999.0,
                    "jitter_ms": 0, "total_with_jitter_ms": 999.0,
                    "meets_requirement": False, "target_delay_ms": 1.0,
                    "network_slice": "URLLC", "num_hops": 0,
                },
                "packet_size_bytes": 0,
            }
            return False, "Lost(No Route)"

        path_str = "->".join([f"L{link_id}" for link_id in path_links])
        used_link_id = path_links[-1]
        num_hops = len(path_links)
        interference_above_noise_db = self.topo.link_interference_db.get(
            used_link_id, 0.0
        )
        interference_power_dbm = (
            self.noise_floor_dbm + interference_above_noise_db
            if interference_above_noise_db > 0 else None
        )
        path_loss_db = self.calculate_path_loss_matlab()
        rssi, snr_without_interference = self.calculate_sinr(path_loss_db)
        rssi, self.snr = self.calculate_sinr(
            path_loss_db, interference_power_dbm)

        per = self.calculate_bler_ldpc(self.snr)
        success = random.random() > per

        dst_slice = self.dst_node.internal_state.get("network_slice", "URLLC")
        tp_result = self.throughput_model.calculate(
            sinr_db=self.snr,
            bler=per,
            network_slice=dst_slice,
            num_hops=num_hops,
        )

        pkt_size = estimate_packet_size_bytes(packet_data)
        eff_bps = tp_result["throughput"]["effective_bps"]
        net_load = 0.3 + random.uniform(0, 0.15)
        if interference_above_noise_db > 0:
            net_load += 0.3
        net_load = min(net_load, 0.95)
        lat_result = self.latency_model.calculate(
            distance_m=self.distance,
            packet_size_bytes=pkt_size,
            throughput_bps=eff_bps,
            bler=per,
            num_hops=num_hops,
            network_slice=dst_slice,
            network_load=net_load,
            is_attacked=False,
        )

        self.last_channel_meta = {
            "distance_m": round(self.distance, 2),
            "snr_db": round(self.snr, 1),
            "sinr_db": round(self.snr, 1),
            "snr_without_interference_db": round(snr_without_interference, 1),
            "path_loss_db": round(path_loss_db, 1),
            "rssi_dbm": round(rssi, 1),
            "noise_power_dbm": self.noise_floor_dbm,
            "interference_power_dbm": (
                round(interference_power_dbm, 1)
                if interference_power_dbm is not None else None
            ),
            "interference_above_noise_db": round(
                interference_above_noise_db, 1
            ),
            "per": round(per, 6),
            "link_id": used_link_id,
            "full_path": path_links,
            "route_desc": f"[{path_str}]",
            "link_interference_above_noise_db": round(
                interference_above_noise_db, 1
            ),
            "is_encrypted": packet_data.get("payload_obj", {}).get(
                "is_encrypted", False),
        }
        self.last_channel_meta.update(self.last_propagation_meta)
        self.last_performance_meta = {
            "throughput": tp_result,
            "latency": lat_result,
            "packet_size_bytes": pkt_size,
            "network_load": round(net_load, 4),
        }

        log = {
            "src": self.src_node.node_id,
            "dst": self.dst_node.node_id,
            "snr_db": round(self.snr, 1),
            "link_id": used_link_id,
            "full_path": path_links,
            "status": "ACK" if success else "NACK",
        }
        if success:
            status_str = self.dst_node.secure_receive(packet_data, log)
            return True, f"{status_str} via [{path_str}]"

        reason = "Interference" if interference_power_dbm is not None else "PathLoss"
        return False, f"Lost({reason}) on [{path_str}]"
