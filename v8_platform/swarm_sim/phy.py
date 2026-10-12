"""Persistent, deterministic direct-link PHY model."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from .calibration import CalibrationProfile
from .csi import CSI_N_SUBCARRIERS, CSI_N_TAPS, frequency_response_db, measure_csi_db, random_tdl_taps
from .domain import Node
from .network import DirectedLink, FormationTopology
from .simulation import RNGRegistry


@dataclass(slots=True)
class LinkPhyState:
    link_id: str
    frequency_hz: float = 3.5e9
    bandwidth_hz: float = 20e6
    channel_id: str = "ch-3500"
    noise_power_dbm: float = -89.0
    tx_power_dbm: float = 23.0
    shadowing_std_db: float = 2.0
    rician_k_db: float = 10.0
    shadowing_db: float = 0.0
    fading_db: float = 0.0
    channel_busy_ratio: float = 0.08
    measurement_quality: float = 0.95
    last_sample_time_s: float = 0.0
    sample_count: int = 0
    session_epoch: int = 1
    calibration_profile_id: str = "uncalibrated-static-a2a-v1"
    calibration_status: str = "UNCALIBRATED_BASELINE"


@dataclass(slots=True)
class PhyOutcome:
    observation: dict[str, Any]
    decode_success: bool
    latency_ms: float
    throughput_mbps: float
    truth: dict[str, Any]


class PersistentPhyModel:
    """One state object per directed physical link.

    The public observation contains only receiver-estimated quantities. Generic
    externally supplied interference, when used by a channel experiment, remains
    in ``PhyOutcome.truth`` and is not a supported attack-plan subtype.
    """

    def __init__(
        self,
        topology: FormationTopology,
        rng_registry: RNGRegistry,
        *,
        profile_id: str = "uncalibrated-static-a2a-v1",
        calibration_status: str = "UNCALIBRATED_BASELINE",
        calibration_profile: CalibrationProfile | None = None,
        frequency_hz: float = 3.5e9,
        bandwidth_hz: float = 20e6,
    ) -> None:
        self.topology = topology
        self.rng_registry = rng_registry
        self.profile_id = profile_id
        self.calibration_status = calibration_status
        self.calibration_profile = calibration_profile
        self.frequency_hz = float(frequency_hz)
        self.bandwidth_hz = float(bandwidth_hz)
        self._parameters = {
            item.parameter: item.value
            for item in calibration_profile.parameters
        } if calibration_profile else {}
        self._calibration_controls = (
            calibration_profile.runtime_controls()
            if calibration_profile is not None
            else {
                "rssi_bias_db": 0.0,
                "snr_bias_db": 0.0,
                "background_loss_probability": 0.0,
                "base_latency_ms": 0.0,
                "latency_jitter_ms": 0.0,
            }
        )
        self.states: dict[str, LinkPhyState] = {}
        self._csi_mag_db: dict[tuple[int, int], list[float]] = {}
        self._ensure_states()

    def _ensure_states(self) -> None:
        for link_id in self.topology.links:
            if link_id not in self.states:
                rng = self.rng_registry.python(f"phy-init:{link_id}")
                self.states[link_id] = LinkPhyState(
                    link_id=link_id,
                    frequency_hz=self._parameters.get("frequency_hz", self.frequency_hz),
                    bandwidth_hz=self._parameters.get("bandwidth_hz", self.bandwidth_hz),
                    noise_power_dbm=self._parameters.get("noise_power_dbm", -89.0),
                    tx_power_dbm=self._parameters.get("tx_power_dbm", 23.0),
                    shadowing_std_db=self._parameters.get("shadowing_std_db", 2.0),
                    rician_k_db=self._parameters.get("rician_k_db", 10.0),
                    shadowing_db=rng.gauss(
                        0.0, self._parameters.get("shadowing_std_db", 2.0)
                    ),
                    fading_db=rng.gauss(0.0, 0.8),
                    channel_busy_ratio=max(0.0, min(1.0, rng.uniform(0.03, 0.12))),
                    calibration_profile_id=self.profile_id,
                    calibration_status=self.calibration_status,
                )

    def ensure_link(self, link: DirectedLink) -> LinkPhyState:
        self._ensure_states()
        return self.states[link.link_id]

    @staticmethod
    def _distance(first: Node, second: Node) -> float:
        return max(
            math.sqrt(
                sum(
                    (float(a) - float(b)) ** 2
                    for a, b in zip(first.position_xyz_m, second.position_xyz_m)
                )
            ),
            1.0,
        )

    @staticmethod
    def _fspl_db(distance_m: float, frequency_hz: float) -> float:
        return 20.0 * math.log10(
            4.0 * math.pi * distance_m * frequency_hz / 299_792_458.0
        )

    @staticmethod
    def _dbm_to_mw(power_dbm: float) -> float:
        return 10.0 ** (power_dbm / 10.0)

    def _evolve(self, state: LinkPhyState, sim_time_s: float) -> None:
        rng = self.rng_registry.python(f"phy-evolve:{state.link_id}")
        delta_s = max(0.0, sim_time_s - state.last_sample_time_s)
        rho = math.exp(-delta_s / 2.5) if delta_s else 0.96
        state.shadowing_db = rho * state.shadowing_db + math.sqrt(1 - rho**2) * rng.gauss(0, state.shadowing_std_db)
        state.fading_db = 0.72 * state.fading_db + math.sqrt(1 - 0.72**2) * rng.gauss(0, 0.8)
        natural_busy = 0.08 + rng.gauss(0.0, 0.025)
        state.channel_busy_ratio = max(0.0, min(0.75, 0.82 * state.channel_busy_ratio + 0.18 * natural_busy))
        state.measurement_quality = max(0.45, min(1.0, 0.96 + rng.gauss(0, 0.015)))
        state.last_sample_time_s = sim_time_s
        state.sample_count += 1

    def shared_csi_mag_db(self, src_id: int, dst_id: int) -> list[float]:
        """Noiseless |H[k]| in dB. Both directions of a link share one response."""
        pair = (src_id, dst_id) if src_id < dst_id else (dst_id, src_id)
        cached = self._csi_mag_db.get(pair)
        if cached is None:
            tap_rng = self.rng_registry.python(f"phy-csi-taps:{pair[0]}-{pair[1]}")
            cached = [
                round(value, 4)
                for value in frequency_response_db(
                    random_tdl_taps(tap_rng, CSI_N_TAPS),
                    CSI_N_SUBCARRIERS,
                )
            ]
            self._csi_mag_db[pair] = cached
        return cached

    def sample(
        self,
        link: DirectedLink,
        sender: Node,
        receiver: Node,
        sim_time_s: float,
        *,
        interference_power_dbm: float | None = None,
        natural_attenuation_db: float = 0.0,
        natural_loss_probability: float = 0.0,
        natural_busy_ratio_addition: float = 0.0,
        packet_size_bytes: int = 256,
        decode_attempt: bool = True,
    ) -> PhyOutcome:
        state = self.ensure_link(link)
        self._evolve(state, sim_time_s)
        rng = self.rng_registry.python(f"phy-sample:{link.link_id}")

        distance_m = self._distance(sender, receiver)
        path_loss_db = self._fspl_db(distance_m, state.frequency_hz)
        raw_rssi_dbm = (
            state.tx_power_dbm
            + 5.0
            + 5.0
            - path_loss_db
            - state.shadowing_db
            + state.fading_db
            - max(0.0, float(natural_attenuation_db))
        )
        rssi_bias_db = self._calibration_controls["rssi_bias_db"]
        snr_bias_db = self._calibration_controls["snr_bias_db"]
        rssi_dbm = raw_rssi_dbm + rssi_bias_db
        signal_mw = self._dbm_to_mw(rssi_dbm)
        # Adjusting effective noise by (RSSI bias - SNR bias) makes the two
        # calibrated observables independently controllable while preserving
        # the effect of real path loss, fading and generic interference.
        effective_noise_power_dbm = (
            state.noise_power_dbm + rssi_bias_db - snr_bias_db
        )
        noise_mw = self._dbm_to_mw(effective_noise_power_dbm)
        interference_mw = (
            self._dbm_to_mw(interference_power_dbm)
            if interference_power_dbm is not None
            else 0.0
        )
        snr_db = 10.0 * math.log10(signal_mw / noise_mw)
        sinr_db = 10.0 * math.log10(signal_mw / (noise_mw + interference_mw))
        physical_per = 1.0 / (
            1.0
            + math.exp(max(-60.0, min(60.0, 0.55 * (sinr_db - 7.5))))
        )
        natural_loss_probability = max(
            0.0, min(1.0, float(natural_loss_probability))
        )
        calibrated_loss = self._calibration_controls[
            "background_loss_probability"
        ]
        combined_background_loss = 1.0 - (
            (1.0 - natural_loss_probability) * (1.0 - calibrated_loss)
        )
        per = 1.0 - (1.0 - physical_per) * (1.0 - combined_background_loss)
        busy = min(
            1.0,
            state.channel_busy_ratio
            + (0.55 if interference_power_dbm is not None else 0.0),
            # ``min`` accepts multiple values; this extra term is included
            # below to keep normal congestion independent of attack truth.
        )
        busy = min(1.0, busy + max(0.0, float(natural_busy_ratio_addition)))
        quality = max(
            0.0,
            min(1.0, state.measurement_quality * (1.0 - 0.45 * busy)),
        )
        decode_success = bool(link.active and decode_attempt and rng.random() > per)
        estimated_interference = None
        if interference_power_dbm is not None:
            estimated_interference = interference_power_dbm + rng.gauss(0.0, 1.0)

        bandwidth_efficiency = max(0.0, min(6.0, math.log2(1.0 + 10 ** (sinr_db / 10))))
        throughput_mbps = state.bandwidth_hz * bandwidth_efficiency * (1.0 - per) / 1e6
        transmission_ms = (
            packet_size_bytes * 8.0 / max(throughput_mbps * 1e6, 1.0) * 1000.0
        )
        queue_component_ms = 0.05 + 1.2 * busy / max(0.05, 1.0 - busy)
        latency_rng = self.rng_registry.python(f"phy-latency:{link.link_id}")
        calibrated_latency_ms = max(
            0.0,
            latency_rng.gauss(
                self._calibration_controls["base_latency_ms"],
                self._calibration_controls["latency_jitter_ms"],
            ),
        )
        latency_ms = (
            transmission_ms
            + distance_m / 299_792_458.0 * 1000.0
            + queue_component_ms
            + calibrated_latency_ms
        )

        shared_csi = self.shared_csi_mag_db(link.src_id, link.dst_id)
        csi_noise_rng = self.rng_registry.python(f"phy-csi-noise:{link.link_id}")
        csi_mag_db = measure_csi_db(shared_csi, csi_noise_rng)
        observation = {
            "rssi_dbm": round(rssi_dbm, 4),
            "csi_mag_db": csi_mag_db,
            "snr_db": round(snr_db, 4),
            "sinr_db": round(sinr_db, 4),
            "noise_power_dbm": round(effective_noise_power_dbm, 4),
            "interference_power_dbm": (
                round(estimated_interference, 4) if estimated_interference is not None else None
            ),
            "per_estimate": round(per, 7),
            "decode_success": decode_success if decode_attempt else None,
            "channel_busy_ratio": round(busy, 5),
            "frequency_hz": state.frequency_hz,
            "bandwidth_hz": state.bandwidth_hz,
            "channel_id": state.channel_id,
            "measurement_quality": round(quality, 5),
        }
        truth = {
            "interference_power_dbm": interference_power_dbm,
            "path_loss_db": path_loss_db,
            "shadowing_db": state.shadowing_db,
            "fading_db": state.fading_db,
            "distance_m": distance_m,
            "csi_mag_db": list(shared_csi),
            "calibration_runtime_controls": dict(self._calibration_controls),
        }
        return PhyOutcome(
            observation=observation,
            decode_success=decode_success,
            latency_ms=round(latency_ms, 6),
            throughput_mbps=round(throughput_mbps, 6),
            truth=truth,
        )

    def passive_sample(
        self,
        link: DirectedLink,
        sender: Node,
        receiver: Node,
        sim_time_s: float,
        *,
        interference_power_dbm: float | None = None,
        natural_attenuation_db: float = 0.0,
        natural_loss_probability: float = 0.0,
        natural_busy_ratio_addition: float = 0.0,
    ) -> dict[str, Any]:
        return self.sample(
            link,
            sender,
            receiver,
            sim_time_s,
            interference_power_dbm=interference_power_dbm,
            natural_attenuation_db=natural_attenuation_db,
            natural_loss_probability=natural_loss_probability,
            natural_busy_ratio_addition=natural_busy_ratio_addition,
            decode_attempt=False,
        ).observation

    def switch_channel(self, link_id: str) -> dict[str, Any]:
        state = self.states[link_id]
        link = self.topology.links[link_id]
        new_frequency = state.frequency_hz + 20e6
        new_epoch = state.session_epoch + 1
        reciprocal = self.topology.get_link(link.dst_id, link.src_id)
        affected = [link_id]
        if reciprocal is not None and reciprocal.link_id in self.states:
            affected.append(reciprocal.link_id)
        for affected_id in affected:
            affected_state = self.states[affected_id]
            affected_state.session_epoch = new_epoch
            affected_state.frequency_hz = new_frequency
            affected_state.channel_id = f"ch-{int(new_frequency / 1e6)}"
        return {
            "link_id": link_id,
            "frequency_hz": state.frequency_hz,
            "channel_id": state.channel_id,
            "session_epoch": state.session_epoch,
            "reciprocal_link_id": reciprocal.link_id if reciprocal else None,
            "affected_link_ids": affected,
        }

    def reset(self) -> None:
        self.states.clear()
        self._csi_mag_db.clear()
        self._ensure_states()
