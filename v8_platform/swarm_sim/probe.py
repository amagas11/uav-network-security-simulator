"""Direct-neighbor reciprocal PHY probes for A's future SKG module."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from .domain import Node
from .network import FormationTopology
from .phy import PersistentPhyModel
from .simulation import RunContext


V8_DEFAULT_PROBE_PROFILE = "V8_DEFAULT"
PERSON_A_V01_COMPAT_PROBE_PROFILE = "PERSON_A_V01_COMPAT_TEST"
SUPPORTED_PROBE_PROFILES = frozenset(
    {V8_DEFAULT_PROBE_PROFILE, PERSON_A_V01_COMPAT_PROBE_PROFILE}
)


@dataclass(slots=True)
class LocalPhyObservation:
    local_id: int
    peer_id: int
    session_id: str
    probe_id: str
    sim_time_s: float
    freq_hz: float
    role: Literal["tx", "rx"]
    measurement_kind: Literal["rssi_dbm", "csi"]
    measurement: list[float] | None
    snr_db: float | None
    noise_var: float | None
    missing: bool
    missing_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProbeService:
    """Produces paired local observations from a shared latent channel.

    Neither terminal's vector is derived from the other terminal's vector.
    Both are generated as ``latent + independent receiver noise``.
    """

    def __init__(
        self,
        context: RunContext,
        topology: FormationTopology,
        phy: PersistentPhyModel,
        nodes: dict[int, Node],
        *,
        profile: str = V8_DEFAULT_PROBE_PROFILE,
    ) -> None:
        if profile not in SUPPORTED_PROBE_PROFILES:
            raise ValueError(f"UNSUPPORTED_PROBE_PROFILE:{profile}")
        self.context = context
        self.topology = topology
        self.phy = phy
        self.nodes = nodes
        self.profile = profile

    def probe(
        self,
        first_id: int,
        second_id: int,
        *,
        sample_count: int = 16,
        session_id: str | None = None,
        measurement_kind: Literal["rssi_dbm", "csi"] = "rssi_dbm",
    ) -> tuple[LocalPhyObservation, LocalPhyObservation]:
        if measurement_kind not in {"rssi_dbm", "csi"}:
            raise ValueError(f"UNSUPPORTED_MEASUREMENT_KIND:{measurement_kind}")
        if measurement_kind == "rssi_dbm" and sample_count < 2:
            raise ValueError("sample_count must be at least 2")
        probe_id = self.context.ids.next("prb")
        forward = self.topology.get_link(first_id, second_id)
        reverse = self.topology.get_link(second_id, first_id)
        state = self.phy.states.get(forward.link_id) if forward else None
        frequency_hz = state.frequency_hz if state else 3.5e9
        # The caller may bind a probe to an existing business-security
        # session.  Default generation remains backward compatible.
        session_id = session_id or self.context.ids.next("sess")
        usable = (
            first_id in self.nodes
            and second_id in self.nodes
            and forward is not None
            and reverse is not None
            and forward.active
            and reverse.active
        )
        if not usable:
            return (
                self._missing(first_id, second_id, session_id, probe_id, frequency_hz, "tx", "NOT_DIRECT_ACTIVE_NEIGHBORS", measurement_kind),
                self._missing(second_id, first_id, session_id, probe_id, frequency_hz, "rx", "NOT_DIRECT_ACTIVE_NEIGHBORS", measurement_kind),
            )
        reverse_state = self.phy.states[reverse.link_id]
        if abs(float(state.frequency_hz) - float(reverse_state.frequency_hz)) > 1e-6:
            return (
                self._missing(first_id, second_id, session_id, probe_id, state.frequency_hz, "tx", "FREQUENCY_MISMATCH", measurement_kind),
                self._missing(second_id, first_id, session_id, probe_id, reverse_state.frequency_hz, "rx", "FREQUENCY_MISMATCH", measurement_kind),
            )

        first_noise_rng = self.context.rng.python(f"probe-noise:{probe_id}:{first_id}")
        second_noise_rng = self.context.rng.python(f"probe-noise:{probe_id}:{second_id}")
        first = self.nodes[first_id]
        second = self.nodes[second_id]
        if measurement_kind == "csi":
            shared = self.phy.shared_csi_mag_db(first_id, second_id)
            threshold = sum(shared) / len(shared)
            # Exact syndrome match cannot tolerate bits that flip near the mean.
            # Keep the platform frequency-response shape, then separate it into
            # two levels before adding each receiver's noise.
            latent = [10.0 if value >= threshold else -10.0 for value in shared]
            first_noise_var = 0.0225
            second_noise_var = 0.0324
        else:
            latent_rng = self.context.rng.python(f"probe-latent:{probe_id}")
            base_outcome = self.phy.sample(
                forward,
                first,
                second,
                self.context.clock.now_s,
                decode_attempt=False,
            )
            base_rssi = float(base_outcome.observation["rssi_dbm"])
            if self.profile == V8_DEFAULT_PROBE_PROFILE:
                # Frozen V8 behavior used by normal simulation, calibration and
                # attack experiments.  Do not tune this distribution for a
                # particular upstream SKG implementation.
                latent = [
                    base_rssi + latent_rng.gauss(0.0, 1.25)
                    for _ in range(sample_count)
                ]
            else:
                # TEST ONLY compatibility profile for Person-A v0.1's exact-match
                # mean-threshold quantizer.  It remains a real V8 ProbeService
                # observation, but its deliberately separated channel states are
                # not calibration/formal-experiment evidence.
                latent = [
                    base_rssi
                    + (8.0 if latent_rng.random() >= 0.5 else -8.0)
                    + latent_rng.gauss(0.0, 0.35)
                    for _ in range(sample_count)
                ]
            first_noise_var = 0.18
            second_noise_var = 0.22
        first_measurement = [
            round(value + first_noise_rng.gauss(0.0, first_noise_var**0.5), 6)
            for value in latent
        ]
        second_measurement = [
            round(value + second_noise_rng.gauss(0.0, second_noise_var**0.5), 6)
            for value in latent
        ]
        # Each endpoint estimates SNR from its own receiver-side measurement
        # and local receiver noise floor.  The estimates share the reciprocal
        # latent channel but neither value is copied from the forward packet
        # observation (or from the peer's estimate).
        forward_state = self.phy.states[forward.link_id]
        first_snr = round(
            sum(first_measurement) / len(first_measurement)
            - reverse_state.noise_power_dbm,
            6,
        )
        second_snr = round(
            sum(second_measurement) / len(second_measurement)
            - forward_state.noise_power_dbm,
            6,
        )
        now_s = self.context.clock.now_s
        return (
            LocalPhyObservation(
                local_id=first_id,
                peer_id=second_id,
                session_id=session_id,
                probe_id=probe_id,
                sim_time_s=now_s,
                freq_hz=frequency_hz,
                role="tx",
                measurement_kind=measurement_kind,
                measurement=first_measurement,
                snr_db=first_snr,
                noise_var=first_noise_var,
                missing=False,
                missing_reason=None,
            ),
            LocalPhyObservation(
                local_id=second_id,
                peer_id=first_id,
                session_id=session_id,
                probe_id=probe_id,
                sim_time_s=now_s,
                freq_hz=frequency_hz,
                role="rx",
                measurement_kind=measurement_kind,
                measurement=second_measurement,
                snr_db=second_snr,
                noise_var=second_noise_var,
                missing=False,
                missing_reason=None,
            ),
        )

    def _missing(
        self,
        local_id: int,
        peer_id: int,
        session_id: str,
        probe_id: str,
        frequency_hz: float,
        role: Literal["tx", "rx"],
        reason: str,
        measurement_kind: Literal["rssi_dbm", "csi"] = "rssi_dbm",
    ) -> LocalPhyObservation:
        return LocalPhyObservation(
            local_id=local_id,
            peer_id=peer_id,
            session_id=session_id,
            probe_id=probe_id,
            sim_time_s=self.context.clock.now_s,
            freq_hz=frequency_hz,
            role=role,
            measurement_kind=measurement_kind,
            measurement=None,
            snr_db=None,
            noise_var=None,
            missing=True,
            missing_reason=reason,
        )
