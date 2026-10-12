"""A1 局部观测、合成互易 RSSI、合成 Eve。

数据是算法自造的：合法两端共享衰落 + 独立噪声；Eve 另抽弱相关/不相关信道。
合成、未用实测、未校准、未接入仿真，不要当成 NRChannel 输出。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Mapping


FREQ_HZ_BASELINE = 3.5e9


@dataclass(frozen=True, slots=True)
class LocalPhyObservation:
    local_id: int
    peer_id: int
    session_id: str
    probe_id: str
    sim_time_s: float
    freq_hz: float
    role: str
    measurement_kind: str
    measurement: tuple[float, ...]
    snr_db: float | None
    noise_var: float | None
    missing: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> LocalPhyObservation:
        measurement = data.get("measurement") or ()
        leftover = dict(data.get("quality") or {})
        snr_raw = data.get("snr_db", leftover.pop("snr_db", None))
        missing = bool(data.get("missing", False)) or leftover.get("valid") is False
        return cls(
            local_id=int(data["local_id"]),
            peer_id=int(data["peer_id"]),
            session_id=str(data["session_id"]),
            probe_id=str(data["probe_id"]),
            sim_time_s=float(data.get("sim_time_s", 0.0)),
            freq_hz=float(data.get("freq_hz", FREQ_HZ_BASELINE)),
            role=str(data.get("role", "rx")),
            measurement_kind=str(data.get("measurement_kind", "rssi_dbm")),
            measurement=tuple(float(x) for x in measurement),
            snr_db=None if snr_raw is None else float(snr_raw),
            noise_var=None if data.get("noise_var") is None else float(data["noise_var"]),
            missing=missing,
        )


def _rssi_observation(
    *,
    local_id: int,
    peer_id: int,
    session_id: str,
    probe_id: str,
    measurement: list[float],
    missing: bool,
    role: str,
    sim_time_s: float,
    noise_var: float | None,
    snr_db: float | None = None,
) -> LocalPhyObservation:
    return LocalPhyObservation(
        local_id=local_id,
        peer_id=peer_id,
        session_id=session_id,
        probe_id=probe_id,
        sim_time_s=sim_time_s,
        freq_hz=FREQ_HZ_BASELINE,
        role=role,
        measurement_kind="rssi_dbm",
        measurement=tuple(measurement),
        snr_db=snr_db,
        noise_var=noise_var,
        missing=missing,
    )


def synthesize_reciprocal_rssi(
    local_id: int,
    peer_id: int,
    session_id: str,
    probe_id: str,
    *,
    n_samples: int = 64,
    seed: int = 0,
    peer_scrambled: bool = False,
    local_missing: bool = False,
    peer_missing: bool = False,
    sim_time_s: float = 12.04,
    noise_std_db: float = 0.3,
) -> tuple[LocalPhyObservation, LocalPhyObservation]:
    """构造一对合成互易 RSSI。两端相关、噪声独立，禁止把一端数组复制给另一端。"""
    rng = random.Random(seed)
    channel = [-60.0 if rng.randint(0, 1) else -80.0 for _ in range(n_samples)]

    def _noisy(source: list[float], noise_rng: random.Random) -> list[float]:
        return [value + noise_rng.gauss(0.0, noise_std_db) for value in source]

    meas_local = _noisy(channel, random.Random(seed + 1))
    if peer_scrambled:
        other = [-60.0 if rng.randint(0, 1) else -80.0 for _ in range(n_samples)]
        meas_peer = _noisy(other, random.Random(seed + 99))
    else:
        meas_peer = _noisy(channel, random.Random(seed + 2))

    obs_local = _rssi_observation(
        local_id=local_id,
        peer_id=peer_id,
        session_id=session_id,
        probe_id=probe_id,
        measurement=[] if local_missing else meas_local,
        missing=local_missing,
        role="rx",
        sim_time_s=sim_time_s,
        noise_var=None,
    )
    obs_peer = _rssi_observation(
        local_id=peer_id,
        peer_id=local_id,
        session_id=session_id,
        probe_id=probe_id,
        measurement=[] if peer_missing else meas_peer,
        missing=peer_missing,
        role="tx",
        sim_time_s=sim_time_s,
        noise_var=None,
    )
    return obs_local, obs_peer


def _two_level_channel(rng: random.Random, n_samples: int) -> list[float]:
    return [-60.0 if rng.randint(0, 1) else -80.0 for _ in range(n_samples)]


def _add_gauss_noise(source: list[float], noise_rng: random.Random, noise_std_db: float) -> list[float]:
    return [value + noise_rng.gauss(0.0, noise_std_db) for value in source]


def synthesize_eve_rssi(
    eve_id: int,
    peer_id: int,
    session_id: str,
    probe_id: str,
    *,
    n_samples: int = 64,
    seed: int = 0,
    legitimate_seed: int | None = None,
    correlation: str = "uncorrelated",
    sim_time_s: float = 12.04,
    noise_std_db: float = 0.3,
) -> LocalPhyObservation:
    """合成 Eve 观测：同一 probe_id，local_id 为窃听者。

    量测从独立（或弱相关）信道抽出，禁止复制 Alice/Bob 的 measurement 再加一点点噪。
    合成 Eve、未用实测、未接入仿真。
    """
    if correlation not in {"uncorrelated", "weak"}:
        raise ValueError("correlation must be 'uncorrelated' or 'weak'")
    if eve_id == peer_id:
        raise ValueError("eve_id must differ from peer_id")

    eve_channel_rng = random.Random(seed ^ 0xE5E5E5E5)
    independent = _two_level_channel(eve_channel_rng, n_samples)
    if correlation == "weak":
        legit_seed = seed if legitimate_seed is None else legitimate_seed
        shared = _two_level_channel(random.Random(legit_seed), n_samples)
        mix_rng = random.Random(seed + 4242)
        # 弱相关：偶发对齐共享衰落，主体仍是独立信道；不是 Alice 数组加噪。
        channel = [
            shared[i] if mix_rng.random() < 0.2 else independent[i] for i in range(n_samples)
        ]
    else:
        channel = independent

    measurement = _add_gauss_noise(channel, random.Random(seed + 10007), noise_std_db)
    return _rssi_observation(
        local_id=eve_id,
        peer_id=peer_id,
        session_id=session_id,
        probe_id=probe_id,
        measurement=measurement,
        missing=False,
        role="rx",
        sim_time_s=sim_time_s,
        noise_var=None,
    )


def synthesize_reciprocal_rssi_with_eve(
    local_id: int,
    peer_id: int,
    eve_id: int,
    session_id: str,
    probe_id: str,
    *,
    n_samples: int = 64,
    seed: int = 0,
    correlation: str = "uncorrelated",
    sim_time_s: float = 12.04,
    noise_std_db: float = 0.3,
) -> tuple[LocalPhyObservation, LocalPhyObservation, LocalPhyObservation]:
    """合法互易一对 + 合成 Eve。Eve 与合法信道不相关或弱相关；未用实测、未接入仿真。"""
    obs_local, obs_peer = synthesize_reciprocal_rssi(
        local_id,
        peer_id,
        session_id,
        probe_id,
        n_samples=n_samples,
        seed=seed,
        sim_time_s=sim_time_s,
        noise_std_db=noise_std_db,
    )
    obs_eve = synthesize_eve_rssi(
        eve_id,
        local_id,
        session_id,
        probe_id,
        n_samples=n_samples,
        seed=seed,
        legitimate_seed=seed,
        correlation=correlation,
        sim_time_s=sim_time_s,
        noise_std_db=noise_std_db,
    )
    return obs_local, obs_peer, obs_eve

