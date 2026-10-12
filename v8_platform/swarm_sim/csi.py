"""Simple frequency-domain CSI for a reciprocal link.

Tapped-delay-line taps are shared by both directions of a link. Each receiver
adds its own noise when the PHY samples the link. This is an uncalibrated
simulation channel, not a measured 5G NR CSI report.
"""

from __future__ import annotations

import cmath
import math
import random


CSI_N_SUBCARRIERS = 64
CSI_N_TAPS = 4


def random_tdl_taps(rng: random.Random, n_taps: int = CSI_N_TAPS) -> list[complex]:
    """Independent complex-Gaussian taps with exponential power decay."""
    taps: list[complex] = []
    for index in range(n_taps):
        std = math.sqrt((0.5 ** index) / 2.0)
        taps.append(complex(rng.gauss(0.0, std), rng.gauss(0.0, std)))
    return taps


def frequency_response_db(taps: list[complex], n_subcarriers: int = CSI_N_SUBCARRIERS) -> list[float]:
    """DFT of the taps. Returns |H[k]| in dB, one value per subcarrier."""
    magnitudes: list[float] = []
    for bin_index in range(n_subcarriers):
        response = 0j
        for tap_index, tap in enumerate(taps):
            response += tap * cmath.exp(-2j * math.pi * bin_index * tap_index / n_subcarriers)
        magnitude = abs(response)
        magnitudes.append(20.0 * math.log10(magnitude) if magnitude > 1e-12 else -120.0)
    return magnitudes


def measure_csi_db(
    shared_mag_db: list[float],
    noise_rng: random.Random,
    noise_std_db: float = 0.3,
) -> list[float]:
    """Receiver-local |H[k]|: shared frequency response plus independent noise."""
    return [
        round(value + noise_rng.gauss(0.0, noise_std_db), 4)
        for value in shared_mag_db
    ]
