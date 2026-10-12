import random
import unittest

from NRChannel.NRChannel import NRChannel
from UAVNode.UAVNode import UAVNode
from network.network import NetworkTopology


class StaticUavChannelTests(unittest.TestCase):
    def setUp(self):
        self.topology = NetworkTopology(2)
        self.src = UAVNode(0, (0, 0, 100))
        self.dst = UAVNode(1, (100, 0, 100))

    def test_python_fallback_returns_physical_components(self):
        random.seed(7)
        channel = NRChannel(self.topology, self.src, self.dst, matlab_eng=None)

        path_loss_db = channel.calculate_path_loss_matlab()
        meta = channel.last_propagation_meta

        self.assertEqual(meta["propagation_model"], "python_static_a2a")
        self.assertGreater(meta["fspl_db"], 0.0)
        self.assertEqual(meta["rician_k_factor_db"], 10.0)
        self.assertAlmostEqual(path_loss_db, meta["total_path_loss_db"], places=2)

    def test_interference_is_combined_with_noise_in_linear_power(self):
        channel = NRChannel(self.topology, self.src, self.dst, matlab_eng=None)

        _, snr_db = channel.calculate_sinr(path_loss=100.0)
        _, sinr_db = channel.calculate_sinr(
            path_loss=100.0,
            interference_power_dbm=channel.noise_floor_dbm + 30.0,
        )

        self.assertGreater(snr_db - sinr_db, 29.9)
        self.assertLess(snr_db - sinr_db, 30.1)


if __name__ == "__main__":
    unittest.main()
