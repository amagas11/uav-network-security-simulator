import unittest

from tools.estimate_packet_size_bytes import estimate_packet_size_bytes
from tools.traffic_model import UavTrafficModel


class UavTrafficModelTests(unittest.TestCase):
    def test_packets_include_business_metadata_and_declared_sizes(self):
        model = UavTrafficModel(4, seed=17)
        packets = [model.next_packet(index) for index in range(1, 200)]

        payloads = [packet["payload_obj"] for packet in packets]
        traffic_types = {payload["traffic_type"] for payload in payloads}
        self.assertIn("C2_HEARTBEAT", traffic_types)
        self.assertIn("TELEMETRY", traffic_types)
        self.assertIn("MISSION_COMMAND", traffic_types)
        self.assertTrue(all(payload["payload_size_bytes"] > 0 for payload in payloads))
        self.assertTrue(all(payload["arrival_interval_s"] >= 0 for payload in payloads))

    def test_video_traffic_has_frame_level_bursts(self):
        model = UavTrafficModel(3, seed=23)
        video_payloads = []
        for index in range(1, 600):
            payload = model.next_packet(index)["payload_obj"]
            if payload["traffic_type"] == "VIDEO_FRAME":
                video_payloads.append(payload)

        self.assertGreater(len(video_payloads), 10)
        i_frame_sizes = [
            payload["payload_size_bytes"]
            for payload in video_payloads
            if payload["data"]["params"]["frame_type"] == "I"
        ]
        p_frame_sizes = [
            payload["payload_size_bytes"]
            for payload in video_payloads
            if payload["data"]["params"]["frame_type"] == "P"
        ]
        self.assertGreater(sum(i_frame_sizes) / len(i_frame_sizes),
                           sum(p_frame_sizes) / len(p_frame_sizes))

    def test_declared_payload_size_drives_packet_estimation(self):
        packet = {"payload_obj": {"payload_size_bytes": 5_000}}
        self.assertEqual(estimate_packet_size_bytes(packet), 5_068)

    def test_video_session_keeps_the_same_endpoints(self):
        model = UavTrafficModel(4, seed=31)
        active_endpoints = None
        checked_frames = 0

        for index in range(1, 1_000):
            payload = model.next_packet(index)["payload_obj"]
            command = payload["data"]["cmd"]
            if command == "VIDEO_STREAM" and payload["data"]["params"]["action"] == "start":
                active_endpoints = (payload["src"], payload["dst"])
            elif payload["traffic_type"] == "VIDEO_FRAME":
                self.assertEqual((payload["src"], payload["dst"]), active_endpoints)
                checked_frames += 1

        self.assertGreater(checked_frames, 10)


if __name__ == "__main__":
    unittest.main()
