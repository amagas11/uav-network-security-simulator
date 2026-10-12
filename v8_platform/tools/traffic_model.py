import math
import random

from .calculate_signature import calculate_signature


class UavTrafficModel:
    """Business-aware synthetic traffic for the UAV simulation."""

    DEFAULT_PROFILE = {
        "heartbeat_interval_s": 1.0,
        "telemetry_interval_s": 0.2,
        "telemetry_jitter_std_s": 0.01,
        "mission_mean_interval_s": 2.5,
        "alert_mean_interval_s": 60.0,
        "video_fps": 30,
        "video_bitrate_bps": 2_000_000,
        "video_gop_frames": 30,
        "video_i_frame_multiplier": 4.0,
        "video_mean_on_duration_s": 8.0,
    }

    def __init__(self, num_nodes, profile=None, seed=None):
        self.profile = dict(self.DEFAULT_PROFILE)
        if profile:
            self.profile.update(profile)
        self.rng = random.Random(seed)
        self.reset(num_nodes)

    def reset(self, num_nodes=None):
        if num_nodes is not None:
            self.num_nodes = max(int(num_nodes), 2)

        self.simulation_time_s = 0.0
        self.flight_state = "GROUNDED"
        self.video_enabled = False
        self.video_frame_index = 0
        self.video_endpoints = None
        self.next_due_s = {
            "heartbeat": self.profile["heartbeat_interval_s"],
            "telemetry": self._periodic_delay(
                self.profile["telemetry_interval_s"],
                self.profile["telemetry_jitter_std_s"]),
            "mission": self._exponential_delay(
                self.profile["mission_mean_interval_s"]),
            "alert": self._exponential_delay(
                self.profile["alert_mean_interval_s"]),
            "video_frame": math.inf,
            "video_stop": math.inf,
        }

    def next_packet(self, sequence):
        source_name, due_time_s = min(
            self.next_due_s.items(), key=lambda item: item[1])
        arrival_interval_s = max(0.0, due_time_s - self.simulation_time_s)
        self.simulation_time_s = due_time_s

        if source_name == "heartbeat":
            event = self._heartbeat_event()
            self.next_due_s["heartbeat"] = (
                self.simulation_time_s + self.profile["heartbeat_interval_s"])
        elif source_name == "telemetry":
            event = self._telemetry_event()
            self.next_due_s["telemetry"] = self.simulation_time_s + self._periodic_delay(
                self.profile["telemetry_interval_s"],
                self.profile["telemetry_jitter_std_s"])
        elif source_name == "mission":
            event = self._mission_event()
            self.next_due_s["mission"] = self.simulation_time_s + self._exponential_delay(
                self.profile["mission_mean_interval_s"])
        elif source_name == "alert":
            event = self._alert_event()
            self.next_due_s["alert"] = self.simulation_time_s + self._exponential_delay(
                self.profile["alert_mean_interval_s"])
        elif source_name == "video_frame":
            event = self._video_frame_event()
            self.next_due_s["video_frame"] = (
                self.simulation_time_s + 1.0 / self.profile["video_fps"])
        else:
            event = self._stop_video_event()

        return self._build_packet(sequence, arrival_interval_s, **event)

    def _heartbeat_event(self):
        return {
            "traffic_type": "C2_HEARTBEAT",
            "arrival_model": "periodic",
            "payload_size_bytes": 24,
            "data": {"cmd": "HEARTBEAT", "params": {"state": self.flight_state}},
        }

    def _telemetry_event(self):
        return {
            "traffic_type": "TELEMETRY",
            "arrival_model": "periodic_jittered",
            "payload_size_bytes": self.rng.randint(84, 140),
            "data": {
                "cmd": "TELEMETRY",
                "params": {
                    "battery_pct": round(self.rng.uniform(35.0, 100.0), 1),
                    "flight_state": self.flight_state,
                },
            },
        }

    def _mission_event(self):
        prior_state = self.flight_state
        endpoints = None
        if prior_state == "GROUNDED":
            self.flight_state = "TAKING_OFF"
            data = {"cmd": "TAKEOFF", "params": {"alt": self._altitude()}}
            payload_size_bytes = 100
        elif prior_state == "TAKING_OFF":
            self.flight_state = "FLYING"
            data = {"cmd": "FLY_TO", "params": {"target": self._target()}}
            payload_size_bytes = 120
        elif prior_state in {"FLYING", "HOVERING"} and self.video_enabled:
            endpoints = self.video_endpoints
            data = self._stop_video_data()
            payload_size_bytes = 100
        elif prior_state in {"FLYING", "HOVERING"} and self.rng.random() < 0.2:
            data = self._start_video_data()
            endpoints = self.video_endpoints
            payload_size_bytes = 100
        elif prior_state == "FLYING" and self.rng.random() < 0.28:
            self.flight_state = "HOVERING"
            data = {"cmd": "HOVER", "params": {"mode": "hold"}}
            payload_size_bytes = 80
        elif prior_state == "HOVERING" and self.rng.random() < 0.35:
            self.flight_state = "GROUNDED"
            data = {"cmd": "LAND", "params": {"alt": 0}}
            payload_size_bytes = 100
        else:
            self.flight_state = "FLYING"
            data = {"cmd": "FLY_TO", "params": {"target": self._target()}}
            payload_size_bytes = 120

        return {
            "traffic_type": "MISSION_COMMAND",
            "arrival_model": "poisson_markov_state",
            "payload_size_bytes": payload_size_bytes,
            "data": data,
            "prior_flight_state": prior_state,
            "endpoints": endpoints,
        }

    def _alert_event(self):
        return {
            "traffic_type": "ALERT",
            "arrival_model": "poisson_rare_event",
            "payload_size_bytes": self.rng.randint(64, 128),
            "data": {
                "cmd": "ALERT",
                "params": {"code": self.rng.choice(["LOW_BATTERY", "LINK_QUALITY"])},
            },
        }

    def _video_frame_event(self):
        frame_type = "I" if self.video_frame_index % self.profile["video_gop_frames"] == 0 else "P"
        frame_size_bytes = self._video_frame_size_bytes(frame_type)
        self.video_frame_index += 1
        return {
            "traffic_type": "VIDEO_FRAME",
            "arrival_model": "on_off_frame_stream",
            "payload_size_bytes": frame_size_bytes,
            "endpoints": self.video_endpoints,
            "data": {
                "cmd": "VIDEO_FRAME",
                "params": {"frame_type": frame_type, "frame_index": self.video_frame_index},
            },
        }

    def _stop_video_event(self):
        endpoints = self.video_endpoints
        return {
            "traffic_type": "MISSION_COMMAND",
            "arrival_model": "on_off_transition",
            "payload_size_bytes": 100,
            "endpoints": endpoints,
            "data": self._stop_video_data(),
        }

    def _start_video_data(self):
        self.video_enabled = True
        self.video_frame_index = 0
        self.video_endpoints = self._endpoints()
        self.next_due_s["video_frame"] = (
            self.simulation_time_s + 1.0 / self.profile["video_fps"])
        self.next_due_s["video_stop"] = self.simulation_time_s + self._exponential_delay(
            self.profile["video_mean_on_duration_s"])
        return {
            "cmd": "VIDEO_STREAM",
            "params": {
                "action": "start",
                "res": "480p",
                "fps": self.profile["video_fps"],
                "coding": "H.264",
            },
        }

    def _stop_video_data(self):
        self.video_enabled = False
        self.video_endpoints = None
        self.next_due_s["video_frame"] = math.inf
        self.next_due_s["video_stop"] = math.inf
        return {"cmd": "VIDEO_STREAM", "params": {"action": "stop"}}

    def _build_packet(self, sequence, arrival_interval_s, traffic_type,
                      arrival_model, payload_size_bytes, data,
                      prior_flight_state=None, endpoints=None):
        src, dst = endpoints or self._endpoints()
        traffic_profile = {
            "arrival_model": arrival_model,
            "flight_state": self.flight_state,
            "video_enabled": self.video_enabled,
        }
        if prior_flight_state is not None:
            traffic_profile["prior_flight_state"] = prior_flight_state

        payload = {
            "ver": 1,
            "seq": sequence,
            "src": src,
            "dst": dst,
            "timestamp": round(self.simulation_time_s, 6),
            "is_encrypted": False,
            "traffic_type": traffic_type,
            "traffic_profile": traffic_profile,
            "payload_size_bytes": int(payload_size_bytes),
            "simulation_time_s": round(self.simulation_time_s, 6),
            "arrival_interval_s": round(arrival_interval_s, 6),
            "data": data,
            "signature": "",
        }
        payload["signature"] = calculate_signature(payload)
        return {"seq": sequence, "payload_obj": payload}

    def _video_frame_size_bytes(self, frame_type):
        mean_frame_bytes = (
            self.profile["video_bitrate_bps"] / 8.0 / self.profile["video_fps"])
        gop_size = self.profile["video_gop_frames"]
        i_frame_multiplier = self.profile["video_i_frame_multiplier"]
        base_mean = mean_frame_bytes * gop_size / (
            (gop_size - 1) + i_frame_multiplier)
        target_mean = base_mean * i_frame_multiplier if frame_type == "I" else base_mean
        shape = 4.0
        return max(256, int(self.rng.gammavariate(shape, target_mean / shape)))

    def _periodic_delay(self, interval_s, jitter_std_s):
        return max(0.001, interval_s + self.rng.gauss(0.0, jitter_std_s))

    def _exponential_delay(self, mean_interval_s):
        return self.rng.expovariate(1.0 / max(mean_interval_s, 0.001))

    def _altitude(self):
        return round(max(10.0, self.rng.gauss(100.0, 20.0)), 1)

    def _target(self):
        return [
            round(max(0.0, self.rng.gauss(250.0, 100.0)), 1),
            round(max(0.0, self.rng.gauss(250.0, 100.0)), 1),
            self._altitude(),
        ]

    def _endpoints(self):
        src = self.rng.randrange(self.num_nodes)
        dst = self.rng.randrange(self.num_nodes - 1)
        if dst >= src:
            dst += 1
        return src, dst
