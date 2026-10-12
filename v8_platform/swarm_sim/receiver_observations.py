"""Bounded read-only receiver observations, never detector/defense inputs."""
from collections import deque
from copy import deepcopy


class ReceiverRateObservations:
    def __init__(self, target_ids, window_s, threshold_pps, capacity=320):
        self.window_s = window_s
        self.threshold_pps = threshold_pps
        self.capacity = capacity
        self.arrivals = {node: deque() for node in target_ids}
        self.samples = {node: deque(maxlen=capacity) for node in target_ids}
        self.peaks = {node: 0.0 for node in target_ids}

    def arrival(self, node_id, now_s, actual_statistics):
        if node_id not in self.arrivals:
            return
        self.arrivals[node_id].append(now_s)
        # Exact value returned by the existing pre-HMAC detector accumulator.
        self.peaks[node_id] = max(self.peaks[node_id], actual_statistics['packet_rate_pps'])

    def sample(self, now_s):
        for node, arrivals in self.arrivals.items():
            while arrivals and arrivals[0] < now_s - self.window_s:
                arrivals.popleft()
            point = {'sim_time_s': now_s, 'packet_rate_pps': round(len(arrivals) / self.window_s, 6),
                     'total_packet_count': len(arrivals), 'statistics_window_s': self.window_s,
                     'flooding_threshold_pps': self.threshold_pps}
            if self.samples[node] and self.samples[node][-1]['sim_time_s'] == now_s:
                self.samples[node][-1] = point
            else:
                self.samples[node].append(point)

    def snapshot(self):
        return {'scope': 'TARGET_RECEIVER_RUNTIME_OBSERVATIONS',
                'sampling': 'END_OF_SIMULATION_TICK', 'capacity_per_node': self.capacity,
                'nodes': [{'node_id': node, 'samples': deepcopy(list(samples)),
                           'peak_window_rate_pps': self.peaks[node],
                           'statistics_window_s': self.window_s}
                          for node, samples in self.samples.items()]}
