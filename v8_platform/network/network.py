import heapq


class NetworkTopology:
    def __init__(self, num_nodes):
        self.num_nodes = num_nodes
        # 邻接矩阵：graph[u][v] = link_id (如果相连)
        # 这里的 link_id 就是你说的 "信道ID"
        self.adj_matrix = {}
        self.link_status = {}  # 记录链路健康状态: {link_id: True/False}
        # Generic channel interference retained for PHY experiments and normal
        # disturbances. It is not exposed as a DoS attack capability.
        self.link_interference_db = {}
        self.link_counter = 1

        # 初始化全连接网络 (Mesh)
        for i in range(num_nodes):
            self.adj_matrix[i] = {}
            for j in range(num_nodes):
                if i != j:
                    # 为每对节点分配唯一的链路ID
                    # 注意：无向图中 i-j 和 j-i 通常视为同一物理信道，但在通信中可能有不同频段
                    # 这里简化为：i->j 和 j->i 是不同的单向链路
                    self.adj_matrix[i][j] = self.link_counter
                    self.link_status[self.link_counter] = True  # 默认链路健康
                    self.link_interference_db[self.link_counter] = 0.0
                    self.link_counter += 1

    def get_path(self, src_id, dst_id):
        """
        Dijkstra 算法寻找最短路径（跳数最少）
        只使用状态为 True (健康) 的链路
        """
        queue = [(0, src_id, [])]  # (cost, current_node, path_of_links)
        visited = set()

        while queue:
            cost, u, path = heapq.heappop(queue)

            if u == dst_id:
                return path  # 返回链路ID列表，例如 [5, 8] 或 [9, 1, 2]

            if u in visited:
                continue
            visited.add(u)

            for v, link_id in self.adj_matrix[u].items():
                # 关键：只走健康的链路
                if self.link_status.get(link_id, False):
                    new_path = path + [link_id]
                    heapq.heappush(queue, (cost + 1, v, new_path))

        return None  # 无路可通

    def report_bad_link(self, link_id):
        """
        防御机制调用：标记某条链路已被干扰/攻破
        """
        print(f"      [Topo] 警告：链路 Link-{link_id} 被标记为不安全/阻塞！")
        self.link_status[link_id] = False

    def apply_interference(self, link_id, interference_above_noise_db=0.0):
        """Set generic link interference above the receiver noise floor."""
        if link_id in self.link_interference_db:
            self.link_interference_db[link_id] = max(
                0.0, float(interference_above_noise_db)
            )

    def clear_interference(self, link_id):
        """Clear generic link interference."""
        if link_id in self.link_interference_db:
            self.link_interference_db[link_id] = 0.0
