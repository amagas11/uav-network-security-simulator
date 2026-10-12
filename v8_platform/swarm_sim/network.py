"""Role-aware directed topology and route calculation."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable

from .domain import NodeRole


@dataclass(slots=True)
class DirectedLink:
    link_id: str
    src_id: int
    dst_id: int
    active: bool = True


class FormationTopology:
    """Topology truth owned by the simulator, never by ordinary nodes."""

    def __init__(self, roles: dict[int, NodeRole]) -> None:
        self.roles = dict(roles)
        self.links: dict[str, DirectedLink] = {}
        self._outgoing: dict[int, dict[int, str]] = {node_id: {} for node_id in roles}
        self.version = 1
        self._build_default_formation()

    def _build_default_formation(self) -> None:
        gcs_ids = sorted(node_id for node_id, role in self.roles.items() if role == NodeRole.GCS)
        leader_ids = sorted(
            node_id for node_id, role in self.roles.items() if role == NodeRole.LEADER
        )
        follower_ids = sorted(
            node_id for node_id, role in self.roles.items() if role == NodeRole.FOLLOWER
        )
        primary_gcs = gcs_ids[0]
        primary_leader = leader_ids[0]
        self.add_bidirectional(primary_gcs, primary_leader)
        for extra_leader in leader_ids[1:]:
            self.add_bidirectional(primary_gcs, extra_leader)
        for follower_id in follower_ids:
            self.add_bidirectional(primary_leader, follower_id)

    @staticmethod
    def link_id(src_id: int, dst_id: int) -> str:
        return f"link-{src_id}-{dst_id}"

    def add_link(self, src_id: int, dst_id: int, *, active: bool = True) -> str:
        if src_id == dst_id:
            raise ValueError("self-links are not supported")
        self._outgoing.setdefault(src_id, {})
        self._outgoing.setdefault(dst_id, {})
        link_id = self.link_id(src_id, dst_id)
        self.links[link_id] = DirectedLink(link_id, src_id, dst_id, active)
        self._outgoing[src_id][dst_id] = link_id
        self.version += 1
        return link_id

    def add_bidirectional(self, first: int, second: int, *, active: bool = True) -> None:
        self.add_link(first, second, active=active)
        self.add_link(second, first, active=active)

    def ensure_external_ingress(self, external_id: int, target_ids: Iterable[int]) -> None:
        for target_id in target_ids:
            if self.link_id(external_id, target_id) not in self.links:
                self.add_bidirectional(external_id, target_id)

    def get_link(self, src_id: int, dst_id: int) -> DirectedLink | None:
        link_id = self._outgoing.get(src_id, {}).get(dst_id)
        return self.links.get(link_id) if link_id else None

    def set_link_active(self, link_id: str, active: bool) -> None:
        if link_id not in self.links:
            raise KeyError(f"unknown link: {link_id}")
        self.links[link_id].active = bool(active)
        self.version += 1

    def set_bidirectional_active(self, first: int, second: int, active: bool) -> None:
        for src_id, dst_id in ((first, second), (second, first)):
            link = self.get_link(src_id, dst_id)
            if link:
                self.set_link_active(link.link_id, active)

    def route(self, src_id: int, dst_id: int) -> list[int] | None:
        if src_id == dst_id:
            return [src_id]
        queue: deque[list[int]] = deque([[src_id]])
        visited = {src_id}
        while queue:
            path = queue.popleft()
            current = path[-1]
            for neighbor_id in sorted(self._outgoing.get(current, {})):
                link = self.get_link(current, neighbor_id)
                if link is None or not link.active or neighbor_id in visited:
                    continue
                candidate = [*path, neighbor_id]
                if neighbor_id == dst_id:
                    return candidate
                visited.add(neighbor_id)
                queue.append(candidate)
        return None

    def links_for_route(self, route: list[int]) -> list[str]:
        result: list[str] = []
        for src_id, dst_id in zip(route, route[1:]):
            link = self.get_link(src_id, dst_id)
            if link is None:
                raise ValueError(f"route contains no direct link: {src_id}->{dst_id}")
            result.append(link.link_id)
        return result

    def direct_neighbors(self, node_id: int, *, active_only: bool = True) -> list[int]:
        result: list[int] = []
        for neighbor_id, link_id in self._outgoing.get(node_id, {}).items():
            if not active_only or self.links[link_id].active:
                result.append(neighbor_id)
        return sorted(result)

    def snapshot(self) -> dict[str, object]:
        return {
            "version": self.version,
            "links": [
                {
                    "link_id": link.link_id,
                    "src_id": link.src_id,
                    "dst_id": link.dst_id,
                    "active": link.active,
                }
                for link in sorted(self.links.values(), key=lambda item: item.link_id)
            ],
        }

