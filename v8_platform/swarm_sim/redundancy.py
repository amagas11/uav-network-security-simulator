"""Logical redundancy baseline; not a claim of software heterogeneity."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from typing import Any, Callable


@dataclass(slots=True)
class Replica:
    replica_id: str
    executor: Callable[[Any], Any]
    weight: float = 1.0
    healthy: bool = True
    failure_reason: str | None = None

    def run(self, value: Any) -> dict[str, Any]:
        if not self.healthy:
            return {
                "replica_id": self.replica_id,
                "status": "FAILED",
                "output": None,
                "failure_reason": self.failure_reason or "REPLICA_UNHEALTHY",
                "weight": self.weight,
            }
        try:
            return {
                "replica_id": self.replica_id,
                "status": "OK",
                "output": self.executor(value),
                "failure_reason": None,
                "weight": self.weight,
            }
        except Exception as exc:  # pragma: no cover - specific executors vary
            self.healthy = False
            self.failure_reason = type(exc).__name__
            return {
                "replica_id": self.replica_id,
                "status": "FAILED",
                "output": None,
                "failure_reason": self.failure_reason,
                "weight": self.weight,
            }


class HealthMonitor:
    @staticmethod
    def status(replicas: list[Replica]) -> list[dict[str, Any]]:
        return [
            {
                "replica_id": replica.replica_id,
                "healthy": replica.healthy,
                "failure_reason": replica.failure_reason,
            }
            for replica in replicas
        ]


class Adjudicator:
    @staticmethod
    def majority(results: list[dict[str, Any]]) -> dict[str, Any]:
        successful = [item for item in results if item["status"] == "OK"]
        if not successful:
            return {"status": "FAILED", "output": None, "agreeing_replicas": []}
        keys = [
            json.dumps(item["output"], ensure_ascii=False, sort_keys=True, default=str)
            for item in successful
        ]
        winner, count = Counter(keys).most_common(1)[0]
        candidates = [
            item for item, key in zip(successful, keys) if key == winner
        ]
        status = "CONSENSUS" if count > len(successful) / 2 else "INCONSISTENT"
        return {
            "status": status,
            "output": candidates[0]["output"],
            "agreeing_replicas": [item["replica_id"] for item in candidates],
        }


class SwitchRecovery:
    @staticmethod
    def recover(replica: Replica) -> dict[str, Any]:
        previous = replica.failure_reason
        replica.healthy = True
        replica.failure_reason = None
        return {
            "event": "REPLICA_RECOVERED",
            "replica_id": replica.replica_id,
            "previous_failure_reason": previous,
        }


class RedundantExecutor:
    implementation_status = "IMPLEMENTED"
    assurance_scope = "LOGICAL_REDUNDANCY_BASELINE"

    def __init__(self, replicas: list[Replica]) -> None:
        if len(replicas) < 3:
            raise ValueError("at least three logical replicas are required")
        self.replicas = replicas

    def execute(self, value: Any) -> dict[str, Any]:
        results = [replica.run(value) for replica in self.replicas]
        adjudication = Adjudicator.majority(results)
        return {
            "implementation_scope": self.assurance_scope,
            "replica_results": results,
            "adjudication": adjudication,
            "health": HealthMonitor.status(self.replicas),
        }

