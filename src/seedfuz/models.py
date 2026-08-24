"""Shared domain models for packets, campaigns, and measurements."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp suitable for SQLite and JSON."""
    return datetime.now(timezone.utc).isoformat()


class CampaignStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class TransportProtocol(str, Enum):
    DRY_RUN = "dry-run"
    TCP = "tcp"
    UDP = "udp"


@dataclass(slots=True)
class PacketRecord:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    raw: bytes
    payload: bytes
    protocol: str = "raw"
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int | None = None

    def summary(self) -> dict[str, Any]:
        data = asdict(self)
        data["raw"] = self.raw.hex()
        data["payload"] = self.payload.hex()
        return data


@dataclass(slots=True, frozen=True)
class SensitiveField:
    offset: int
    length: int
    score: float
    reasons: tuple[str, ...]


@dataclass(slots=True)
class MutationResult:
    data: bytes
    operator: str
    offsets: tuple[int, ...]
    score: float = 0.0
    reason: str = ""


@dataclass(slots=True)
class HealthSample:
    timestamp: str
    alive: bool
    latency_ms: float | None = None
    memory_percent: float | None = None
    detail: str = ""


@dataclass(slots=True)
class CampaignMetrics:
    total_cases: int = 0
    sent_cases: int = 0
    failed_cases: int = 0
    crashes: int = 0
    bytes_sent: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    packets_per_second: float = 0.0
    memory_leak_rate: float | None = None
    operator_counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
