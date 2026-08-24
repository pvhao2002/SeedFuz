"""Configuration parsing and safety validation."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import TransportProtocol


@dataclass(slots=True)
class CampaignConfig:
    name: str = "SeedFuz campaign"
    seed_path: str = ""
    protocol: TransportProtocol = TransportProtocol.DRY_RUN
    target_host: str = "127.0.0.1"
    target_port: int = 0
    authorized: bool = False
    allow_public_target: bool = False
    max_cases: int = 100
    delay_seconds: float = 0.01
    timeout_seconds: float = 1.0
    random_seed: int = 1337
    smart_selection: bool = True
    state_aware: bool = True
    monitor_interval: float = 1.0
    memory_probe_url: str | None = None
    crash_threshold: int = 2

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CampaignConfig:
        values = dict(data)
        if "protocol" in values:
            values["protocol"] = TransportProtocol(values["protocol"])
        config = cls(**values)
        config.validate()
        return config

    @classmethod
    def from_json(cls, path: str | Path) -> CampaignConfig:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["protocol"] = self.protocol.value
        return data

    def validate(self) -> None:
        if not 1 <= self.max_cases <= 1_000_000:
            raise ValueError("max_cases must be between 1 and 1,000,000")
        if self.delay_seconds < 0 or self.timeout_seconds <= 0:
            raise ValueError("delay_seconds must be non-negative and timeout_seconds positive")
        if self.crash_threshold < 1:
            raise ValueError("crash_threshold must be at least 1")
        if self.protocol is TransportProtocol.DRY_RUN:
            return
        if not self.authorized:
            raise ValueError("Network fuzzing requires authorized=true")
        if not 1 <= self.target_port <= 65535:
            raise ValueError("target_port must be between 1 and 65535")
        try:
            address = ipaddress.ip_address(self.target_host)
        except ValueError as exc:
            raise ValueError("target_host must be an explicit IP address") from exc
        safe_scope = address.is_private or address.is_loopback or address.is_link_local
        if not safe_scope and not self.allow_public_target:
            raise ValueError("Public targets are disabled; use an isolated private lab network")
