"""Continuous reachability and optional memory telemetry monitoring."""

from __future__ import annotations

import json
import platform
import subprocess
import time
import urllib.request
from dataclasses import dataclass

from .models import HealthSample, utc_now


@dataclass(slots=True)
class DeviceMonitor:
    host: str
    timeout_seconds: float = 1.0
    memory_probe_url: str | None = None

    def sample(self) -> HealthSample:
        started = time.perf_counter()
        timeout = max(1, int(round(self.timeout_seconds)))
        flag = "-W" if platform.system() == "Linux" else "-t"
        command = ["ping", "-c", "1", flag, str(timeout), self.host]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout_seconds + 1
            )
            alive = result.returncode == 0
            detail = "ping ok" if alive else (result.stderr.strip() or "ping failed")[-200:]
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            alive = False
            detail = str(exc)
        latency = (time.perf_counter() - started) * 1000
        memory = self._read_memory() if alive and self.memory_probe_url else None
        return HealthSample(utc_now(), alive, latency, memory, detail)

    def _read_memory(self) -> float | None:
        assert self.memory_probe_url is not None
        try:
            with urllib.request.urlopen(
                self.memory_probe_url, timeout=self.timeout_seconds
            ) as response:
                data = json.loads(response.read(64 * 1024))
            value = float(data["memory_percent"])
            return value if 0 <= value <= 100 else None
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None


def memory_leak_rate(samples: list[HealthSample]) -> float | None:
    """Return least-squares memory growth in percentage points per sample."""
    values = [sample.memory_percent for sample in samples if sample.memory_percent is not None]
    if len(values) < 2:
        return None
    count = len(values)
    mean_x = (count - 1) / 2
    mean_y = sum(values) / count
    numerator = sum((index - mean_x) * (value - mean_y) for index, value in enumerate(values))
    denominator = sum((index - mean_x) ** 2 for index in range(count))
    return numerator / denominator if denominator else 0.0
