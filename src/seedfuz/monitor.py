"""Continuous reachability and optional memory telemetry monitoring."""

from __future__ import annotations

import json
import platform
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .models import HealthSample, utc_now


@dataclass(slots=True)
class DeviceMonitor:
    """Detect device liveness via HTTP status, TCP connect, or ICMP ping.

    On black-box commercial routers (no shell for RAM/CPU telemetry), set
    ``http_url`` or ``tcp_port`` so a hang is caught by an HTTP 5xx, an abruptly
    closed TCP port, or sustained ping loss. ``http_url`` wins over ``tcp_port``
    over ping when more than one is configured.
    """

    host: str
    timeout_seconds: float = 1.0
    memory_probe_url: str | None = None
    tcp_port: int | None = None
    http_url: str | None = None
    unhealthy_http_status: int = 500

    def sample(self) -> HealthSample:
        started = time.perf_counter()
        if self.http_url:
            alive, detail = self._check_http()
        elif self.tcp_port is not None:
            alive, detail = self._check_tcp()
        else:
            alive, detail = self._check_ping()
        latency = (time.perf_counter() - started) * 1000
        memory = self._read_memory() if alive and self.memory_probe_url else None
        return HealthSample(utc_now(), alive, latency, memory, detail)

    def _check_ping(self) -> tuple[bool, str]:
        timeout = max(1, int(round(self.timeout_seconds)))
        flag = "-W" if platform.system() == "Linux" else "-t"
        command = ["ping", "-c", "1", flag, str(timeout), self.host]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout_seconds + 1
            )
            alive = result.returncode == 0
            return alive, "ping ok" if alive else (result.stderr.strip() or "ping failed")[-200:]
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def _check_tcp(self) -> tuple[bool, str]:
        assert self.tcp_port is not None
        try:
            with socket.create_connection(
                (self.host, self.tcp_port), timeout=self.timeout_seconds
            ):
                return True, f"tcp {self.tcp_port} open"
        except ConnectionRefusedError:
            return False, f"tcp {self.tcp_port} refused"
        except OSError as exc:  # timeout, host unreachable, etc.
            return False, f"tcp {self.tcp_port} down: {exc}"

    def _check_http(self) -> tuple[bool, str]:
        assert self.http_url is not None
        request = urllib.request.Request(self.http_url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
        except urllib.error.HTTPError as exc:  # server replied, so it is still alive unless 5xx
            status = exc.code
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return False, f"http down: {exc}"
        alive = status < self.unhealthy_http_status
        return alive, f"http {status}" + ("" if alive else " (unhealthy)")

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
