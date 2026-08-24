"""Campaign orchestration: mutate, send, monitor, measure, and persist."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import CampaignConfig
from .models import CampaignMetrics, CampaignStatus, HealthSample, TransportProtocol, utc_now
from .monitor import DeviceMonitor, memory_leak_rate
from .mutation import Mutator
from .pcap import read_pcap, usable_seeds
from .storage import Storage
from .transport import DryRunTransport, SocketTransport, Transport


class CampaignRunner:
    def __init__(
        self,
        storage: Storage,
        config: CampaignConfig,
        campaign_id: str,
        transport: Transport | None = None,
        monitor: DeviceMonitor | None = None,
        on_progress: Callable[[CampaignMetrics], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config
        self.campaign_id = campaign_id
        self.transport = transport or self._build_transport()
        self.monitor = monitor
        self.on_progress = on_progress
        self.metrics = CampaignMetrics(total_cases=config.max_cases)
        self._stop = threading.Event()
        self._health: list[HealthSample] = []

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> CampaignMetrics:
        self.config.validate()
        self.metrics.started_at = self.metrics.started_at or utc_now()
        self.storage.update_campaign(
            self.campaign_id, CampaignStatus.RUNNING, self.metrics.as_dict()
        )
        self.storage.add_event(self.campaign_id, "info", "campaign-started", "Campaign started")
        started = time.perf_counter()
        try:
            packets = read_pcap(Path(self.config.seed_path))
            seeds = usable_seeds(packets)
            if not seeds:
                raise ValueError("PCAP contains no non-empty TCP/UDP application payloads")
            mutator = Mutator(self.config.random_seed, self.config.smart_selection)
            consecutive_down = 0
            for case_number in range(1, self.config.max_cases + 1):
                if self._stop.is_set():
                    return self._finish(CampaignStatus.STOPPED, started)
                if self.config.state_aware:
                    seed_index = (case_number - 1) % len(seeds)
                else:
                    seed_index = mutator.random.randrange(len(seeds))
                mutation = mutator.mutate(seeds[seed_index], case_number - 1)
                case_started = time.perf_counter()
                outcome = "sent"
                response = b""
                sent = 0
                try:
                    result = self.transport.send(mutation.data)
                    sent, response = result.bytes_sent, result.response
                    self.metrics.sent_cases += 1
                    self.metrics.bytes_sent += sent
                except OSError as exc:
                    outcome = "send-error"
                    self.metrics.failed_cases += 1
                    self.storage.add_event(
                        self.campaign_id, "warning", "send-error", str(exc), {"case": case_number}
                    )
                duration = (time.perf_counter() - case_started) * 1000
                self.metrics.operator_counts[mutation.operator] = (
                    self.metrics.operator_counts.get(mutation.operator, 0) + 1
                )
                self.storage.add_case(
                    self.campaign_id,
                    case_number,
                    seed_index,
                    mutation,
                    sent,
                    response,
                    outcome,
                    duration,
                )
                if self.monitor and (case_number == 1 or case_number % self._monitor_every() == 0):
                    sample = self.monitor.sample()
                    self._health.append(sample)
                    self.storage.add_health(self.campaign_id, sample)
                    consecutive_down = 0 if sample.alive else consecutive_down + 1
                    if consecutive_down == self.config.crash_threshold:
                        self.metrics.crashes += 1
                        self.storage.add_event(
                            self.campaign_id,
                            "error",
                            "target-crash",
                            "Target failed consecutive health checks",
                            {"case": case_number, "timestamp": sample.timestamp},
                        )
                elapsed = max(time.perf_counter() - started, 1e-9)
                self.metrics.packets_per_second = self.metrics.sent_cases / elapsed
                self.metrics.memory_leak_rate = memory_leak_rate(self._health)
                self.storage.update_campaign(
                    self.campaign_id, CampaignStatus.RUNNING, self.metrics.as_dict()
                )
                if self.on_progress:
                    self.on_progress(self.metrics)
                if self.config.delay_seconds:
                    time.sleep(self.config.delay_seconds)
            return self._finish(CampaignStatus.COMPLETED, started)
        except Exception as exc:
            self.storage.add_event(self.campaign_id, "error", "campaign-failed", str(exc))
            self.storage.update_campaign(
                self.campaign_id, CampaignStatus.FAILED, self.metrics.as_dict(), error=str(exc)
            )
            raise

    def _finish(self, status: CampaignStatus, started: float) -> CampaignMetrics:
        self.metrics.finished_at = utc_now()
        elapsed = max(time.perf_counter() - started, 1e-9)
        self.metrics.packets_per_second = self.metrics.sent_cases / elapsed
        self.metrics.memory_leak_rate = memory_leak_rate(self._health)
        self.storage.update_campaign(self.campaign_id, status, self.metrics.as_dict())
        self.storage.add_event(self.campaign_id, "info", f"campaign-{status.value}", status.value)
        return self.metrics

    def _build_transport(self) -> Transport:
        if self.config.protocol is TransportProtocol.DRY_RUN:
            return DryRunTransport()
        return SocketTransport(
            self.config.target_host,
            self.config.target_port,
            self.config.protocol.value,
            self.config.timeout_seconds,
        )

    def _monitor_every(self) -> int:
        delay = max(self.config.delay_seconds, 0.001)
        return max(1, int(self.config.monitor_interval / delay))
