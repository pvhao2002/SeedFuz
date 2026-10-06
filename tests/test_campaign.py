from pathlib import Path

from seedfuz.campaign import CampaignRunner
from seedfuz.config import CampaignConfig
from seedfuz.models import HealthSample
from seedfuz.storage import Storage


def _config(sample_pcap: Path, **overrides: object) -> CampaignConfig:
    base = {
        "name": "test dry run",
        "seed_path": str(sample_pcap),
        "protocol": "dry-run",
        "max_cases": 9,
        "delay_seconds": 0,
        "random_seed": 9,
    }
    base.update(overrides)
    return CampaignConfig.from_dict(base)


def test_dry_run_campaign_end_to_end(sample_pcap: Path, tmp_path: Path) -> None:
    storage = Storage(tmp_path / "campaign.db")
    config = _config(sample_pcap)
    campaign_id = storage.create_campaign(config.name, config.to_dict())
    metrics = CampaignRunner(storage, config, campaign_id).run()
    assert metrics.sent_cases == 9
    assert metrics.failed_cases == 0
    assert set(metrics.operator_counts) == {"bit-flip", "byte-boundary", "smart-field"}
    assert metrics.security_status == "not-monitored"  # dry-run has no device to assess
    assert storage.get_campaign(campaign_id)["status"] == "completed"  # type: ignore[index]
    assert len(storage.list_cases(campaign_id)) == 9


def test_smart_selection_covers_sensitive_fields(sample_pcap: Path, tmp_path: Path) -> None:
    storage = Storage(tmp_path / "cov.db")
    smart = CampaignRunner(
        storage, _config(sample_pcap, max_cases=30), storage.create_campaign("s", {})
    ).run()
    plain = CampaignRunner(
        storage,
        _config(sample_pcap, max_cases=30, smart_selection=False),
        storage.create_campaign("p", {}),
    ).run()
    assert smart.sensitive_fields_covered > 0
    assert smart.sensitive_fields_covered >= plain.sensitive_fields_covered


class _ScriptedMonitor:
    """Monitor returning a fixed alive/dead sequence for recovery testing."""

    def __init__(self, pattern: list[bool]) -> None:
        self.pattern = pattern
        self.index = 0

    def sample(self) -> HealthSample:
        alive = self.pattern[min(self.index, len(self.pattern) - 1)]
        self.index += 1
        return HealthSample("t", alive, 1.0, None, "scripted")


def test_crash_records_payload_and_recovers(sample_pcap: Path, tmp_path: Path) -> None:
    storage = Storage(tmp_path / "recover.db")
    config = _config(
        sample_pcap, max_cases=6, monitor_interval=0, crash_threshold=2, recovery_wait_seconds=5
    )
    campaign_id = storage.create_campaign(config.name, config.to_dict())
    monitor = _ScriptedMonitor([False, False, True, True, True, True, True, True])
    metrics = CampaignRunner(storage, config, campaign_id, monitor=monitor).run()
    assert metrics.crashes >= 1
    assert metrics.security_status == "vulnerable"
    kinds = {event["kind"]: event for event in storage.list_events(campaign_id)}
    assert "target-crash" in kinds
    assert kinds["target-crash"]["data"]["last_payload_hex"]  # hex of last sent case recorded
    assert "target-recovered" in kinds
    assert "security-alert" in kinds  # security status alert raised on crash
    assert storage.list_alerts()  # alert surfaced for remote monitoring
