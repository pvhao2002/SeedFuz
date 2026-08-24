from pathlib import Path

from seedfuz.campaign import CampaignRunner
from seedfuz.config import CampaignConfig
from seedfuz.storage import Storage


def test_dry_run_campaign_end_to_end(sample_pcap: Path, tmp_path: Path) -> None:
    storage = Storage(tmp_path / "campaign.db")
    config = CampaignConfig.from_dict(
        {
            "name": "test dry run",
            "seed_path": str(sample_pcap),
            "protocol": "dry-run",
            "max_cases": 9,
            "delay_seconds": 0,
            "random_seed": 9,
        }
    )
    campaign_id = storage.create_campaign(config.name, config.to_dict())
    metrics = CampaignRunner(storage, config, campaign_id).run()
    assert metrics.sent_cases == 9
    assert metrics.failed_cases == 0
    assert set(metrics.operator_counts) == {"bit-flip", "byte-boundary", "smart-field"}
    assert storage.get_campaign(campaign_id)["status"] == "completed"  # type: ignore[index]
    assert len(storage.list_cases(campaign_id)) == 9
