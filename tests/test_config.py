import pytest

from seedfuz.config import CampaignConfig


def test_dry_run_does_not_require_authorization() -> None:
    CampaignConfig.from_dict({"protocol": "dry-run", "max_cases": 1})


def test_network_campaign_requires_authorization() -> None:
    with pytest.raises(ValueError, match="authorized"):
        CampaignConfig.from_dict(
            {"protocol": "tcp", "target_host": "192.168.1.10", "target_port": 80}
        )


def test_public_target_is_denied_by_default() -> None:
    with pytest.raises(ValueError, match="Public targets"):
        CampaignConfig.from_dict(
            {"protocol": "udp", "target_host": "8.8.8.8", "target_port": 53, "authorized": True}
        )
