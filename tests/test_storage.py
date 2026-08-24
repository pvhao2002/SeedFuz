from pathlib import Path

from seedfuz.models import CampaignStatus, MutationResult
from seedfuz.storage import Storage


def test_persists_campaign_case_and_event(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "test.db")
    campaign_id = storage.create_campaign("test", {"protocol": "dry-run"})
    mutation = MutationResult(b"abc", "bit-flip", (1,))
    storage.add_case(campaign_id, 1, 0, mutation, 3, b"ok", "sent", 1.2)
    storage.add_event(campaign_id, "info", "test", "persisted")
    storage.update_campaign(campaign_id, CampaignStatus.COMPLETED, {"sent_cases": 1})
    assert storage.get_campaign(campaign_id)["status"] == "completed"  # type: ignore[index]
    assert storage.list_cases(campaign_id)[0]["payload_hex"] == "616263"
    assert storage.list_events(campaign_id)[0]["message"] == "persisted"
