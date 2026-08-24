from pathlib import Path

from fastapi.testclient import TestClient

from seedfuz.api import create_app


def test_health_and_pcap_upload(sample_pcap: Path, tmp_path: Path) -> None:
    app = create_app(tmp_path / "api.db", tmp_path / "uploads", tmp_path / "results")
    with TestClient(app) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        with sample_pcap.open("rb") as stream:
            response = client.post(
                "/api/pcaps",
                files={"file": ("sample.pcap", stream, "application/vnd.tcpdump.pcap")},
            )
        assert response.status_code == 200
        assert response.json()["seed_count"] == 2
