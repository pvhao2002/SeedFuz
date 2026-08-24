"""FastAPI service and background campaign registry."""

from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .campaign import CampaignRunner
from .config import CampaignConfig
from .monitor import DeviceMonitor
from .pcap import PcapError, detect_sensitive_fields, read_pcap, usable_seeds
from .reporting import export_csv, export_pdf
from .state_machine import infer_state_graph
from .storage import Storage


class RunnerRegistry:
    def __init__(self) -> None:
        self._runners: dict[str, CampaignRunner] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.RLock()

    def start(self, campaign_id: str, runner: CampaignRunner) -> None:
        def target() -> None:
            try:
                runner.run()
            except Exception:
                pass  # Failure details are persisted and exposed by the API.
            finally:
                with self._lock:
                    self._threads.pop(campaign_id, None)

        thread = threading.Thread(target=target, name=f"seedfuz-{campaign_id[:8]}", daemon=True)
        with self._lock:
            self._runners[campaign_id] = runner
            self._threads[campaign_id] = thread
        thread.start()

    def stop(self, campaign_id: str) -> bool:
        with self._lock:
            runner = self._runners.get(campaign_id)
        if not runner:
            return False
        runner.stop()
        return True


def create_app(
    database_path: str | Path = "results/seedfuz.db",
    upload_dir: str | Path = "datasets/uploads",
    result_dir: str | Path = "results",
) -> FastAPI:
    storage = Storage(database_path)
    uploads = Path(upload_dir)
    results = Path(result_dir)
    uploads.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    registry = RunnerRegistry()
    app = FastAPI(title="SeedFuz", version="0.1.0")
    app.state.storage = storage
    app.state.registry = registry
    app.state.upload_dir = uploads
    app.state.result_dir = results

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/pcaps")
    async def upload_pcap(file: Annotated[UploadFile, File()]) -> dict[str, Any]:
        suffix = Path(file.filename or "capture.pcap").suffix.lower()
        if suffix not in {".pcap", ".cap"}:
            raise HTTPException(400, "Only classic .pcap/.cap files are accepted")
        destination = uploads / _safe_name(file.filename or "capture.pcap")
        with destination.open("wb") as output:
            shutil.copyfileobj(file.file, output)
        if destination.stat().st_size > 100 * 1024 * 1024:
            destination.unlink(missing_ok=True)
            raise HTTPException(413, "Capture exceeds the 100 MiB limit")
        try:
            packets = read_pcap(destination, max_packets=100_000)
        except PcapError as exc:
            destination.unlink(missing_ok=True)
            raise HTTPException(400, str(exc)) from exc
        seeds = usable_seeds(packets)
        graph = infer_state_graph(packets)
        fields = detect_sensitive_fields(seeds[0])[:20] if seeds else []
        return {
            "path": str(destination),
            "filename": destination.name,
            "packet_count": len(packets),
            "seed_count": len(seeds),
            "protocols": sorted({packet.protocol for packet in packets}),
            "state_graph": graph.as_dict(),
            "sample_sensitive_fields": [
                {
                    "offset": field.offset,
                    "length": field.length,
                    "score": field.score,
                    "reasons": field.reasons,
                }
                for field in fields
            ],
        }

    @app.post("/api/campaigns")
    def create_campaign(config_json: Annotated[str, Form()]) -> dict[str, Any]:
        try:
            config = CampaignConfig.from_dict(json.loads(config_json))
            seed = Path(config.seed_path).resolve()
            upload_root = uploads.resolve()
            if upload_root not in seed.parents:
                raise ValueError("seed_path must reference a file uploaded through SeedFuz")
            read_pcap(seed, max_packets=1)
        except (ValueError, json.JSONDecodeError, PcapError) as exc:
            raise HTTPException(400, str(exc)) from exc
        campaign_id = storage.create_campaign(config.name, config.to_dict())
        monitor = None
        if config.protocol.value != "dry-run":
            monitor = DeviceMonitor(
                config.target_host, config.timeout_seconds, config.memory_probe_url
            )
        runner = CampaignRunner(storage, config, campaign_id, monitor=monitor)
        registry.start(campaign_id, runner)
        return {"id": campaign_id, "status": "created"}

    @app.get("/api/campaigns")
    def list_campaigns() -> list[dict[str, Any]]:
        return storage.list_campaigns()

    @app.get("/api/campaigns/{campaign_id}")
    def get_campaign(campaign_id: str) -> dict[str, Any]:
        campaign = storage.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")
        campaign["recent_events"] = storage.list_events(campaign_id, limit=100)
        campaign["health"] = storage.list_health(campaign_id, limit=500)
        return campaign

    @app.get("/api/campaigns/{campaign_id}/events")
    def get_events(campaign_id: str, after: int = 0) -> list[dict[str, Any]]:
        if not storage.get_campaign(campaign_id):
            raise HTTPException(404, "Campaign not found")
        return storage.list_events(campaign_id, after_id=after)

    @app.post("/api/campaigns/{campaign_id}/stop")
    def stop_campaign(campaign_id: str) -> dict[str, bool]:
        if not registry.stop(campaign_id):
            raise HTTPException(409, "Campaign is not running")
        return {"stopping": True}

    @app.get("/api/campaigns/{campaign_id}/report.csv")
    def csv_report(campaign_id: str) -> FileResponse:
        try:
            path = export_csv(storage, campaign_id, results / f"{campaign_id}.csv")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        return FileResponse(path, media_type="text/csv", filename=f"seedfuz-{campaign_id}.csv")

    @app.get("/api/campaigns/{campaign_id}/report.pdf")
    def pdf_report(campaign_id: str) -> FileResponse:
        try:
            path = export_pdf(storage, campaign_id, results / f"{campaign_id}.pdf")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        return FileResponse(
            path, media_type="application/pdf", filename=f"seedfuz-{campaign_id}.pdf"
        )

    static = Path(__file__).with_name("static")
    app.mount("/", StaticFiles(directory=static, html=True), name="dashboard")
    return app


def _safe_name(filename: str) -> str:
    base = Path(filename).name
    safe = "".join(character for character in base if character.isalnum() or character in "._-")
    return safe[:120] or "capture.pcap"


app = create_app()
