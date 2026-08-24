"""SQLite persistence for campaigns, test cases, health samples, and events."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from .models import CampaignStatus, HealthSample, MutationResult, utc_now

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    config_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS test_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    case_number INTEGER NOT NULL,
    seed_index INTEGER NOT NULL,
    operator TEXT NOT NULL,
    offsets_json TEXT NOT NULL,
    payload_hex TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    response_hex TEXT,
    outcome TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(campaign_id, case_number)
);
CREATE TABLE IF NOT EXISTS health_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    alive INTEGER NOT NULL,
    latency_ms REAL,
    memory_percent REAL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_campaign ON test_cases(campaign_id, case_number);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id, id);
"""


class Storage:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self) -> None:
        with self._lock, self.connect() as connection:
            connection.executescript(SCHEMA)

    def create_campaign(self, name: str, config: dict[str, Any]) -> str:
        campaign_id = uuid.uuid4().hex
        with self._lock, self.connect() as connection:
            connection.execute(
                "INSERT INTO campaigns(id,name,status,config_json,created_at) VALUES(?,?,?,?,?)",
                (campaign_id, name, CampaignStatus.CREATED.value, json.dumps(config), utc_now()),
            )
        return campaign_id

    def update_campaign(
        self,
        campaign_id: str,
        status: CampaignStatus,
        metrics: dict[str, Any],
        error: str | None = None,
    ) -> None:
        now = utc_now()
        started = now if status is CampaignStatus.RUNNING else None
        finished = (
            now
            if status in {CampaignStatus.COMPLETED, CampaignStatus.STOPPED, CampaignStatus.FAILED}
            else None
        )
        with self._lock, self.connect() as connection:
            connection.execute(
                """UPDATE campaigns
                   SET status=?, metrics_json=?, error=COALESCE(?,error),
                       started_at=COALESCE(started_at,?),
                       finished_at=COALESCE(?,finished_at)
                   WHERE id=?""",
                (status.value, json.dumps(metrics), error, started, finished, campaign_id),
            )

    def add_case(
        self,
        campaign_id: str,
        case_number: int,
        seed_index: int,
        mutation: MutationResult,
        bytes_sent: int,
        response: bytes,
        outcome: str,
        duration_ms: float,
    ) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO test_cases(campaign_id,case_number,seed_index,operator,offsets_json,
                   payload_hex,bytes_sent,response_hex,outcome,duration_ms,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    campaign_id,
                    case_number,
                    seed_index,
                    mutation.operator,
                    json.dumps(mutation.offsets),
                    mutation.data.hex(),
                    bytes_sent,
                    response.hex(),
                    outcome,
                    duration_ms,
                    utc_now(),
                ),
            )

    def add_health(self, campaign_id: str, sample: HealthSample) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO health_samples(
                       campaign_id,timestamp,alive,latency_ms,memory_percent,detail
                   )
                   VALUES(?,?,?,?,?,?)""",
                (
                    campaign_id,
                    sample.timestamp,
                    int(sample.alive),
                    sample.latency_ms,
                    sample.memory_percent,
                    sample.detail,
                ),
            )

    def add_event(
        self,
        campaign_id: str,
        level: str,
        kind: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO events(
                       campaign_id,level,kind,message,data_json,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (campaign_id, level, kind, message, json.dumps(data or {}), utc_now()),
            )

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM campaigns WHERE id=?", (campaign_id,)
            ).fetchone()
        return self._campaign_row(row) if row else None

    def list_campaigns(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._campaign_row(row) for row in rows]

    def list_cases(self, campaign_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_cases WHERE campaign_id=? ORDER BY case_number LIMIT ?",
                (campaign_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_health(self, campaign_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM health_samples WHERE campaign_id=? ORDER BY id LIMIT ?",
                (campaign_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_events(
        self, campaign_id: str, after_id: int = 0, limit: int = 500
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE campaign_id=? AND id>? ORDER BY id LIMIT ?",
                (campaign_id, after_id, limit),
            ).fetchall()
        return [dict(row) | {"data": json.loads(row["data_json"])} for row in rows]

    @staticmethod
    def _campaign_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["config"] = json.loads(result.pop("config_json"))
        result["metrics"] = json.loads(result.pop("metrics_json"))
        return result
