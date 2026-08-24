"""CSV and PDF exports for campaign evidence."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .storage import Storage


def export_csv(storage: Storage, campaign_id: str, output: str | Path) -> Path:
    _require_campaign(storage, campaign_id)
    cases = storage.list_cases(campaign_id, limit=1_000_000)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "case_number",
        "seed_index",
        "operator",
        "offsets_json",
        "bytes_sent",
        "outcome",
        "duration_ms",
        "created_at",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in cases)
    return path


def export_pdf(storage: Storage, campaign_id: str, output: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("Install project dependencies to export PDF") from exc

    campaign = _require_campaign(storage, campaign_id)
    events = storage.list_events(campaign_id, limit=200)
    metrics = campaign["metrics"]
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph("SeedFuz Campaign Report", styles["Title"]),
        Paragraph(str(campaign["name"]), styles["Heading2"]),
        Spacer(1, 8),
    ]
    summary = [
        ["Status", campaign["status"]],
        ["Started", campaign.get("started_at") or "-"],
        ["Finished", campaign.get("finished_at") or "-"],
        ["Cases sent", str(metrics.get("sent_cases", 0))],
        ["Crashes", str(metrics.get("crashes", 0))],
        ["Speed", f"{metrics.get('packets_per_second', 0):.2f} packets/s"],
        ["Memory trend", _memory_text(metrics.get("memory_leak_rate"))],
    ]
    table = Table(summary, colWidths=[45 * mm, 115 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF8")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#AAB4C3")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([table, Spacer(1, 14), Paragraph("Recorded events", styles["Heading2"])])
    if events:
        rows = [["Time", "Level", "Event", "Message"]] + [
            [event["created_at"][:19], event["level"], event["kind"], event["message"]]
            for event in events
        ]
        event_table = Table(rows, colWidths=[35 * mm, 18 * mm, 38 * mm, 69 * mm], repeatRows=1)
        event_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17233D")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCD3DD")),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(event_table)
    else:
        story.append(Paragraph("No events were recorded.", styles["BodyText"]))
    document.build(story)
    return path


def _require_campaign(storage: Storage, campaign_id: str) -> dict[str, Any]:
    campaign = storage.get_campaign(campaign_id)
    if not campaign:
        raise KeyError(f"Unknown campaign: {campaign_id}")
    return campaign


def _memory_text(value: float | None) -> str:
    return "not measured" if value is None else f"{value:+.4f} percentage points/sample"
