"""Command-line entry points for analysis, campaigns, reports, and dashboard."""

from __future__ import annotations

import argparse
import json

from .campaign import CampaignRunner
from .config import CampaignConfig
from .monitor import DeviceMonitor
from .pcap import detect_sensitive_fields, read_pcap, usable_seeds
from .reporting import export_csv, export_pdf
from .state_machine import infer_state_graph
from .storage import Storage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seedfuz", description="Authorized IoT mutational fuzzing"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    analyze = subcommands.add_parser("analyze", help="inspect a classic PCAP")
    analyze.add_argument("pcap")
    analyze.add_argument("--json", action="store_true")
    run = subcommands.add_parser("run", help="run a campaign from JSON configuration")
    run.add_argument("config")
    run.add_argument("--database", default="results/seedfuz.db")
    report = subcommands.add_parser("report", help="export an existing campaign")
    report.add_argument("campaign_id")
    report.add_argument("--database", default="results/seedfuz.db")
    report.add_argument("--format", choices=("csv", "pdf"), default="csv")
    report.add_argument("--output")
    serve = subcommands.add_parser("serve", help="start the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        packets = read_pcap(args.pcap)
        seeds = usable_seeds(packets)
        result = {
            "packets": len(packets),
            "seeds": len(seeds),
            "protocols": sorted({packet.protocol for packet in packets}),
            "state_graph": infer_state_graph(packets).as_dict(),
            "sensitive_fields": [
                {
                    "offset": item.offset,
                    "length": item.length,
                    "score": item.score,
                    "reasons": item.reasons,
                }
                for item in (detect_sensitive_fields(seeds[0])[:20] if seeds else [])
            ],
        }
        print(json.dumps(result, indent=2) if args.json else _human_analysis(result))
        return 0
    if args.command == "run":
        config = CampaignConfig.from_json(args.config)
        storage = Storage(args.database)
        campaign_id = storage.create_campaign(config.name, config.to_dict())
        monitor = (
            DeviceMonitor(config.target_host, config.timeout_seconds, config.memory_probe_url)
            if config.protocol.value != "dry-run"
            else None
        )
        metrics = CampaignRunner(storage, config, campaign_id, monitor=monitor).run()
        print(json.dumps({"campaign_id": campaign_id, "metrics": metrics.as_dict()}, indent=2))
        return 0
    if args.command == "report":
        storage = Storage(args.database)
        output = args.output or f"results/{args.campaign_id}.{args.format}"
        path = (
            export_csv(storage, args.campaign_id, output)
            if args.format == "csv"
            else export_pdf(storage, args.campaign_id, output)
        )
        print(path)
        return 0
    if args.command == "serve":
        import uvicorn

        uvicorn.run("seedfuz.api:app", host=args.host, port=args.port, reload=False)
        return 0
    return 2


def _human_analysis(result: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Packets: {result['packets']}",
            f"Unique payload seeds: {result['seeds']}",
            f"Protocols: {', '.join(str(item) for item in result['protocols'])}",
            f"State graph: {json.dumps(result['state_graph'])}",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
