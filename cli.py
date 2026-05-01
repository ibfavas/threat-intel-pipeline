from __future__ import annotations

import argparse
import json
import sys

from pipeline.storage import IOCStorage


INGESTORS = ("urlhaus", "feodo", "otx")


def build_ingestor(name: str, args: argparse.Namespace | None = None):
    if name == "urlhaus":
        from pipeline.ingestors.urlhaus import URLHausIngestor

        return URLHausIngestor()
    if name == "feodo":
        from pipeline.ingestors.feodo import FeodoIngestor

        return FeodoIngestor()
    if name == "otx":
        from pipeline.ingestors.otx import OTXIngestor

        if args and args.otx_limit is not None:
            return OTXIngestor(limit=args.otx_limit, max_page=args.otx_max_page)
        return OTXIngestor()
    raise ValueError(f"Unknown ingestor: {name}")


def ingest(args: argparse.Namespace) -> int:
    storage = IOCStorage()
    total = 0
    selected = args.feeds or list(INGESTORS)

    for name in selected:
        try:
            ingestor = build_ingestor(name, args)
            records = ingestor.ingest()
            stored = storage.upsert_iocs(records)
            storage.log_feed_run(name, "success", stored)
            total += stored
            print(f"{name}: stored {stored} normalized records")
        except Exception as exc:
            storage.log_feed_run(name, "failed", 0, str(exc))
            print(f"{name}: failed: {exc}", file=sys.stderr)

    print(f"ingest complete: {total} records processed")
    return 0


def score(args: argparse.Namespace) -> int:
    from pipeline.scorer import ConfidenceScorer

    storage = IOCStorage()
    scorer = ConfidenceScorer(storage)
    updated = scorer.score_all()
    print(f"scored {updated} IOC records")

    if args.verbose:
        print("\nscore breakdown:")
        rows = storage.top_iocs(args.top)
        for row in rows:
            breakdown = scorer.score_breakdown(row)
            print(
                f"{row['value']} ({row['type']}): "
                f"recency={breakdown['recency']}, "
                f"source={breakdown['source']}, "
                f"corroboration={breakdown['corroboration']}, "
                f"total={row['confidence_score']:.1f}"
            )
    return 0


def enrich(args: argparse.Namespace) -> int:
    from pipeline.enricher import IOCEnricher

    storage = IOCStorage()
    updated = IOCEnricher(storage).enrich_high_confidence(
        limit=args.limit, verbose=args.verbose, ioc_type=args.ioc_type
    )
    print(f"enriched {updated} high-confidence IOC records")
    return 0


def export(args: argparse.Namespace) -> int:
    from pipeline.exporter import IOCExporter

    storage = IOCStorage()
    exporter = IOCExporter(storage)
    if args.wazuh:
        try:
            counts = exporter.export_wazuh(
                ip_path=args.ip_list,
                domain_path=args.domain_list,
                reload_wazuh=args.reload,
            )
        except PermissionError as exc:
            print(
                f"export failed: permission denied writing Wazuh list path: {exc.filename}",
                file=sys.stderr,
            )
            print(
                "Use --ip-list/--domain-list for a local screenshot export, "
                "or run with permissions to write /var/ossec.",
                file=sys.stderr,
            )
            return 1
        print(
            f"exported {counts['ips']} IPs and {counts['domains']} domains to Wazuh lists"
        )
    else:
        print(exporter.report(args.top))
    return 0


def report(args: argparse.Namespace) -> int:
    from pipeline.exporter import IOCExporter

    storage = IOCStorage()
    print(IOCExporter(storage).report(args.top))
    return 0


def stats(args: argparse.Namespace) -> int:
    storage = IOCStorage()
    print(json.dumps(storage.stats(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Threat intel IOC aggregation pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="pull feeds, normalize, and store")
    ingest_parser.add_argument(
        "--feeds",
        nargs="+",
        choices=sorted(INGESTORS),
        help="optional feed subset to ingest",
    )
    ingest_parser.add_argument(
        "--otx-limit",
        type=int,
        help="maximum OTX pulses to fetch; keeps OTX screenshots fast",
    )
    ingest_parser.add_argument(
        "--otx-max-page",
        type=int,
        default=1,
        help="maximum OTX API pages to walk when --otx-limit is used",
    )
    ingest_parser.set_defaults(func=ingest)

    score_parser = subparsers.add_parser("score", help="calculate confidence scores")
    score_parser.add_argument("--verbose", action="store_true", help="print scoring components")
    score_parser.add_argument("--top", type=int, default=5, help="verbose rows to print")
    score_parser.set_defaults(func=score)

    enrich_parser = subparsers.add_parser("enrich", help="enrich high-confidence IOCs")
    enrich_parser.add_argument("--limit", type=int, help="maximum number of IOCs to enrich")
    enrich_parser.add_argument("--verbose", action="store_true", help="print enrichment summaries")
    enrich_parser.add_argument(
        "--type",
        dest="ioc_type",
        choices=["ip", "domain", "url", "hash"],
        help="only enrich high-confidence IOCs of this type",
    )
    enrich_parser.set_defaults(func=enrich)

    export_parser = subparsers.add_parser("export", help="export to Wazuh or print report")
    export_parser.add_argument("--wazuh", action="store_true", help="write Wazuh CDB lists")
    export_parser.add_argument("--reload", action="store_true", help="reload Wazuh after export")
    export_parser.add_argument(
        "--ip-list",
        help="IP CDB list output path; defaults to TIP_WAZUH_IP_LIST or /var/ossec",
    )
    export_parser.add_argument(
        "--domain-list",
        help="domain CDB list output path; defaults to TIP_WAZUH_DOMAIN_LIST or /var/ossec",
    )
    export_parser.add_argument("--top", type=int, default=20, help="report rows when not using Wazuh")
    export_parser.set_defaults(func=export)

    report_parser = subparsers.add_parser("report", help="print top IOCs by score")
    report_parser.add_argument("--top", type=int, default=20)
    report_parser.set_defaults(func=report)

    stats_parser = subparsers.add_parser("stats", help="show database and feed run stats")
    stats_parser.set_defaults(func=stats)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
