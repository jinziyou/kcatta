"""CLI entry points for the form package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from .detect import OsvStore, detect_report, ecosystem_for_os, sync_ecosystem
from .schemas import Alert, AssetReport, DetectionResult, FlowBatch
from .storage import JsonlStore

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"
DEFAULT_DATA_DIR = Path("data")

EXPORTABLE: dict[str, type] = {
    "AssetReport": AssetReport,
    "FlowBatch": FlowBatch,
    "Alert": Alert,
    "DetectionResult": DetectionResult,
}


def export_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in EXPORTABLE.items():
        schema = model.model_json_schema()
        path = out_dir / f"{name}.schema.json"
        path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def export_schemas_main() -> None:
    parser = argparse.ArgumentParser(
        description="Export JSON Schemas for cyber-posture data contracts",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    paths = export_schemas(args.out)
    for p in paths:
        print(f"wrote {p}")


def api_main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the cyber-posture form HTTP API",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = parser.parse_args()

    uvicorn.run(
        "form.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def osv_sync_main() -> None:
    parser = argparse.ArgumentParser(
        description="Download OSV advisory data into the local store",
    )
    parser.add_argument(
        "--ecosystem",
        required=True,
        nargs="+",
        metavar="ECOSYSTEM",
        help="One or more top-level OSV ecosystems, e.g. --ecosystem Debian PyPI npm",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "osv",
        help="Local OSV store directory (default: data/osv)",
    )
    args = parser.parse_args()

    failures = 0
    for ecosystem in args.ecosystem:
        try:
            count = sync_ecosystem(ecosystem, args.db)
        except OSError as exc:  # URLError/HTTPError/timeout all subclass OSError
            failures += 1
            print(f"failed to sync {ecosystem}: {exc}", file=sys.stderr)
            continue
        print(f"wrote {count} OSV records to {args.db / ecosystem}")
    if failures:
        sys.exit(1)


def detect_main() -> None:
    parser = argparse.ArgumentParser(
        description="Match ingested AssetReports against the local OSV store",
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=DEFAULT_DATA_DIR / "asset-reports.jsonl",
        help="AssetReport JSONL file (default: data/asset-reports.jsonl)",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "osv",
        help="Local OSV store directory (default: data/osv)",
    )
    parser.add_argument(
        "--ecosystem",
        default=None,
        help="OSV ecosystem (e.g. Debian:12). Default: derive per report from host.os",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Most-recent reports to scan (default: 50)",
    )
    parser.add_argument("--out", type=Path, default=None, help="Write results JSON to a file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print output")
    args = parser.parse_args()

    store = OsvStore.load_dir(args.db)
    print(f"loaded {store.record_count} OSV records from {args.db}", file=sys.stderr)

    reports = [AssetReport.model_validate(row) for row in JsonlStore(args.reports).tail(args.limit)]

    results = []
    for report in reports:
        ecosystem = args.ecosystem or ecosystem_for_os(report.host.os)
        if not ecosystem:
            print(
                f"skip {report.report_id}: cannot derive ecosystem from os "
                f"{report.host.os!r} (pass --ecosystem)",
                file=sys.stderr,
            )
            continue
        vulns = detect_report(report, store, ecosystem)
        results.append(
            {
                "report_id": report.report_id,
                "host_id": report.host.host_id,
                "ecosystem": ecosystem,
                "vulnerabilities": [v.model_dump(mode="json") for v in vulns],
            }
        )
        print(f"{report.report_id}: {len(vulns)} finding(s)", file=sys.stderr)

    payload = json.dumps(results, indent=2 if args.pretty else None)
    if args.out:
        args.out.write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(payload)
