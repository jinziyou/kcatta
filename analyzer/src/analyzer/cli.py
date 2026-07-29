"""CLI entry points for the analyzer package."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import uvicorn

from .detect import (
    DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS,
    DEFAULT_OSV_ECOSYSTEMS,
    DebianTrackerStore,
    OsvStore,
    detect_report,
    ecosystem_for_os,
    read_complete_manifest,
    sync_debian_tracker,
    sync_ecosystem,
    sync_ecosystem_archive,
    write_complete_manifest,
)
from .logging_config import configure_logging
from .schemas import (
    Alert,
    AssetReport,
    AttackPath,
    CapabilityGraph,
    DetectionResult,
    GuardEventBatch,
    MdeSecurityBatch,
    MdvmVulnerabilityBatch,
    TraceBatch,
)
from .storage import JsonlStore, create_store, migrate_jsonl_to_sqlite

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"
DEFAULT_OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"
DEFAULT_DATA_DIR = Path("data")

# Default OSV ecosystems to sync — the supported surface the agent emits:
# dpkg (Debian/Ubuntu), apk (Alpine), rpm (Rocky/Alma/openSUSE Leap), and the
# language collectors (PyPI, npm). Windows inventory is still collected, but
# OSV has no Windows ecosystem/export; coverage reports it as unsupported rather
# than making the whole atomic sync fail. GHSA advisories need no separate feed — OSV
# merges them into each language ecosystem's export (PyPI/all.zip, npm/all.zip),
# so syncing PyPI+npm covers GHSA-derived findings for collected language packages.
# Deliberately NOT here: SLES/RHEL/CentOS/Fedora (OSV keys them by CPE/product-
# module, unreproducible from os-release — see sbom.rs::osv_ecosystem), and
# Maven/Go/RubyGems/etc. (no agent collector emits them — pure dead weight).
EXPORTABLE: dict[str, type] = {
    "AssetReport": AssetReport,
    "TraceBatch": TraceBatch,
    "GuardEventBatch": GuardEventBatch,
    "MdeSecurityBatch": MdeSecurityBatch,
    "MdvmVulnerabilityBatch": MdvmVulnerabilityBatch,
    "Alert": Alert,
    "DetectionResult": DetectionResult,
    "CapabilityGraph": CapabilityGraph,
    "AttackPath": AttackPath,
}


def export_schemas(out_dir: Path) -> list[Path]:
    """Write JSON Schema files for the exportable data contracts and return their paths."""
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
    """CLI entry point: export data-contract JSON Schemas to a directory."""
    parser = argparse.ArgumentParser(
        description="Export JSON Schemas for kcatta data contracts",
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


def export_openapi(out_path: Path) -> Path:
    """Write the analyzer's OpenAPI schema to ``out_path`` and return it.

    This is Analyzer's internal Form-facing API contract. Written sorted +
    indented so a CI ``git diff`` is a stable drift gate.
    """
    # Imported lazily: building the app pulls in the whole API layer, which the
    # other CLI entry points (schema export, osv-sync) have no need for.
    from .api import create_app

    schema = create_app(api_token="openapi-contract-export").openapi()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def export_openapi_main() -> None:
    """CLI entry point: export the analyzer OpenAPI schema to a file."""
    parser = argparse.ArgumentParser(
        description="Export the analyzer OpenAPI schema (the API contract)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OPENAPI,
        help=f"Output file (default: {DEFAULT_OPENAPI})",
    )
    args = parser.parse_args()
    print(f"wrote {export_openapi(args.out)}")


def api_main() -> None:
    """CLI entry point: run the analyzer HTTP API via uvicorn."""
    parser = argparse.ArgumentParser(
        description="Run the kcatta analyzer HTTP API",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=10068, help="bind port (default: 10068)")
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = parser.parse_args()

    # Configure business logging before uvicorn starts so startup-time logs are
    # visible (create_app also calls this, idempotently).
    configure_logging()
    uvicorn.run(
        "analyzer.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def osv_sync_main() -> None:
    """CLI entry point: download OSV advisory data for one or more ecosystems into the store."""
    parser = argparse.ArgumentParser(
        description="Download OSV advisory data into the local store",
    )
    parser.add_argument(
        "--ecosystem",
        nargs="+",
        metavar="ECOSYSTEM",
        default=list(DEFAULT_OSV_ECOSYSTEMS),
        help=(
            "Top-level OSV ecosystems to sync. Default: the supported package surface "
            f"({', '.join(DEFAULT_OSV_ECOSYSTEMS)}); Windows has no OSV export and is "
            "reported as unsupported coverage. GHSA advisories ride inside the "
            "PyPI/npm exports, so no separate feed is needed. Pass an "
            "explicit list to narrow the download, e.g. --ecosystem Debian PyPI npm."
        ),
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "osv",
        help="Local OSV store directory (default: data/osv)",
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        help=(
            "Import pre-downloaded <ecosystem>.zip files instead of using the network "
            "(for example 'Debian.zip' and 'Rocky Linux.zip')"
        ),
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="validate the count-bearing manifest and local indexes without downloading",
    )
    parser.add_argument(
        "--index-only",
        action="store_true",
        help=(
            "retain only the disk-backed SQLite package index, not expanded JSON "
            "records (recommended for runtime stores)"
        ),
    )
    args = parser.parse_args()
    configure_logging()

    if args.verify_only:
        manifest = read_complete_manifest(args.db)
        actual_counts = OsvStore.load_dir(args.db).ecosystem_record_counts
        expected = set(args.ecosystem)
        valid = bool(
            manifest is not None
            and expected <= manifest.ecosystems
            and all(
                actual_counts.get(ecosystem, 0) == count
                for ecosystem, count in manifest.record_counts.items()
            )
        )
        if not valid:
            print("OSV corpus manifest/count verification failed", file=sys.stderr)
            sys.exit(1)
        print("OSV corpus manifest/count verification passed")
        return

    failures = 0
    record_counts: dict[str, int] = {}
    marker = args.db / ".complete"
    marker.unlink(missing_ok=True)
    for ecosystem in args.ecosystem:
        try:
            if args.archive_dir is None:
                count = sync_ecosystem(
                    ecosystem,
                    args.db,
                    retain_json=not args.index_only,
                )
            else:
                count = sync_ecosystem_archive(
                    ecosystem,
                    args.db,
                    args.archive_dir / f"{ecosystem}.zip",
                    retain_json=not args.index_only,
                )
        except OSError as exc:  # URLError/HTTPError/timeout all subclass OSError
            failures += 1
            print(f"failed to sync {ecosystem}: {exc}", file=sys.stderr)
            continue
        if count <= 0:
            failures += 1
            print(
                f"failed to sync {ecosystem}: export contained no valid matchable records",
                file=sys.stderr,
            )
            continue
        record_counts[ecosystem] = count
        print(f"wrote {count} OSV records to {args.db / ecosystem}")
    if failures:
        sys.exit(1)
    write_complete_manifest(args.db, args.ecosystem, record_counts)


def debian_tracker_sync_main() -> None:
    """CLI entry point: build or verify the Debian Security Tracker index."""
    parser = argparse.ArgumentParser(
        description="Build the exact-source-version Debian Security Tracker index",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "debian-tracker",
        help="Local tracker index directory (default: data/debian-tracker)",
    )
    parser.add_argument(
        "--json-file",
        type=Path,
        help="Import a pre-downloaded official tracker JSON file instead of using the network",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="validate that a non-empty, non-stale tracker index can be opened",
    )
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(
            os.getenv(
                "ANALYZER_DEBIAN_TRACKER_MAX_AGE_HOURS",
                str(DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS / 3600),
            )
        ),
        help="maximum accepted index age for --verify-only (default: 48 hours)",
    )
    parser.add_argument(
        "--allow-stale",
        action="store_true",
        help="with --verify-only, accept a structurally valid but stale index",
    )
    args = parser.parse_args()
    configure_logging()

    if args.max_age_hours <= 0:
        parser.error("--max-age-hours must be positive")

    if args.verify_only:
        store = DebianTrackerStore.load(
            args.db,
            max_age_seconds=args.max_age_hours * 3600,
        )
        valid = store.available and (args.allow_stale or not store.stale)
        age = store.age_seconds()
        store.close()
        if not valid:
            reason = "stale" if store.available and store.stale else "invalid or empty"
            print(f"Debian tracker index verification failed: {reason}", file=sys.stderr)
            sys.exit(1)
        print(f"Debian tracker index verification passed (age_hours={(age or 0.0) / 3600:.2f})")
        return

    try:
        records, packages = sync_debian_tracker(args.db, json_file=args.json_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"failed to sync Debian tracker: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"wrote {records} Debian tracker rows for {packages} source packages to {args.db}")


def detect_main() -> None:
    """CLI entry point: match stored asset reports against the local OSV store and emit findings."""
    parser = argparse.ArgumentParser(
        description="Match ingested AssetReports against the local OSV store",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Data directory for ingest stores (default: data)",
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=None,
        help="Legacy: read AssetReports from this JSONL file instead of --data-dir store",
    )
    parser.add_argument(
        "--storage",
        default=None,
        help="Backend for --data-dir: jsonl or sqlite (default: ANALYZER_STORAGE env or jsonl)",
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
    configure_logging()

    store = OsvStore.load_dir(args.db)
    print(f"loaded {store.record_count} OSV records from {args.db}", file=sys.stderr)

    if args.reports is not None:
        report_rows = JsonlStore(args.reports).tail(args.limit)
    else:
        report_rows = create_store(
            args.data_dir,
            "asset_reports",
            backend=args.storage,
        ).tail(args.limit)

    reports = [AssetReport.model_validate(row) for row in report_rows]

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


def migrate_storage_main() -> None:
    """CLI entry point: migrate JSONL ingest files under data/ into the SQLite analyzer.db store."""
    parser = argparse.ArgumentParser(
        description="Migrate JSONL ingest files under data/ into SQLite analyzer.db",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Data directory containing *.jsonl and/or analyzer.db (default: data)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Import even when target SQLite tables already contain rows",
    )
    args = parser.parse_args()
    configure_logging()

    counts = migrate_jsonl_to_sqlite(args.data_dir, force=args.force)
    total = sum(counts.values())
    for table, count in counts.items():
        if count:
            print(f"imported {count} row(s) into {table}")
        else:
            print(f"skipped {table} (no jsonl rows or sqlite already populated)")
    if total == 0:
        print(
            "nothing imported — set ANALYZER_STORAGE=sqlite and restart analyzer-api",
            file=sys.stderr,
        )
    else:
        print(f"done: {total} total row(s) -> {args.data_dir / 'analyzer.db'}")
