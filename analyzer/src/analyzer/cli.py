"""CLI entry points for the analyzer package."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import uvicorn

from .detect import OsvStore, detect_report, ecosystem_for_os, sync_ecosystem
from .logging_config import configure_logging
from .schemas import (
    Alert,
    AssetReport,
    AttackPath,
    CapabilityGraph,
    DetectionResult,
    GuardEventBatch,
    TraceBatch,
)
from .storage import JsonlStore, create_store, migrate_jsonl_to_sqlite

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"
DEFAULT_OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"
DEFAULT_DATA_DIR = Path("data")

# Default OSV ecosystems to sync — exactly the surface the agent emits packages
# for: dpkg (Debian/Ubuntu), apk (Alpine), rpm (Rocky/Alma/openSUSE Leap), and the
# language collectors (PyPI, npm). GHSA advisories need no separate feed — OSV
# merges them into each language ecosystem's export (PyPI/all.zip, npm/all.zip),
# so syncing PyPI+npm covers GHSA-derived findings for collected language packages.
# Deliberately NOT here: SLES/RHEL/CentOS/Fedora (OSV keys them by CPE/product-
# module, unreproducible from os-release — see sbom.rs::osv_ecosystem), and
# Maven/Go/RubyGems/etc. (no agent collector emits them — pure dead weight).
DEFAULT_OSV_ECOSYSTEMS = (
    "Debian",
    "Ubuntu",
    "Alpine",
    "Rocky Linux",
    "AlmaLinux",
    "openSUSE",
    "PyPI",
    "npm",
)

EXPORTABLE: dict[str, type] = {
    "AssetReport": AssetReport,
    "TraceBatch": TraceBatch,
    "GuardEventBatch": GuardEventBatch,
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

    This is the API contract (routes + request/response models, including the
    scan / credential / attack-path models that are *not* in ``schemas-json/``).
    Written sorted + indented so a CI ``git diff`` is a stable drift gate.
    """
    # Imported lazily: building the app pulls in the whole API layer, which the
    # other CLI entry points (schema export, osv-sync) have no need for.
    from .api import create_app

    schema = create_app().openapi()
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
            "Top-level OSV ecosystems to sync. Default: the full surface the agent "
            f"emits packages for ({', '.join(DEFAULT_OSV_ECOSYSTEMS)}); GHSA advisories "
            "ride inside the PyPI/npm exports, so no separate feed is needed. Pass an "
            "explicit list to narrow the download, e.g. --ecosystem Debian PyPI npm."
        ),
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DATA_DIR / "osv",
        help="Local OSV store directory (default: data/osv)",
    )
    args = parser.parse_args()
    configure_logging()

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


# SSH deploy binaries are resolved by the deploy layer from the target's probed
# arch (x86_64 / aarch64) under ANALYZER_AGENT_TARGET_DIR — `--agent-binary` is an
# explicit override. WinRM (Windows) has no arch probe, so it keeps a fixed .exe.
_DEFAULT_AGENT_WINRM = "../agent/target/x86_64-pc-windows-msvc/release/agent-collect-host.exe"


def _resolve_ssh_password(arg: str | None, from_stdin: bool) -> str | None:
    if from_stdin:
        if sys.stdin.isatty():
            print("ssh password: ", end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline().rstrip("\r\n")
        if not line:
            raise SystemExit("--ssh-password-stdin given but stdin was empty")
        return line
    return arg or None


def scan_main() -> None:
    """CLI entry point: deploy `agentd` to a target, scan, pull results, optionally upload.

    This is analyzer's cross-machine orchestration (formerly the Rust ``agent-remote``
    crate): upload the probe to the machine under test, invoke ``agentd host``,
    retrieve the per-asset JSON, and assemble / upload an ``AssetReport``.
    """
    parser = argparse.ArgumentParser(
        description="Ship the agent probe to a target over SSH/WinRM, scan, pull JSON back",
    )
    parser.add_argument(
        "--ssh-host",
        metavar="USER@HOST",
        help="user@host target (required for ssh/winrm; ignored for --transport local)",
    )
    parser.add_argument("--transport", choices=("ssh", "winrm", "local"), default="ssh")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-identity", type=Path, default=None, help="override managed key path")
    parser.add_argument(
        "--ssh-password",
        default=os.environ.get("SCDR_SSH_PASSWORD"),
        help="one-shot password to install the managed key (env SCDR_SSH_PASSWORD)",
    )
    parser.add_argument("--ssh-password-stdin", action="store_true", help="read password on stdin")
    parser.add_argument(
        "--winrm-password",
        default=os.environ.get("AGENT_WINRM_PASSWORD"),
        help="WinRM password (env AGENT_WINRM_PASSWORD); falls back to --ssh-password",
    )
    parser.add_argument("--winrm-port", type=int, default=5986)
    parser.add_argument("--winrm-insecure", action="store_true", help="WinRM over HTTP (port 5985)")
    parser.add_argument("--winrm-skip-cert-check", action="store_true", help="skip TLS validation")
    parser.add_argument("--revoke-key", action="store_true", help="remove the managed key and exit")
    parser.add_argument("-t", "--target", default="host", help="host|packages|sbom|...|all")
    parser.add_argument("-o", "--output", type=Path, default=Path("."), help="local output dir")
    parser.add_argument("--task-id", default=None, help="stable remote work-dir id")
    parser.add_argument("--agent-binary", type=Path, default=None, help="agent binary to ship")
    parser.add_argument("--scan-root", default=None, help="filesystem root on the target")
    parser.add_argument("--windows-packages", default="apps", help="full|apps")
    parser.add_argument(
        "--upload", metavar="URL", default=None, help="POST AssetReport to analyzer"
    )
    parser.add_argument(
        "--malware", action="store_true", help="also run the built-in malware scan (SSH/Linux only)"
    )
    parser.add_argument(
        "--malware-jobs", type=int, default=None, help="parallel malware scan workers"
    )
    parser.add_argument(
        "--capability",
        choices=("host", "trace", "guard"),
        default="host",
        help="kcatta capability to deploy: host scan (default) | trace capture | guard daemon",
    )
    # flow (one-shot capture) options
    parser.add_argument("--pcap", action="store_true", help="flow: live libpcap capture on target")
    parser.add_argument("--iface", default="any", help="flow: pcap interface (with --pcap)")
    parser.add_argument("--duration", type=int, default=5, help="flow: pcap seconds (with --pcap)")
    parser.add_argument("--bpf", default="tcp or udp or icmp", help="flow: BPF filter")
    # guard (persistent daemon) options
    parser.add_argument(
        "--guard-config", type=Path, default=None, help="guard: local guard.json to upload + use"
    )
    args = parser.parse_args()
    configure_logging()

    from . import deploy

    if args.transport in ("ssh", "winrm") and not args.ssh_host:
        raise SystemExit("--ssh-host USER@HOST is required for --transport ssh/winrm")

    if args.revoke_key:
        if args.transport != "ssh":
            raise SystemExit("--revoke-key is only supported with --transport ssh")
        password = _resolve_ssh_password(args.ssh_password, args.ssh_password_stdin)
        removed = deploy.revoke_key(args.ssh_host, args.ssh_port, args.ssh_identity, password)
        print(
            f"revoked managed key from {args.ssh_host}"
            if removed
            else f"no managed key found on {args.ssh_host} (already clean)",
            file=sys.stderr,
        )
        if args.ssh_identity is None:
            key = deploy.managed_key_path(args.ssh_host, args.ssh_port)
            for path in (key, key.with_name(key.name + ".pub")):
                if path.exists():
                    path.unlink()
                    print(f"removed local {path}", file=sys.stderr)
        return

    # --- trace / guard: SSH-only remote scheduling (distinct from the host scan path) ---
    if args.capability in ("trace", "guard"):
        if args.transport != "ssh":
            raise SystemExit(
                f"--capability {args.capability} is only supported with --transport ssh"
            )
        password = _resolve_ssh_password(args.ssh_password, args.ssh_password_stdin)

        if args.capability == "trace":
            trace_json = deploy.run_trace_capture(
                deploy.TraceCaptureOptions(
                    target=args.ssh_host,
                    agent_binary=args.agent_binary,
                    output_dir=args.output,
                    port=args.ssh_port,
                    identity=args.ssh_identity,
                    password=password,
                    task_id=args.task_id,
                    pcap=args.pcap,
                    iface=args.iface,
                    duration=args.duration,
                    bpf=args.bpf,
                )
            )
            print(f"wrote {trace_json}", file=sys.stderr)
            if args.upload is not None:
                deploy.upload_trace_batch(trace_json, args.upload)
                print(f"uploaded TraceBatch to {args.upload}", file=sys.stderr)
            return

        # guard: the daemon pushes to analyzer itself, so --upload is required.
        if args.upload is None:
            raise SystemExit(
                "--capability guard requires --upload <analyzer-url> (the daemon pushes there)"
            )
        pid = deploy.start_guard_daemon(
            deploy.GuardDeployOptions(
                target=args.ssh_host,
                agent_binary=args.agent_binary,
                upload=args.upload,
                config=args.guard_config,
                port=args.ssh_port,
                identity=args.ssh_identity,
                password=password,
            )
        )
        print(
            f"started agent-respond on {args.ssh_host} (pid {pid}) -> {args.upload}",
            file=sys.stderr,
        )
        return

    if args.malware and args.transport == "winrm":
        raise SystemExit("--malware is not supported with --transport winrm (SSH/Linux only)")

    if args.transport == "local":
        # Scan the analyzer's OWN host: run the bundled agent-collect-host in place (no SSH).
        report = deploy.run_local_agent_scan(
            deploy.LocalScanOptions(
                output_dir=args.output,
                agent_binary=args.agent_binary,
                scan_target=args.target,
                # None → ANALYZER_LOCAL_SCAN_ROOT or "/".
                scan_root=args.scan_root,
                windows_packages=args.windows_packages,
                task_id=args.task_id,
                malware=deploy.MalwareAgentOptions(jobs=args.malware_jobs)
                if args.malware
                else None,
            )
        )
    elif args.transport == "ssh":
        password = _resolve_ssh_password(args.ssh_password, args.ssh_password_stdin)
        opts = deploy.AgentScanOptions(
            target=args.ssh_host,
            agent_binary=args.agent_binary,
            output_dir=args.output,
            scan_target=args.target,
            scan_root=args.scan_root or "/",
            port=args.ssh_port,
            identity=args.ssh_identity,
            password=password,
            task_id=args.task_id,
            windows_packages=args.windows_packages,
            malware=deploy.MalwareAgentOptions(jobs=args.malware_jobs)
            if args.malware
            else None,
        )
        report = deploy.run_agent_scan(opts)
    elif args.transport == "winrm":
        from .deploy.winrm import WinRmAgentScanOptions, WinRmOptions, run_winrm_agent_scan

        password = args.winrm_password or _resolve_ssh_password(
            args.ssh_password, args.ssh_password_stdin
        )
        if not password:
            raise SystemExit("WinRM password required (--winrm-password / AGENT_WINRM_PASSWORD)")
        port = 5985 if args.winrm_insecure and args.winrm_port == 5986 else args.winrm_port
        winrm_opts = WinRmOptions.from_user_host(
            args.ssh_host,
            password,
            port=port,
            use_ssl=not args.winrm_insecure,
            skip_cert_check=args.winrm_skip_cert_check,
        )
        report = run_winrm_agent_scan(
            WinRmAgentScanOptions(
                winrm=winrm_opts,
                agent_binary=args.agent_binary or Path(_DEFAULT_AGENT_WINRM),
                output_dir=args.output,
                scan_target=args.target,
                scan_root=args.scan_root or "C:\\",
                task_id=args.task_id,
                windows_packages=args.windows_packages,
            )
        )
    else:  # unreachable: argparse restricts --transport to the choices above
        raise SystemExit(f"unsupported --transport {args.transport!r}")

    print(f"task-id {report.task_id}", file=sys.stderr)
    for path in report.files:
        print(f"wrote {path}", file=sys.stderr)

    # Assemble + (optionally) upload an AssetReport when host.json was pulled.
    if args.upload is not None or args.target in ("host", "all"):
        asset_report = deploy.finalize_asset_report(args.output)
        report_path = deploy.write_asset_report(args.output, asset_report)
        print(f"wrote {report_path}", file=sys.stderr)
        if args.upload is not None:
            deploy.upload_asset_report(asset_report, args.upload)
            print(f"uploaded report to {args.upload}", file=sys.stderr)
