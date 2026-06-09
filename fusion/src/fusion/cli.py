"""CLI entry points for the fusion package."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import uvicorn

from .detect import OsvStore, detect_report, ecosystem_for_os, sync_ecosystem
from .schemas import (
    Alert,
    AssetReport,
    AttackPath,
    CapabilityGraph,
    DetectionResult,
    FlowBatch,
    GuardEventBatch,
)
from .storage import JsonlStore, create_store, migrate_jsonl_to_sqlite

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"
DEFAULT_DATA_DIR = Path("data")

EXPORTABLE: dict[str, type] = {
    "AssetReport": AssetReport,
    "FlowBatch": FlowBatch,
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
        description="Export JSON Schemas for posture data contracts",
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
    """CLI entry point: run the fusion HTTP API via uvicorn."""
    parser = argparse.ArgumentParser(
        description="Run the posture fusion HTTP API",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = parser.parse_args()

    uvicorn.run(
        "fusion.api:create_app",
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
        help="Backend for --data-dir: jsonl or sqlite (default: FUSION_STORAGE env or jsonl)",
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
    """CLI entry point: migrate JSONL ingest files under data/ into the SQLite fusion.db store."""
    parser = argparse.ArgumentParser(
        description="Migrate JSONL ingest files under data/ into SQLite fusion.db",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Data directory containing *.jsonl and/or fusion.db (default: data)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Import even when target SQLite tables already contain rows",
    )
    args = parser.parse_args()

    counts = migrate_jsonl_to_sqlite(args.data_dir, force=args.force)
    total = sum(counts.values())
    for table, count in counts.items():
        if count:
            print(f"imported {count} row(s) into {table}")
        else:
            print(f"skipped {table} (no jsonl rows or sqlite already populated)")
    if total == 0:
        print(
            "nothing imported — set FUSION_STORAGE=sqlite and restart fusion-api",
            file=sys.stderr,
        )
    else:
        print(f"done: {total} total row(s) -> {args.data_dir / 'fusion.db'}")


# Default static `posture-host` probe binary, relative to the posture monorepo
# layout (fusion/ and agent/ are siblings). Override with --agent-binary.
_DEFAULT_AGENT_SSH = "../agent/target/x86_64-unknown-linux-musl/release/posture-host"
_DEFAULT_AGENT_WINRM = "../agent/target/x86_64-pc-windows-msvc/release/posture-host.exe"
# Default lean binaries for the flow / guard capabilities (SSH/Linux).
_DEFAULT_FLOW_SSH = "../agent/target/x86_64-unknown-linux-musl/release/posture-flow"
_DEFAULT_GUARD_SSH = "../agent/target/x86_64-unknown-linux-musl/release/posture-guard"


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
    """CLI entry point: deploy `agent` to a target, scan, pull results, optionally upload.

    This is fusion's cross-machine orchestration (formerly the Rust ``agent-remote``
    crate): upload the probe to the machine under test, invoke ``agent host``,
    retrieve the per-asset JSON, and assemble / upload an ``AssetReport``.
    """
    parser = argparse.ArgumentParser(
        description="Ship the agent probe to a target over SSH/WinRM, scan, pull JSON back",
    )
    parser.add_argument("--ssh-host", required=True, metavar="USER@HOST", help="user@host target")
    parser.add_argument("--transport", choices=("ssh", "winrm"), default="ssh")
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
    parser.add_argument("--upload", metavar="URL", default=None, help="POST AssetReport to fusion")
    parser.add_argument(
        "--malware", action="store_true", help="also run the built-in malware scan (SSH/Linux only)"
    )
    parser.add_argument(
        "--malware-jobs", type=int, default=None, help="parallel malware scan workers"
    )
    parser.add_argument(
        "--capability",
        choices=("host", "flow", "guard"),
        default="host",
        help="posture capability to deploy: host scan (default) | flow capture | guard daemon",
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

    from . import deploy

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

    # --- flow / guard: SSH-only remote scheduling (distinct from the host scan path) ---
    if args.capability in ("flow", "guard"):
        if args.transport != "ssh":
            raise SystemExit(
                f"--capability {args.capability} is only supported with --transport ssh"
            )
        password = _resolve_ssh_password(args.ssh_password, args.ssh_password_stdin)

        if args.capability == "flow":
            flow_json = deploy.run_flow_capture(
                deploy.FlowCaptureOptions(
                    target=args.ssh_host,
                    agent_binary=args.agent_binary or Path(_DEFAULT_FLOW_SSH),
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
            print(f"wrote {flow_json}", file=sys.stderr)
            if args.upload is not None:
                deploy.upload_flow_batch(flow_json, args.upload)
                print(f"uploaded FlowBatch to {args.upload}", file=sys.stderr)
            return

        # guard: the daemon pushes to fusion itself, so --upload is required.
        if args.upload is None:
            raise SystemExit(
                "--capability guard requires --upload <fusion-url> (the daemon pushes there)"
            )
        pid = deploy.start_guard_daemon(
            deploy.GuardDeployOptions(
                target=args.ssh_host,
                agent_binary=args.agent_binary or Path(_DEFAULT_GUARD_SSH),
                upload=args.upload,
                config=args.guard_config,
                port=args.ssh_port,
                identity=args.ssh_identity,
                password=password,
            )
        )
        print(
            f"started posture-guard on {args.ssh_host} (pid {pid}) -> {args.upload}",
            file=sys.stderr,
        )
        return

    if args.malware and args.transport == "winrm":
        raise SystemExit("--malware is not supported with --transport winrm (SSH/Linux only)")

    if args.transport == "ssh":
        binary = args.agent_binary or Path(_DEFAULT_AGENT_SSH)
        password = _resolve_ssh_password(args.ssh_password, args.ssh_password_stdin)
        opts = deploy.AgentScanOptions(
            target=args.ssh_host,
            agent_binary=binary,
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
    else:
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
