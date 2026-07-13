"""Console entry points for Form."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path


def api_main() -> None:
    parser = argparse.ArgumentParser(description="Run the kcatta Form control plane")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10067)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(
        "kcatta_form.api.app:create_app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=True,
    )


def agent_api_main(argv: Sequence[str] | None = None) -> None:
    """Run Form's dedicated Agent ingest listener with mandatory mTLS.

    This listener exposes only Agent-facing metadata/ingest routes.  Admin keeps
    using the control listener, so requiring a client certificate here cannot
    accidentally turn every browser/server-side Admin request into an mTLS
    client.  Certificate identity is taken from the live TLS transport by the
    custom h11 protocol, never from caller-provided HTTP headers.
    """
    parser = argparse.ArgumentParser(description="Run the kcatta Form Agent mTLS API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=10443)
    parser.add_argument(
        "--certfile",
        type=Path,
        default=Path(os.getenv("FORM_AGENT_TLS_CERT", "/agent-tls/current/server-cert.pem")),
    )
    parser.add_argument(
        "--keyfile",
        type=Path,
        default=Path(os.getenv("FORM_AGENT_TLS_KEY", "/agent-tls/current/server-key.pem")),
    )
    parser.add_argument(
        "--client-ca",
        type=Path,
        default=Path(os.getenv("FORM_AGENT_TLS_CLIENT_CA", "/agent-tls/ca-cert.pem")),
    )
    parser.add_argument(
        "--tls-reload-poll-seconds",
        type=float,
        default=os.getenv("FORM_AGENT_TLS_RELOAD_POLL_SECONDS", "5"),
    )
    parser.add_argument(
        "--graceful-shutdown-seconds",
        type=int,
        default=os.getenv("FORM_AGENT_TLS_GRACEFUL_SHUTDOWN_SECONDS", "30"),
    )
    args = parser.parse_args(argv)

    from .agent_listener_runtime import (
        ListenerTlsMaterialError,
        run_reloadable_agent_listener,
    )

    try:
        run_reloadable_agent_listener(
            host=args.host,
            port=args.port,
            certificate=args.certfile,
            private_key=args.keyfile,
            client_ca=args.client_ca,
            poll_seconds=args.tls_reload_poll_seconds,
            graceful_shutdown_seconds=args.graceful_shutdown_seconds,
        )
    except (ListenerTlsMaterialError, ValueError) as exc:
        parser.error(str(exc))


def migrate_control_state_main(argv: Sequence[str] | None = None) -> None:
    """Copy legacy Analyzer targets/jobs into Form's own data directory."""

    parser = argparse.ArgumentParser(
        description=(
            "Migrate only legacy Analyzer scan targets/jobs into Form. "
            "Run offline with Form stopped."
        )
    )
    parser.add_argument(
        "--analyzer-data-dir",
        type=Path,
        required=True,
        help="read-only path containing the old analyzer.db or scan-*.jsonl files",
    )
    parser.add_argument(
        "--form-data-dir",
        type=Path,
        default=Path(os.getenv("FORM_DATA_DIR", "data")),
        help="destination Form data directory (default: FORM_DATA_DIR or ./data)",
    )
    parser.add_argument(
        "--source-storage",
        choices=("auto", "jsonl", "sqlite"),
        default="auto",
        help="legacy backend; auto prefers a populated analyzer.db (default: auto)",
    )
    parser.add_argument(
        "--form-storage",
        choices=("jsonl", "sqlite"),
        default=os.getenv("FORM_STORAGE", "jsonl"),
        help="destination backend (default: FORM_STORAGE or jsonl)",
    )
    args = parser.parse_args(argv)

    from .control_state_migration import ControlStateMigrationError, migrate_control_state

    try:
        result = migrate_control_state(
            args.analyzer_data_dir,
            args.form_data_dir,
            source_storage=args.source_storage,
            form_storage=args.form_storage,
        )
    except (ControlStateMigrationError, OSError) as exc:
        parser.exit(1, f"form-migrate-control-state: error: {exc}\n")

    print(
        f"source={result.source_storage} "
        f"targets={result.targets_migrated}/{result.unique_targets} "
        f"jobs={result.jobs_migrated}/{result.unique_jobs} "
        f"in_flight_failed={result.in_flight_jobs_failed}"
    )
    if result.targets_skipped or result.jobs_skipped:
        print(
            "existing Form records skipped: "
            f"targets={result.targets_skipped} jobs={result.jobs_skipped}"
        )
    print(
        "Only targets/jobs were copied. Analyzer telemetry, credentials, tokens, "
        "and resident Guard processes were not migrated."
    )
