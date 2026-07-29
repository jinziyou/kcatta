"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import metrics as metrics_mod
from ..detect import (
    DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS,
    DEFAULT_OSV_ECOSYSTEMS,
    DebianTrackerStore,
    OsvStore,
    ecosystem_family,
    read_complete_manifest,
    sync_debian_tracker,
)
from ..logging_config import configure_logging
from ..storage import StorageCapacityError, create_store
from . import alerts, detect, ingest, predict, reports
from .auth import require_internal_token, require_metrics_token
from .idempotency import DEFAULT_WINDOW
from .ingest_queue import DerivedWorker, IngestLedger
from .report_projection_cache import ReportProjectionCache

logger = logging.getLogger("analyzer.api")

DEFAULT_DATA_DIR = Path("data")
DEFAULT_OSV_DIR = DEFAULT_DATA_DIR / "osv"
DEFAULT_DEBIAN_TRACKER_DIR = DEFAULT_DATA_DIR / "debian-tracker"
DEFAULT_DEBIAN_TRACKER_REFRESH_SECONDS = 24 * 60 * 60
# Reject oversized ingest bodies (DoS guard); override via ANALYZER_MAX_BODY_BYTES.
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024
DEFAULT_REPORT_PROJECTION_CACHE_ENTRIES = 64
DEFAULT_REPORT_PROJECTION_CACHE_BYTES = 64 * 1024 * 1024


def _data_dir() -> Path:
    env = os.getenv("ANALYZER_DATA_DIR")
    return Path(env) if env else DEFAULT_DATA_DIR


def _osv_dir() -> Path:
    env = os.getenv("ANALYZER_OSV_DIR")
    return Path(env) if env else DEFAULT_OSV_DIR


def _debian_tracker_dir() -> Path:
    env = os.getenv("ANALYZER_DEBIAN_TRACKER_DIR")
    return Path(env) if env else DEFAULT_DEBIAN_TRACKER_DIR


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _non_negative_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _set_debian_tracker_metrics(store: DebianTrackerStore) -> None:
    metrics_mod.set_gauge("kcatta_debian_tracker_records", float(store.record_count))
    metrics_mod.set_gauge("kcatta_debian_tracker_stale", float(store.stale))
    metrics_mod.set_gauge(
        "kcatta_debian_tracker_age_seconds",
        float(store.age_seconds() or 0.0),
    )


async def _refresh_debian_tracker_once(
    application: FastAPI,
    directory: Path,
    max_age_seconds: float,
    *,
    syncer: Callable[[str | Path], tuple[int, int]] = sync_debian_tracker,
) -> bool:
    """Atomically refresh and hot-swap the tracker, preserving the old store on failure."""
    try:
        await asyncio.to_thread(syncer, directory)
        replacement = DebianTrackerStore.load(
            directory,
            max_age_seconds=max_age_seconds,
        )
        if not replacement.available or replacement.stale:
            replacement.close()
            raise OSError("refreshed Debian tracker index is invalid or stale")
    except Exception as exc:  # noqa: BLE001 - background refresh must preserve serving
        metrics_mod.inc("kcatta_debian_tracker_refresh_failures_total")
        _set_debian_tracker_metrics(application.state.debian_tracker_store)
        logger.warning("Debian Security Tracker background refresh failed: %s", exc)
        return False

    previous = application.state.debian_tracker_store
    application.state.debian_tracker_store = replacement
    previous.close()
    metrics_mod.inc("kcatta_debian_tracker_refresh_success_total")
    _set_debian_tracker_metrics(replacement)
    logger.info(
        "refreshed Debian Security Tracker: %d rows across %d source packages",
        replacement.record_count,
        replacement.source_package_count,
    )
    return True


async def _debian_tracker_refresh_loop(
    application: FastAPI,
    directory: Path,
    max_age_seconds: float,
    refresh_seconds: float,
) -> None:
    if (
        not application.state.debian_tracker_store.available
        or application.state.debian_tracker_store.stale
    ):
        await _refresh_debian_tracker_once(application, directory, max_age_seconds)
    while True:
        await asyncio.sleep(refresh_seconds)
        await _refresh_debian_tracker_once(application, directory, max_age_seconds)


def create_app(
    data_dir: Path | None = None,
    osv_dir: Path | None = None,
    debian_tracker_dir: Path | None = None,
    osv_ecosystem: str | None = None,
    api_token: str | None = None,
    storage_backend: str | None = None,
    allow_insecure_no_auth: bool | None = None,
    derived_async: bool | None = None,
    debian_tracker_auto_sync: bool | None = None,
    debian_tracker_max_age_hours: float | None = None,
    debian_tracker_refresh_seconds: float | None = None,
    report_projection_cache_entries: int | None = None,
    report_projection_cache_bytes: int | None = None,
    metrics_token: str | None = None,
) -> FastAPI:
    """Build the FastAPI app and wire its dependencies.

    ``data_dir`` overrides the default, which itself can be set via the
    ``ANALYZER_DATA_DIR`` environment variable. Tests use this to redirect
    persistence to a temporary directory.

    ``osv_dir`` is the local OSV advisory store loaded once at startup for
    the ``/detect`` endpoint (env ``ANALYZER_OSV_DIR``, default ``data/osv``);
    a missing directory yields an empty store rather than an error.
    ``osv_ecosystem`` (env ``ANALYZER_OSV_ECOSYSTEM``) pins the OSV ecosystem
    instead of deriving it per report from ``host.os``.

    ``debian_tracker_dir`` is the exact-source-version index used only for Kali
    dpkg packages whose source version is proven identical to a Debian archive
    version (env ``ANALYZER_DEBIAN_TRACKER_DIR``).

    ``api_token`` is retained as a test/backward-compatible constructor
    argument. In deployments the internal Form-to-Analyzer bearer token comes
    from ``ANALYZER_INTERNAL_TOKEN`` and protects every service route except
    ``/health`` and the separately authenticated ``/metrics`` route. Analyzer
    is an internal service; Admin and Agent authenticate to Form, not directly
    to this API. An unset token fails closed unless local development explicitly
    sets ``ANALYZER_ALLOW_INSECURE_NO_AUTH=true``.
    ``metrics_token`` (env ``ANALYZER_METRICS_TOKEN``) limits Prometheus to the
    read-only exposition route; when omitted it falls back to the internal
    token for backward compatibility outside Compose.

    ``storage_backend`` (env ``ANALYZER_STORAGE``) selects ``jsonl`` (default) or
    ``sqlite`` persistence under ``data_dir``.

    ``derived_async`` overrides ``ANALYZER_DERIVED_ASYNC``. When enabled, ingest
    acknowledges only after the full envelope is in the durable ledger and a
    leased background worker performs detection/correlation.

    The report-detail projection cache is process-local and bounded by both
    ``ANALYZER_REPORT_PROJECTION_CACHE_ENTRIES`` and
    ``ANALYZER_REPORT_PROJECTION_CACHE_BYTES``. Setting either limit to zero
    disables it.
    """

    # E1: configure business-logger handlers up front so swallowed ingest errors
    # (detection/correlation failures) are actually emitted, not silently lost.
    configure_logging()

    dir_ = data_dir if data_dir is not None else _data_dir()
    osv_dir_ = osv_dir if osv_dir is not None else _osv_dir()
    debian_tracker_dir_ = (
        debian_tracker_dir if debian_tracker_dir is not None else _debian_tracker_dir()
    )
    ecosystem_ = osv_ecosystem if osv_ecosystem is not None else os.getenv("ANALYZER_OSV_ECOSYSTEM")
    tracker_auto_sync_ = (
        debian_tracker_auto_sync
        if debian_tracker_auto_sync is not None
        else _env_bool("ANALYZER_DEBIAN_TRACKER_AUTO_SYNC", False)
    )
    tracker_max_age_seconds_ = 3600 * (
        debian_tracker_max_age_hours
        if debian_tracker_max_age_hours is not None
        else _positive_float(
            "ANALYZER_DEBIAN_TRACKER_MAX_AGE_HOURS",
            DEFAULT_DEBIAN_TRACKER_MAX_AGE_SECONDS / 3600,
        )
    )
    tracker_refresh_seconds_ = (
        debian_tracker_refresh_seconds
        if debian_tracker_refresh_seconds is not None
        else _positive_float(
            "ANALYZER_DEBIAN_TRACKER_REFRESH_SECONDS",
            DEFAULT_DEBIAN_TRACKER_REFRESH_SECONDS,
        )
    )
    if tracker_max_age_seconds_ <= 0:
        raise ValueError("debian_tracker_max_age_hours must be positive")
    if tracker_refresh_seconds_ <= 0:
        raise ValueError("debian_tracker_refresh_seconds must be positive")
    projection_cache_entries_ = (
        report_projection_cache_entries
        if report_projection_cache_entries is not None
        else _non_negative_int(
            "ANALYZER_REPORT_PROJECTION_CACHE_ENTRIES",
            DEFAULT_REPORT_PROJECTION_CACHE_ENTRIES,
        )
    )
    projection_cache_bytes_ = (
        report_projection_cache_bytes
        if report_projection_cache_bytes is not None
        else _non_negative_int(
            "ANALYZER_REPORT_PROJECTION_CACHE_BYTES",
            DEFAULT_REPORT_PROJECTION_CACHE_BYTES,
        )
    )
    if projection_cache_entries_ < 0:
        raise ValueError("report_projection_cache_entries must be non-negative")
    if projection_cache_bytes_ < 0:
        raise ValueError("report_projection_cache_bytes must be non-negative")
    token_ = api_token if api_token is not None else os.getenv("ANALYZER_INTERNAL_TOKEN") or ""
    token_ = token_.strip() or None
    metrics_token_ = (
        metrics_token if metrics_token is not None else os.getenv("ANALYZER_METRICS_TOKEN") or ""
    )
    metrics_token_ = metrics_token_.strip() or None
    if metrics_token_ and token_ and secrets.compare_digest(metrics_token_, token_):
        raise RuntimeError("ANALYZER_METRICS_TOKEN must be distinct from ANALYZER_INTERNAL_TOKEN")
    allow_insecure = (
        allow_insecure_no_auth
        if allow_insecure_no_auth is not None
        else os.getenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if not token_ and not allow_insecure:
        raise RuntimeError(
            "ANALYZER_INTERNAL_TOKEN is required; set "
            "ANALYZER_ALLOW_INSECURE_NO_AUTH=true only for isolated local development"
        )
    metrics_token_ = metrics_token_ or token_
    store_backend = storage_backend

    @asynccontextmanager
    async def lifespan(application: FastAPI):  # type: ignore[no-untyped-def]
        worker = application.state.derived_worker
        tracker_refresh_task: asyncio.Task[None] | None = None
        if application.state.derived_async:
            worker.start()
        if application.state.debian_tracker_auto_sync:
            tracker_refresh_task = asyncio.create_task(
                _debian_tracker_refresh_loop(
                    application,
                    debian_tracker_dir_,
                    tracker_max_age_seconds_,
                    tracker_refresh_seconds_,
                ),
                name="analyzer-debian-tracker-refresh",
            )
        try:
            yield
        finally:
            if tracker_refresh_task is not None:
                tracker_refresh_task.cancel()
                with suppress(asyncio.CancelledError):
                    await tracker_refresh_task
            if worker.stop():
                application.state.ingest_ledger.close()
                application.state.osv_store.close()
                application.state.debian_tracker_store.close()
            else:
                logger.warning("derived worker did not stop before shutdown timeout")

    app = FastAPI(
        title="kcatta analyzer",
        version="0.1.0",
        description="Internal ingest, detection, correlation, and reporting service.",
        lifespan=lifespan,
    )

    @app.exception_handler(StorageCapacityError)
    async def _storage_capacity_exhausted(
        request: Request, exc: StorageCapacityError
    ) -> JSONResponse:
        logger.error(
            "storage capacity rejected request %s: %s",
            getattr(request.state, "request_id", "unknown"),
            exc,
        )
        return JSONResponse(
            status_code=507,
            headers={"Retry-After": "60"},
            content={"detail": "Analyzer durable storage capacity is exhausted"},
        )

    max_body_bytes = int(os.getenv("ANALYZER_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))

    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Attach a request id (honour an inbound X-Request-ID) so a log line can be
        # tied back to one request; echoed on the response for client correlation.
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    @app.middleware("http")
    async def _limit_body_size(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Defense in depth behind Form: reject oversized forwarded payloads so a
        # malformed internal request cannot exhaust Analyzer memory/disk.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                too_big = int(content_length) > max_body_bytes
            except ValueError:
                too_big = False
            if too_big:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"request body exceeds {max_body_bytes} bytes"},
                )
        return await call_next(request)

    app.state.asset_report_store = create_store(dir_, "asset_reports", backend=store_backend)
    app.state.trace_batch_store = create_store(dir_, "trace_batches", backend=store_backend)
    app.state.guard_event_store = create_store(dir_, "guard_events", backend=store_backend)
    app.state.mde_security_store = create_store(dir_, "mde_security_batches", backend=store_backend)
    app.state.mdvm_vulnerability_store = create_store(
        dir_, "mdvm_vulnerability_batches", backend=store_backend
    )
    app.state.vulnerability_store = create_store(dir_, "vulnerabilities", backend=store_backend)
    app.state.report_projection_cache = ReportProjectionCache(
        max_entries=projection_cache_entries_,
        max_bytes=projection_cache_bytes_,
    )
    app.state.alert_store = create_store(dir_, "alerts", backend=store_backend)
    # Append-only triage overlay (status/assignee/note/suppress) keyed by alert_key.
    app.state.alert_state_store = create_store(dir_, "alert_states", backend=store_backend)
    app.state.capability_graph_store = create_store(
        dir_, "capability_graphs", backend=store_backend
    )
    app.state.osv_store = OsvStore.load_dir(osv_dir_)
    app.state.debian_tracker_store = DebianTrackerStore.load(
        debian_tracker_dir_,
        max_age_seconds=tracker_max_age_seconds_,
    )
    app.state.debian_tracker_auto_sync = tracker_auto_sync_
    app.state.debian_tracker_max_age_seconds = tracker_max_age_seconds_
    app.state.debian_tracker_refresh_seconds = tracker_refresh_seconds_
    manifest = read_complete_manifest(osv_dir_)
    actual_counts = app.state.osv_store.ecosystem_record_counts
    synced_ecosystems = (
        frozenset(
            ecosystem
            for ecosystem in manifest.ecosystems
            if actual_counts.get(ecosystem, 0) == manifest.record_counts[ecosystem]
        )
        if manifest is not None
        else None
    )
    mismatched_ecosystems = (
        manifest.ecosystems - synced_ecosystems if manifest is not None else frozenset()
    )
    expected_ecosystems = frozenset(
        {ecosystem_family(ecosystem_)} if ecosystem_ else DEFAULT_OSV_ECOSYSTEMS
    )
    missing_ecosystems = expected_ecosystems - (synced_ecosystems or frozenset())
    app.state.osv_synced_ecosystems = synced_ecosystems
    app.state.osv_expected_ecosystems = expected_ecosystems
    app.state.osv_missing_ecosystems = missing_ecosystems
    app.state.osv_mismatched_ecosystems = mismatched_ecosystems
    app.state.osv_complete = bool(
        app.state.osv_store.record_count > 0
        and manifest is not None
        and not mismatched_ecosystems
        and not missing_ecosystems
    )
    metrics_mod.set_gauge("kcatta_osv_records", float(app.state.osv_store.record_count))
    metrics_mod.set_gauge("kcatta_osv_sync_complete", float(app.state.osv_complete))
    _set_debian_tracker_metrics(app.state.debian_tracker_store)
    if app.state.osv_store.record_count == 0:
        # An empty OSV store makes vulnerability detection silently no-op
        # (detect/ingest gate on record_count > 0) — for a blue-team tool that
        # reads as "no vulnerabilities" when the truth is "not inspected". Surface
        # it loudly at startup so an operator knows to run `analyzer-osv-sync`.
        logger.warning(
            "OSV store at %s is empty — vulnerability detection is DISABLED until "
            "you populate it (run `analyzer-osv-sync`). Scanner/malware findings "
            "still flow; only OSV CVE/GHSA matching is off.",
            osv_dir_,
        )
    elif manifest is None:
        logger.warning(
            "OSV store at %s contains %d record(s) but has no valid .complete manifest — "
            "vulnerability detection will run with PARTIAL coverage until a full "
            "atomic sync succeeds.",
            osv_dir_,
            app.state.osv_store.record_count,
        )
    elif mismatched_ecosystems:
        logger.warning(
            "OSV store at %s does not match its atomic manifest for ecosystem(s): %s — "
            "affected packages are marked PARTIAL until a fresh sync succeeds.",
            osv_dir_,
            ", ".join(sorted(mismatched_ecosystems)),
        )
    elif missing_ecosystems:
        logger.warning(
            "OSV store at %s is missing expected ecosystem export(s): %s — global "
            "readiness is degraded and affected reports are marked PARTIAL.",
            osv_dir_,
            ", ".join(sorted(missing_ecosystems)),
        )
    if not app.state.debian_tracker_store.available:
        logger.warning(
            "Debian Security Tracker index at %s is empty — Kali dpkg packages remain "
            "explicitly unverified until analyzer-debian-tracker-sync succeeds.",
            debian_tracker_dir_,
        )
    elif app.state.debian_tracker_store.stale:
        logger.warning(
            "Debian Security Tracker index at %s is stale (age %.1f hours; maximum %.1f); "
            "Kali coverage remains partial until refresh succeeds.",
            debian_tracker_dir_,
            (app.state.debian_tracker_store.age_seconds() or 0.0) / 3600,
            tracker_max_age_seconds_ / 3600,
        )
    app.state.osv_ecosystem = ecosystem_
    app.state.internal_token = token_
    app.state.metrics_token = metrics_token_
    # Durable idempotency/outbox state is always SQLite, including when the raw
    # reporting backend is JSONL. This makes duplicate detection and task leases
    # atomic across restarts and multiple API worker processes.
    dedup_window = int(os.getenv("ANALYZER_INGEST_DEDUP_WINDOW", str(DEFAULT_WINDOW)))
    ledger_path_raw = os.getenv("ANALYZER_INGEST_LEDGER_PATH", "").strip()
    ledger_path = Path(ledger_path_raw) if ledger_path_raw else dir_ / "ingest-ledger.db"
    app.state.ingest_ledger = IngestLedger(ledger_path, max_completed=dedup_window)
    app.state.derived_async = (
        derived_async if derived_async is not None else _env_bool("ANALYZER_DERIVED_ASYNC", False)
    )
    app.state.derived_worker = DerivedWorker(
        app.state.ingest_ledger,
        lambda task: ingest.process_queued_ingest(task, app.state),
        observer=ingest._observe_outcome,
    )

    def queue_counts() -> dict[str, int]:
        counts = app.state.ingest_ledger.counts()
        metrics_mod.set_gauge("kcatta_derived_queue_pending", float(counts["pending"]))
        metrics_mod.set_gauge("kcatta_derived_queue_processing", float(counts["processing"]))
        metrics_mod.set_gauge("kcatta_derived_queue_partial", float(counts["partial"]))
        return counts

    internal_auth = [Depends(require_internal_token)]
    metrics_auth = [Depends(require_metrics_token)]

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:
        """Liveness probe returning a static ok status."""
        return {"status": "ok"}

    @app.get("/ready", tags=["meta"], dependencies=internal_auth)
    async def ready() -> JSONResponse:
        """Readiness with degraded (not unready) empty-OSV signal.

        An empty OSV corpus disables CVE matching but Analyzer remains
        serviceable for ingest/malware/alerts. Orchestrators should treat HTTP
        200 + ``status=degraded`` as ready-to-serve with reduced coverage —
        never as a crash-loop reason (unlike 503).
        """
        count = int(getattr(app.state.osv_store, "record_count", 0) or 0)
        complete = bool(getattr(app.state, "osv_complete", False))
        metrics_mod.set_gauge("kcatta_osv_records", float(count))
        metrics_mod.set_gauge("kcatta_osv_sync_complete", float(complete))
        tracker_store = app.state.debian_tracker_store
        tracker_count = int(tracker_store.record_count)
        tracker_stale = tracker_store.stale
        tracker_age = tracker_store.age_seconds()
        _set_debian_tracker_metrics(tracker_store)
        empty = count == 0
        partial = not empty and not complete
        derived_queue = queue_counts()
        return JSONResponse(
            status_code=200,
            content={
                "status": (
                    "degraded"
                    if empty or partial or tracker_count == 0 or tracker_stale
                    else "ready"
                ),
                "osv": "empty" if empty else ("partial" if partial else "ready"),
                "osv_record_count": count,
                "osv_complete": complete,
                "osv_synced_ecosystems": sorted(
                    getattr(app.state, "osv_synced_ecosystems", None) or ()
                ),
                "osv_missing_ecosystems": sorted(getattr(app.state, "osv_missing_ecosystems", ())),
                "osv_mismatched_ecosystems": sorted(
                    getattr(app.state, "osv_mismatched_ecosystems", ())
                ),
                "debian_tracker": (
                    "empty" if tracker_count == 0 else ("stale" if tracker_stale else "ready")
                ),
                "debian_tracker_record_count": tracker_count,
                "debian_tracker_source_package_count": int(tracker_store.source_package_count),
                "debian_tracker_synced_at": (
                    tracker_store.synced_at.isoformat() if tracker_store.synced_at else None
                ),
                "debian_tracker_age_seconds": tracker_age,
                "debian_tracker_max_age_seconds": tracker_store.max_age_seconds,
                "debian_tracker_auto_sync": bool(app.state.debian_tracker_auto_sync),
                "debian_tracker_refresh_seconds": app.state.debian_tracker_refresh_seconds,
                "derived_async": bool(app.state.derived_async),
                "derived_queue": derived_queue,
            },
        )

    @app.get(
        "/metrics",
        tags=["meta"],
        response_class=PlainTextResponse,
        dependencies=metrics_auth,
    )
    async def metrics() -> PlainTextResponse:
        """Prometheus text exposition (process-local counters/gauges)."""
        count = int(getattr(app.state.osv_store, "record_count", 0) or 0)
        complete = bool(getattr(app.state, "osv_complete", False))
        metrics_mod.set_gauge("kcatta_osv_records", float(count))
        metrics_mod.set_gauge("kcatta_osv_sync_complete", float(complete))
        _set_debian_tracker_metrics(app.state.debian_tracker_store)
        queue_counts()
        return PlainTextResponse(
            metrics_mod.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    app.include_router(ingest.router, dependencies=internal_auth)
    app.include_router(reports.router, dependencies=internal_auth)
    app.include_router(alerts.router, dependencies=internal_auth)
    app.include_router(detect.router, dependencies=internal_auth)
    app.include_router(predict.router, dependencies=internal_auth)

    return app
