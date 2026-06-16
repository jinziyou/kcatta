"""E1: observability — swallowed ingest errors must produce a visible log.

The ingest pipeline deliberately never lets a detection/correlation failure
break the ingest, but those failures used to vanish: the analyzer configured no
logging handler, so the ``logger.warning(...)`` in the except blocks went
nowhere. These tests assert the log record is actually emitted, and that the
central config installs a handler.
"""

from __future__ import annotations

import logging

from analyzer.api import ingest as ingest_api
from analyzer.logging_config import JsonFormatter, configure_logging
from analyzer.schemas import AssetReport, TraceBatch


def _asset_report() -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "r-err",
            "collected_at": "2026-05-28T10:00:00Z",
            "scanner_version": "0.1.0",
            "host": {"host_id": "h-1", "hostname": "n", "os": "Ubuntu 22.04"},
            "assets": [
                {"kind": "package", "asset_id": "pkg-1", "name": "openssl", "version": "1.0"}
            ],
            "vulnerabilities": [],
        }
    )


class _BoomStore:
    """A vulnerability/osv store whose detection path always raises."""

    record_count = 1  # so _auto_detect attempts detection

    def lookup(self, *_a, **_k):
        raise RuntimeError("simulated OSV lookup explosion")

    # consumed by _auto_detect's append path (never reached on error)
    def append(self, *_a, **_k):  # pragma: no cover - defensive
        pass


class _State:
    """Minimal stand-in for app.state used by the ingest helpers."""

    def __init__(self) -> None:
        self.appended: list = []
        self.osv_store = _BoomStore()
        self.osv_ecosystem = "Ubuntu:22.04"

        outer = self

        class _Collector:
            def append(self, record):
                outer.appended.append(record)

            def tail(self, _n):
                return []

        self.asset_report_store = _Collector()
        self.trace_batch_store = _Collector()
        self.vulnerability_store = _Collector()
        self.alert_store = _Collector()


def test_swallowed_detection_error_is_logged(caplog):
    # detect_report calls store.lookup which raises; _auto_detect swallows it but
    # MUST emit a warning so the failure is visible in production.
    state = _State()
    with caplog.at_level(logging.WARNING, logger="analyzer.api.ingest"):
        ingest_api.store_asset_report(_asset_report(), state)

    warnings = [r for r in caplog.records if "detection failed" in r.getMessage()]
    assert warnings, f"expected a visible 'detection failed' warning; got {caplog.records}"
    assert warnings[0].levelno == logging.WARNING
    # The report itself was still stored (ingest never bails on a detection error).
    assert state.appended


def test_swallowed_correlation_error_is_logged(caplog):
    # Force IOC correlation to blow up; the except block must log a warning.
    state = _State()

    def _boom(_batch, _ip_index=None):
        raise RuntimeError("simulated correlation explosion")

    batch = TraceBatch.model_validate(
        {
            "batch_id": "b-err",
            "collected_at": "2026-05-28T10:00:00Z",
            "collector_id": "col-1",
            "collector_version": "0.1.0",
            "events": [],
        }
    )

    import analyzer.api.ingest as mod

    orig = mod.correlate_trace_batch
    mod.correlate_trace_batch = _boom
    try:
        with caplog.at_level(logging.WARNING, logger="analyzer.api.ingest"):
            ingest_api.store_trace_batch(batch, state)
    finally:
        mod.correlate_trace_batch = orig

    msgs = [r.getMessage() for r in caplog.records]
    assert any("IOC correlation failed" in m for m in msgs), msgs


def test_configure_logging_installs_handler_idempotently():
    configure_logging()
    root = logging.getLogger()
    handler_count = len(root.handlers)
    assert handler_count >= 1
    # Calling again must not stack duplicate handlers.
    configure_logging()
    assert len(root.handlers) == handler_count
    # The analyzer logger emits at INFO by default.
    assert logging.getLogger("analyzer").isEnabledFor(logging.INFO)


def test_json_formatter_emits_parseable_line():
    import json

    record = logging.LogRecord(
        name="analyzer.api.ingest",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="detection failed for %s: %s",
        args=("r-1", "boom"),
        exc_info=None,
    )
    record.request_id = "req-123"  # structured extra is surfaced
    line = JsonFormatter().format(record)
    parsed = json.loads(line)
    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "analyzer.api.ingest"
    assert parsed["message"] == "detection failed for r-1: boom"
    assert parsed["request_id"] == "req-123"
