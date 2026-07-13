"""Analyzer's internal OpenAPI export is deterministic and boundary-complete.

The committed ``openapi.json`` is the Form-facing internal API contract. Form
owns orchestration routes; Analyzer owns ingest, detect, reports, and prediction.
"""

from __future__ import annotations

from pathlib import Path

from analyzer.api import create_app
from analyzer.cli import DEFAULT_OPENAPI, export_openapi


def test_openapi_export_is_deterministic(tmp_path: Path) -> None:
    first = export_openapi(tmp_path / "a.json").read_text(encoding="utf-8")
    second = export_openapi(tmp_path / "b.json").read_text(encoding="utf-8")
    assert first == second


def test_committed_openapi_in_sync(tmp_path: Path) -> None:
    # The same gate CI enforces: the checked-in openapi.json must equal a fresh
    # export. A drift (route added, model changed, FastAPI/Pydantic bumped) fails
    # here until `scripts/export_openapi.py` is re-run and committed.
    fresh = export_openapi(tmp_path / "openapi.json").read_text(encoding="utf-8")
    committed = DEFAULT_OPENAPI.read_text(encoding="utf-8")
    assert committed == fresh, "openapi.json is stale — run scripts/export_openapi.py and commit"


def test_openapi_covers_analysis_routes_and_excludes_control_plane() -> None:
    paths = set(create_app().openapi()["paths"])
    expected = (
        "/ingest/asset-report",
        "/ingest/trace-batch",
        "/ingest/guard-event",
        "/detect/asset-report",
        "/reports/asset-reports",
        "/reports/alerts",
        "/attack-paths",
    )
    for route in expected:
        assert route in paths, route
    for route in ("/targets", "/scans", "/credentials"):
        assert route not in paths, route
