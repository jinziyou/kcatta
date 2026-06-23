"""Q6: the OpenAPI export is deterministic, in sync, and covers the API surface.

The committed ``openapi.json`` is the API contract (routes + request/response
models, including the scan / credential / attack-path models that are not in
``schemas-json/``). These tests mirror the CI drift gate at the pytest level.
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


def test_openapi_covers_routes_outside_schemas_json() -> None:
    # The whole point: routes whose models are NOT exported to schemas-json/
    # (scan orchestration, credentials, attack paths) are now drift-protected.
    paths = set(create_app().openapi()["paths"])
    expected = ("/scans", "/scans/{job_id}", "/credentials/{credential_id}/rotate", "/attack-paths")
    for route in expected:
        assert route in paths, route
