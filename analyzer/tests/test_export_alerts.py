"""CSV export of correlated alerts (/reports/alerts/export.csv)."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.schemas import Alert

NOW = datetime(2026, 6, 24, tzinfo=UTC)


def _client(tmp_path: Path):
    app = create_app(data_dir=tmp_path)
    return app, TestClient(app)


def _append_alert(app, **over) -> None:
    base = {
        "alert_id": "a-1",
        "alert_key": "k-1",
        "severity": "high",
        "status": "open",
        "score": 75.0,
        "title": "t",
        "description": "d",
        "created_at": NOW.isoformat(),
    }
    base.update(over)
    app.state.alert_store.append(Alert.model_validate(base))


def _rows(text: str) -> list[list[str]]:
    return [r for r in csv.reader(io.StringIO(text)) if r]


def test_export_csv_basic(tmp_path: Path):
    app, c = _client(tmp_path)
    _append_alert(
        app,
        title="C2 beacon",
        description="host phoned home; see CVE-1",
        related_asset_ids=["h-1", "h-2"],
    )
    resp = c.get("/reports/alerts/export.csv")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers.get("content-disposition", "")
    rows = _rows(resp.text)
    assert rows[0][:3] == ["alert_id", "alert_key", "severity"]
    data = rows[1:]
    assert len(data) == 1
    assert data[0][0] == "a-1"
    assert data[0][5] == "C2 beacon"  # title column
    assert data[0][7] == "h-1;h-2"  # related_asset_ids joined with ';'


def test_export_csv_neutralizes_formula_injection_and_quotes_commas(tmp_path: Path):
    app, c = _client(tmp_path)
    _append_alert(
        app,
        alert_id="a-2",
        alert_key="k-2",
        title="=cmd|'/c calc'!A1",
        description="payload, with comma",
    )
    rows = _rows(c.get("/reports/alerts/export.csv").text)
    row = next(r for r in rows if r[0] == "a-2")
    # A formula-leading title is prefixed with a single quote (rendered literally).
    assert row[5] == "'=cmd|'/c calc'!A1"
    # A comma-containing field survives intact via CSV quoting (not column-split).
    assert row[6] == "payload, with comma"


def test_export_csv_empty_is_header_only(tmp_path: Path):
    app, c = _client(tmp_path)
    rows = _rows(c.get("/reports/alerts/export.csv").text)
    assert len(rows) == 1
    assert rows[0][0] == "alert_id"


def test_export_csv_discloses_only_when_retained_history_exceeds_cap(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("analyzer.api.alerts.ALERT_EXPORT_WINDOW", 2)
    app, c = _client(tmp_path)
    for index in range(2):
        _append_alert(app, alert_id=f"a-{index}", alert_key=f"k-{index}")

    exact = c.get("/reports/alerts/export.csv")
    assert "x-alert-export-truncated" not in exact.headers

    _append_alert(app, alert_id="a-2", alert_key="k-2")
    truncated = c.get("/reports/alerts/export.csv")
    assert truncated.headers["x-alert-export-truncated"] == "true"
    assert len(_rows(truncated.text)) == 3  # header + two newest retained rows


def test_export_csv_route_not_shadowed_by_alert_id(tmp_path: Path):
    # `/export.csv` must resolve to the CSV endpoint, not be captured by the
    # `/{alert_id}` path parameter (which would 404 / return JSON).
    app, c = _client(tmp_path)
    resp = c.get("/reports/alerts/export.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


def test_export_csv_neutralizes_every_list_element(tmp_path: Path):
    app, c = _client(tmp_path)
    _append_alert(
        app,
        alert_id="a-3",
        alert_key="k-3",
        related_asset_ids=["host1", "=cmd|'/c calc'!A1", "+evil"],
    )
    rows = _rows(c.get("/reports/alerts/export.csv").text)
    row = next(r for r in rows if r[0] == "a-3")
    # Each ';'-joined element is neutralized, so a split-to-columns step is safe.
    assert row[7] == "host1;'=cmd|'/c calc'!A1;'+evil"


def test_export_csv_neutralizes_embedded_newline_formula(tmp_path: Path):
    app, c = _client(tmp_path)
    _append_alert(
        app,
        alert_id="a-4",
        alert_key="k-4",
        description='benign line\n=HYPERLINK("http://evil")',
    )
    rows = _rows(c.get("/reports/alerts/export.csv").text)
    row = next(r for r in rows if r[0] == "a-4")
    # A multi-line cell whose 2nd line is a formula -> whole cell prefixed with '.
    assert row[6].startswith("'benign line")
    assert "\n=HYPERLINK" in row[6]


def test_csv_safe_guards_whitespace_and_each_line():
    from analyzer.api.alerts import _csv_safe

    assert _csv_safe("=1+1") == "'=1+1"
    assert _csv_safe(" =1+1") == "' =1+1"  # leading whitespace before a formula
    assert _csv_safe("ok\n=2") == "'ok\n=2"  # formula on an embedded line
    assert _csv_safe("normal text") == "normal text"
    assert _csv_safe("") == ""
