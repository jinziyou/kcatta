"""Stable paging and chunk-lineage read contracts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from analyzer.api import create_app
from analyzer.schemas import Alert, AssetReport, DetectionResult, GuardEventBatch, TraceBatch

NOW = datetime(2026, 7, 15, tzinfo=UTC)


def _report(report_id: str) -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": report_id,
            "collected_at": NOW,
            "scanner_version": "test",
            "host": {"host_id": "h-1", "hostname": "n", "os": "Debian 12"},
            "assets": [],
            "vulnerabilities": [],
        }
    )


def _trace(batch_id: str) -> TraceBatch:
    return TraceBatch(
        batch_id=batch_id,
        collected_at=NOW,
        collector_id="c-1",
        collector_version="test",
        events=[],
    )


def _detection(report_id: str) -> DetectionResult:
    return DetectionResult(
        report_id=report_id,
        host_id="h-1",
        collected_at=NOW,
        ecosystem="Debian:12",
        vulnerabilities=[],
    )


def _guard(batch_id: str, host_id: str) -> GuardEventBatch:
    return GuardEventBatch(
        batch_id=batch_id,
        collected_at=NOW,
        host_id=host_id,
        agent_version="test",
        events=[],
    )


@pytest.fixture(params=["jsonl", "sqlite"])
def client(request, tmp_path):
    app = create_app(
        data_dir=tmp_path / request.param,
        storage_backend=request.param,
        allow_insecure_no_auth=True,
    )
    with TestClient(app) as test_client:
        yield test_client, app


def test_raw_report_offset_pages_keep_newest_insertion_order(client):
    c, app = client
    for report_id in ("r-1", "r-2", "r-3"):
        app.state.asset_report_store.append(_report(report_id))

    first = c.get("/reports/asset-reports", params={"limit": 2, "offset": 0}).json()
    second = c.get("/reports/asset-reports", params={"limit": 2, "offset": 2}).json()

    assert [row["report_id"] for row in first] == ["r-3", "r-2"]
    assert [row["report_id"] for row in second] == ["r-1"]


def test_logical_pages_do_not_skip_rows_when_read_byte_budget_shortens_page(client):
    c, app = client
    reports = [_report(f"budget-r-{index}") for index in range(1, 5)]
    for report in reports:
        app.state.asset_report_store.append(report)

    # Force each storage read to fit one record even though the requested page
    # size is three. Advancing with ``page * limit`` would skip two records on
    # every click; logical page mode must advance by the rows actually read.
    one_record_bytes = max(len(report.model_dump_json().encode()) for report in reports)
    app.state.asset_report_store._read_max_bytes = one_record_bytes + 1

    collected: list[str] = []
    has_more: list[str] = []
    for page in range(4):
        response = c.get(
            "/reports/asset-reports",
            params={"limit": 3, "page": page},
        )
        assert response.status_code == 200
        collected.extend(row["report_id"] for row in response.json())
        has_more.append(response.headers["x-kcatta-has-more"])

    assert collected == ["budget-r-4", "budget-r-3", "budget-r-2", "budget-r-1"]
    assert has_more == ["true", "true", "true", "false"]


def test_filtered_guard_logical_pages_do_not_skip_budget_shortened_reads(client):
    c, app = client
    batches = [
        _guard("guard-a-1", "host-a"),
        _guard("guard-b-1", "host-b"),
        _guard("guard-a-2", "host-a"),
        _guard("guard-b-2", "host-b"),
        _guard("guard-a-3", "host-a"),
    ]
    for batch in batches:
        app.state.guard_event_store.append(batch)
    one_record_bytes = max(len(batch.model_dump_json().encode()) for batch in batches)
    app.state.guard_event_store._read_max_bytes = one_record_bytes + 1

    first = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "limit": 2, "page": 0},
    )
    second = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "limit": 2, "page": 1},
    )
    third = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "limit": 2, "page": 2},
    )

    assert [row["batch_id"] for row in first.json()] == ["guard-a-3", "guard-a-2"]
    assert first.headers["x-kcatta-has-more"] == "true"
    assert [row["batch_id"] for row in second.json()] == ["guard-a-1"]
    assert second.headers["x-kcatta-has-more"] == "false"
    assert third.json() == []
    assert third.headers["x-kcatta-has-more"] == "false"


def test_cursor_pages_are_stable_when_new_rows_arrive(client):
    c, app = client
    for report_id in ("cursor-r-1", "cursor-r-2", "cursor-r-3", "cursor-r-4"):
        app.state.asset_report_store.append(_report(report_id))

    first = c.get("/reports/asset-reports", params={"limit": 2})
    cursor = first.headers["x-kcatta-next-cursor"]
    app.state.asset_report_store.append(_report("cursor-new-after-page-1"))
    second = c.get(
        "/reports/asset-reports",
        params={"limit": 2, "cursor": cursor},
    )

    assert [row["report_id"] for row in first.json()] == ["cursor-r-4", "cursor-r-3"]
    assert [row["report_id"] for row in second.json()] == ["cursor-r-2", "cursor-r-1"]
    assert second.headers["x-kcatta-has-more"] == "false"
    assert "x-kcatta-next-cursor" not in second.headers


def test_cursor_respects_byte_budget_without_replaying_prior_pages(client):
    c, app = client
    reports = [_report(f"cursor-budget-{index}") for index in range(1, 4)]
    for report in reports:
        app.state.asset_report_store.append(report)
    one_record_bytes = max(len(report.model_dump_json().encode()) for report in reports)
    app.state.asset_report_store._read_max_bytes = one_record_bytes + 1

    collected: list[str] = []
    cursor: str | None = None
    while True:
        params = {"limit": "3"}
        if cursor is not None:
            params["cursor"] = cursor
        response = c.get("/reports/asset-reports", params=params)
        collected.extend(row["report_id"] for row in response.json())
        cursor = response.headers.get("x-kcatta-next-cursor")
        if cursor is None:
            break

    assert collected == ["cursor-budget-3", "cursor-budget-2", "cursor-budget-1"]


def test_filtered_guard_cursor_is_bound_to_filter(client):
    c, app = client
    for batch in (
        _guard("cursor-a-1", "host-a"),
        _guard("cursor-b-1", "host-b"),
        _guard("cursor-a-2", "host-a"),
    ):
        app.state.guard_event_store.append(batch)

    first = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "limit": 1},
    )
    cursor = first.headers["x-kcatta-next-cursor"]
    second = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "limit": 1, "cursor": cursor},
    )
    wrong_filter = c.get(
        "/reports/guard-events",
        params={"host_id": "host-b", "limit": 1, "cursor": cursor},
    )

    assert [row["batch_id"] for row in first.json()] == ["cursor-a-2"]
    assert [row["batch_id"] for row in second.json()] == ["cursor-a-1"]
    assert wrong_filter.status_code == 400


def test_malformed_cursor_is_rejected(client):
    response = client[0].get(
        "/reports/asset-reports",
        params={"cursor": "not-a-valid-cursor"},
    )
    assert response.status_code == 400


def test_cursor_page_and_offset_modes_cannot_be_mixed(client):
    c, app = client
    for report_id in ("mode-r-1", "mode-r-2"):
        app.state.asset_report_store.append(_report(report_id))
    cursor = c.get("/reports/asset-reports", params={"limit": 1}).headers["x-kcatta-next-cursor"]

    cursor_and_page = c.get(
        "/reports/asset-reports",
        params={"cursor": cursor, "page": 1},
    )
    cursor_and_offset = c.get(
        "/reports/guard-events",
        params={"host_id": "host-a", "cursor": cursor, "offset": 1},
    )
    page_and_offset = c.get(
        "/reports/asset-reports",
        params={"page": 1, "offset": 1},
    )

    assert cursor_and_page.status_code == 400
    assert cursor_and_offset.status_code == 400
    assert page_and_offset.status_code == 400


def test_form_asset_and_detection_chunks_are_queryable_as_one_lineage(client):
    c, app = client
    ids = ["logical-r", "logical-r::chunk-2-of-3", "logical-r::chunk-3-of-3"]
    for report_id in ids:
        app.state.asset_report_store.append(_report(report_id))
        app.state.vulnerability_store.append(_detection(report_id))

    assets = c.get(f"/reports/asset-reports/{ids[1]}/lineage").json()
    detections = c.get("/reports/vulnerabilities/logical-r/lineage").json()

    assert assets["lineage_id"] == "logical-r"
    assert assets["expected_chunks"] == 3
    assert assets["received_chunks"] == 3
    assert assets["complete"] is True
    assert [row["report_id"] for row in assets["records"]] == ids
    assert [row["report_id"] for row in detections["records"]] == ids
    assert detections["complete"] is True


def test_agent_trace_lineage_is_grouped_without_claiming_unknown_total(client):
    c, app = client
    ids = ("logical-b~batch-part-0", "logical-b~batch-part-1")
    for batch_id in ids:
        app.state.trace_batch_store.append(_trace(batch_id))

    lineage = c.get(f"/reports/trace-batches/{ids[0]}/lineage").json()

    assert lineage["lineage_id"] == "logical-b"
    assert lineage["received_chunks"] == 2
    assert lineage["expected_chunks"] is None
    assert lineage["complete"] is None
    assert [row["batch_id"] for row in lineage["records"]] == list(ids)


def test_agent_asset_and_detection_zero_based_chunks_share_lineage(client):
    c, app = client
    ids = ("logical-agent~report-part-0", "logical-agent~report-part-1")
    for report_id in ids:
        app.state.asset_report_store.append(_report(report_id))
        app.state.vulnerability_store.append(_detection(report_id))

    assets = c.get(f"/reports/asset-reports/{ids[0]}/lineage").json()
    detections = c.get(f"/reports/vulnerabilities/{ids[1]}/lineage").json()

    assert assets["lineage_id"] == "logical-agent"
    assert assets["received_chunks"] == 2
    assert assets["expected_chunks"] is None
    assert assets["complete"] is None
    assert [row["report_id"] for row in assets["records"]] == list(ids)
    assert detections["lineage_id"] == "logical-agent"
    assert detections["received_chunks"] == 2
    assert detections["expected_chunks"] is None
    assert detections["complete"] is None
    assert [row["report_id"] for row in detections["records"]] == list(ids)


def test_report_detail_projection_pages_deduplicated_assets_and_findings(client):
    c, app = client
    ids = ("detail-r::chunk-1-of-2", "detail-r::chunk-2-of-2")
    reports = [
        AssetReport.model_validate(
            {
                "report_id": ids[0],
                "collected_at": NOW,
                "scanner_version": "test",
                "host": {"host_id": "h-1", "hostname": "n", "os": "Debian 12"},
                "assets": [
                    {"kind": "package", "asset_id": "pkg-1", "name": "old", "version": "1"},
                    {"kind": "service", "asset_id": "svc-1", "name": "sshd", "status": "running"},
                ],
                "vulnerabilities": [
                    {
                        "vuln_id": "CVE-2026-0001",
                        "severity": "low",
                        "cvss_score": 3.1,
                        "affected_asset_id": "pkg-1",
                        "source": "test",
                        "evidence": "same-site",
                        "references": ["ref-a"],
                    }
                ],
            }
        ),
        AssetReport.model_validate(
            {
                "report_id": ids[1],
                "collected_at": NOW,
                "scanner_version": "test",
                "host": {"host_id": "h-1", "hostname": "n", "os": "Debian 12"},
                "assets": [
                    {"kind": "package", "asset_id": "pkg-1", "name": "new", "version": "2"},
                    {"kind": "package", "asset_id": "pkg-2", "name": "other", "version": "1"},
                    {"kind": "account", "asset_id": "acct-1", "username": "root", "uid": 0},
                ],
                "vulnerabilities": [],
            }
        ),
    ]
    detections = [
        DetectionResult.model_validate(
            {
                "report_id": ids[0],
                "host_id": "h-1",
                "collected_at": NOW,
                "ecosystem": "Debian:12",
                "detection_status": "complete",
                "scanned_package_count": 2,
                "coverage": [
                    {
                        "detector": "osv",
                        "ecosystem": "Debian:12",
                        "status": "complete",
                        "scanned_count": 2,
                        "finding_count": 2,
                    }
                ],
                "vulnerabilities": [
                    {
                        "vuln_id": "CVE-2026-0001",
                        "severity": "high",
                        "affected_asset_id": "pkg-1",
                        "source": "test",
                        "evidence": "same-site",
                        "references": ["ref-b"],
                    },
                    {
                        "vuln_id": "CVE-2026-0002",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "affected_asset_id": "pkg-2",
                        "source": "test",
                    },
                ],
            }
        ),
        DetectionResult.model_validate(
            {
                "report_id": ids[1],
                "host_id": "h-1",
                "collected_at": NOW,
                "ecosystem": "Debian:12",
                "detection_status": "complete",
                "vulnerabilities": [
                    {
                        "vuln_id": "CVE-2026-0003",
                        "severity": "medium",
                        "affected_asset_id": "pkg-2",
                        "source": "test",
                    }
                ],
            }
        ),
    ]
    for report, detection in zip(reports, detections, strict=True):
        app.state.asset_report_store.append(report)
        app.state.vulnerability_store.append(detection)

    def fail_if_full_scan(*_args, **_kwargs):
        raise AssertionError("lineage lookup must not page through tail()")

    app.state.asset_report_store.tail = fail_if_full_scan
    app.state.vulnerability_store.tail = fail_if_full_scan

    first = c.get(
        f"/reports/report-details/{ids[1]}",
        params={"asset_page_size": 2, "finding_page_size": 2},
    )
    assert first.status_code == 200
    payload = first.json()
    assert payload["report"]["report_id"] == "detail-r"
    assert payload["asset_lineage"] == {
        "lineage_id": "detail-r",
        "expected_chunks": 2,
        "received_chunks": 2,
        "complete": True,
    }
    assert payload["asset_total"] == 4
    assert payload["asset_kind_totals"]["service"] == 1
    assert payload["asset_kind_totals"]["account"] == 1
    assert payload["asset_kind_totals"]["package"] == 2
    assert [asset["asset_id"] for asset in payload["assets"]] == ["svc-1", "acct-1"]
    assert payload["asset_has_more"] is True
    assert payload["vulnerability_total"] == 3
    assert [item["vuln_id"] for item in payload["vulnerabilities"]] == [
        "CVE-2026-0002",
        "CVE-2026-0001",
    ]
    merged = payload["vulnerabilities"][1]
    assert merged["severity"] == "high"
    assert merged["cvss_score"] == 3.1
    assert merged["references"] == ["ref-a", "ref-b"]
    assert payload["finding_has_more"] is True
    assert payload["detection_lineage"]["complete"] is True
    assert len(payload["detection_records"]) == 2
    assert "vulnerabilities" not in payload["detection_records"][0]

    last = c.get(
        "/reports/report-details/detail-r",
        params={
            "asset_page": 999999,
            "asset_page_size": 2,
            "finding_page": 999999,
            "finding_page_size": 2,
        },
    ).json()
    assert last["asset_page"] == 1
    assert [asset["asset_id"] for asset in last["assets"]] == ["pkg-1", "pkg-2"]
    assert last["assets"][0]["name"] == "new"
    assert last["asset_has_more"] is False
    assert last["finding_page"] == 1
    assert [item["vuln_id"] for item in last["vulnerabilities"]] == ["CVE-2026-0003"]
    assert last["finding_has_more"] is False


def test_report_detail_projection_is_bounded_and_does_not_change_lineage_api(client):
    c, app = client
    app.state.asset_report_store.append(_report("detail-bounds"))

    assert c.get("/reports/report-details/missing").status_code == 404
    assert (
        c.get(
            "/reports/report-details/detail-bounds",
            params={"asset_page_size": 201},
        ).status_code
        == 422
    )
    projection = c.get("/reports/report-details/detail-bounds")
    lineage = c.get("/reports/asset-reports/detail-bounds/lineage")
    assert projection.status_code == 200
    assert projection.json()["assets"] == []
    assert projection.json()["detection_records"] == []
    assert lineage.status_code == 200
    assert len(lineage.json()["records"]) == 1


def test_report_detail_projection_cache_uses_lineage_scoped_invalidation(client):
    c, app = client
    report_ids = ("detail-cache::chunk-1-of-2", "detail-cache::chunk-2-of-2")
    for report_id in report_ids:
        app.state.asset_report_store.append(_report(report_id))
        app.state.vulnerability_store.append(_detection(report_id))

    calls = {"asset": 0, "detection": 0}
    original_asset_find = app.state.asset_report_store.find_lineage
    original_detection_find = app.state.vulnerability_store.find_lineage

    def counted_asset_find(*args, **kwargs):
        calls["asset"] += 1
        return original_asset_find(*args, **kwargs)

    def counted_detection_find(*args, **kwargs):
        calls["detection"] += 1
        return original_detection_find(*args, **kwargs)

    app.state.asset_report_store.find_lineage = counted_asset_find
    app.state.vulnerability_store.find_lineage = counted_detection_find

    first = c.get(f"/reports/report-details/{report_ids[1]}")
    second = c.get(
        "/reports/report-details/detail-cache",
        params={"asset_page": 1, "finding_page": 1},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls == {"asset": 1, "detection": 1}
    assert app.state.report_projection_cache.snapshot()[0] == 1

    # Writes for another report must not evict this hot report.
    app.state.asset_report_store.append(_report("unrelated-new-report"))
    app.state.vulnerability_store.append(_detection("unrelated-new-report"))
    still_cached = c.get("/reports/report-details/detail-cache")

    assert still_cached.status_code == 200
    assert calls == {"asset": 1, "detection": 1}
    assert app.state.report_projection_cache.snapshot()[0] == 1

    # A write in either source lineage invalidates only this report and rebuilds
    # both halves as one coherent projection.
    app.state.asset_report_store.append(_report(report_ids[0]))
    app.state.vulnerability_store.append(_detection(report_ids[0]))
    refreshed = c.get("/reports/report-details/detail-cache")

    assert refreshed.status_code == 200
    assert calls == {"asset": 2, "detection": 2}
    assert app.state.report_projection_cache.snapshot()[0] == 1


def test_alert_offset_pages_logical_keys_and_counts_all_occurrences(client):
    c, app = client
    # Insert oldest to newest. ak-b's duplicate is newest and determines order.
    for alert_id, key in (("a-1", "ak-a"), ("b-1", "ak-b"), ("b-2", "ak-b"), ("c-1", "ak-c")):
        app.state.alert_store.append(
            Alert(
                alert_id=alert_id,
                alert_key=key,
                severity="low",
                score=10,
                title=key,
                description=key,
                created_at=NOW,
            )
        )

    first = c.get("/reports/alerts", params={"limit": 2, "offset": 0}).json()
    second = c.get("/reports/alerts", params={"limit": 2, "offset": 2}).json()

    assert [row["alert_key"] for row in first] == ["ak-c", "ak-b"]
    assert first[1]["occurrence_count"] == 2
    assert [row["alert_key"] for row in second] == ["ak-a"]
