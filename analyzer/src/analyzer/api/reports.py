"""Read-side endpoints over the ingest record stores (JSONL or SQLite,
per ``ANALYZER_STORAGE``).

These are intentionally raw: each endpoint tails its store for the latest
N records, newest first, or fetches a single record by id. Aggregated
views (per-host, per-severity, joins between assets and events) are future
work, pending normalization.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from itertools import chain
from typing import Generic, TypeVar

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from ..schemas import (
    Asset,
    AssetReport,
    DetectionCoverage,
    DetectionResult,
    DetectionStatus,
    DetectorRun,
    GuardEventBatch,
    HostInfo,
    MdeSecurityBatch,
    MdvmVulnerabilityBatch,
    StrictModel,
    TraceBatch,
    Vulnerability,
)
from ..schemas.common import MAX_NESTED_LIST_ITEMS, CorrelationIdentifier, Severity, Timestamp
from ..storage import StorageCursorError
from ..storage.lineage import LineageKind, lineage_root, parse_lineage_id
from .report_projection_cache import ReportProjectionCache, StoreFingerprint

router = APIRouter(prefix="/reports", tags=["reports"])

_T = TypeVar("_T")
_STORE_PAGE_SIZE = 500
_PAGE_HEADER = "X-Kcatta-Has-More"
_CURSOR_HEADER = "X-Kcatta-Next-Cursor"
_CURSOR_VERSION = 1


class LineageResponse(BaseModel, Generic[_T]):
    """All retained chunks known to belong to one logical upload."""

    lineage_id: str
    expected_chunks: int | None = Field(
        description="Declared total when the chunk ID carries one; otherwise unknown."
    )
    received_chunks: int = Field(ge=0)
    complete: bool | None = Field(
        description="True/false only when expected_chunks is knowable; otherwise null."
    )
    records: list[_T]


class LineageSummary(StrictModel):
    """Completeness metadata without embedding every retained chunk."""

    lineage_id: CorrelationIdentifier
    expected_chunks: int | None = Field(default=None, ge=1)
    received_chunks: int = Field(ge=0)
    complete: bool | None = None


class ReportHeader(StrictModel):
    """Asset-report metadata safe to return independently from paged assets."""

    report_id: CorrelationIdentifier
    collected_at: Timestamp
    scanner_version: CorrelationIdentifier
    source_agent_id: CorrelationIdentifier | None = None
    source_target_id: CorrelationIdentifier | None = None
    host: HostInfo
    detector_runs: list[DetectorRun] | None = Field(default=None, max_length=32)


class DetectionRecordSummary(StrictModel):
    """Coverage/provenance fields from one derived chunk, excluding findings."""

    report_id: CorrelationIdentifier
    host_id: CorrelationIdentifier
    collected_at: Timestamp
    ecosystem: CorrelationIdentifier
    detection_status: DetectionStatus
    status_reason: str | None = None
    scanned_package_count: int = Field(ge=0)
    unresolved_package_count: int = Field(ge=0)
    uncovered_package_count: int = Field(ge=0)
    truncated: bool
    truncation_reason: str | None = None
    coverage: list[DetectionCoverage]


class ReportDetailPage(StrictModel):
    """Bounded read model for the Admin report-detail screen."""

    report: ReportHeader
    asset_lineage: LineageSummary
    assets: list[Asset]
    asset_total: int = Field(ge=0)
    asset_kind_totals: dict[str, int]
    asset_page: int = Field(ge=0)
    asset_page_size: int = Field(ge=1, le=200)
    asset_has_more: bool
    detection_lineage: LineageSummary
    detection_records: list[DetectionRecordSummary]
    vulnerabilities: list[Vulnerability]
    vulnerability_total: int = Field(ge=0)
    finding_page: int = Field(ge=0)
    finding_page_size: int = Field(ge=1, le=200)
    finding_has_more: bool


@dataclass(frozen=True, slots=True)
class _ReportProjection:
    """Unpaged, reusable part of one logical report-detail response."""

    report: ReportHeader
    asset_lineage: LineageSummary
    assets: tuple[Asset, ...]
    asset_kind_totals: tuple[tuple[str, int], ...]
    detection_lineage: LineageSummary
    detection_records: tuple[DetectionRecordSummary, ...]
    vulnerabilities: tuple[Vulnerability, ...]


def _retained_rows(store):  # type: ignore[no-untyped-def]
    offset = 0
    while True:
        page = store.tail(_STORE_PAGE_SIZE, offset)
        if not page:
            return
        yield from page
        offset += len(page)


def _page_rows(store, *, limit: int, page: int) -> tuple[list[dict], bool]:  # type: ignore[no-untyped-def]
    """Return a byte-budget-safe logical page without skipping records.

    Store reads may legitimately return fewer than ``limit`` rows when their
    configured read-byte budget is reached.  Advancing by ``page * limit`` in
    that case skips retained rows.  Replaying the preceding pages and advancing
    by the number actually returned keeps the public page number stable across
    both storage backends.
    """
    offset = 0
    for _ in range(page):
        rows = store.tail(limit, offset)
        if not rows:
            return [], False
        offset += len(rows)
    rows = store.tail(limit, offset)
    has_more = bool(rows) and bool(store.tail(1, offset + len(rows)))
    return rows, has_more


def _list_rows(
    store,
    *,
    limit: int,
    offset: int,
    page: int | None,
    cursor: str | None,
    scope: str,
    response: Response,
) -> list[dict]:  # type: ignore[no-untyped-def]
    _validate_paging(offset=offset, page=page, cursor=cursor)
    if page is None and (cursor is not None or offset == 0):
        return _cursor_rows(store, limit=limit, cursor=cursor, scope=scope, response=response)
    if page is None:
        return store.tail(limit, offset)
    rows, has_more = _page_rows(store, limit=limit, page=page)
    response.headers[_PAGE_HEADER] = "true" if has_more else "false"
    return rows


def _validate_paging(*, offset: int, page: int | None, cursor: str | None) -> None:
    """Reject ambiguous combinations instead of silently ignoring parameters."""

    if cursor is not None and (page is not None or offset != 0):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cursor cannot be combined with page or offset",
        )
    if page is not None and offset != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="page cannot be combined with offset",
        )


def _store_name(store) -> str:  # type: ignore[no-untyped-def]
    return type(store).__name__.removesuffix("Store").lower()


def _encode_cursor(*, scope: str, backend: str, anchor: str) -> str:
    payload = json.dumps(
        {"v": _CURSOR_VERSION, "s": scope, "b": backend, "a": anchor},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _decode_cursor(cursor: str, *, scope: str, backend: str) -> str:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(cursor + padding))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid report cursor") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("v") != _CURSOR_VERSION
        or payload.get("s") != scope
        or payload.get("b") != backend
        or not isinstance(payload.get("a"), str)
    ):
        raise HTTPException(status_code=400, detail="report cursor does not match this query")
    return str(payload["a"])


def _cursor_rows(
    store,
    *,
    limit: int,
    cursor: str | None,
    scope: str,
    response: Response,
    field: str | None = None,
    value: str | None = None,
) -> list[dict]:  # type: ignore[no-untyped-def]
    backend = _store_name(store)
    anchor = _decode_cursor(cursor, scope=scope, backend=backend) if cursor else None
    try:
        rows, next_anchor, has_more = store.cursor_page(
            limit,
            anchor,
            field=field,
            value=value,
        )
    except StorageCursorError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="report cursor expired; restart from the first page",
        ) from exc
    response.headers[_PAGE_HEADER] = "true" if has_more else "false"
    if has_more and next_anchor is not None:
        response.headers[_CURSOR_HEADER] = _encode_cursor(
            scope=scope,
            backend=backend,
            anchor=next_anchor,
        )
    return rows


def _guard_rows(store, *, host_id: str, limit: int, offset: int) -> list[dict]:  # type: ignore[no-untyped-def]
    """Page matching Guard rows while advancing raw storage by actual reads."""
    out: list[dict] = []
    matched = 0
    raw_offset = 0
    while len(out) < limit:
        rows = store.tail(_STORE_PAGE_SIZE, raw_offset)
        if not rows:
            break
        for record in rows:
            if record.get("host_id") != host_id:
                continue
            if matched < offset:
                matched += 1
                continue
            out.append(record)
            matched += 1
            if len(out) >= limit:
                break
        raw_offset += len(rows)
    return out


def _guard_page_rows(
    store,
    *,
    host_id: str,
    limit: int,
    page: int,
) -> tuple[list[dict], bool]:  # type: ignore[no-untyped-def]
    matching_offset = 0
    for _ in range(page):
        rows = _guard_rows(store, host_id=host_id, limit=limit, offset=matching_offset)
        if not rows:
            return [], False
        matching_offset += len(rows)
    rows = _guard_rows(store, host_id=host_id, limit=limit, offset=matching_offset)
    has_more = bool(rows) and bool(
        _guard_rows(
            store,
            host_id=host_id,
            limit=1,
            offset=matching_offset + len(rows),
        )
    )
    return rows, has_more


def _lineage_rows(
    store,
    *,
    id_field: str,
    requested_id: str,
    kind: LineageKind,
) -> tuple[str, int | None, bool | None, list[dict]]:  # type: ignore[no-untyped-def]
    requested = parse_lineage_id(requested_id, kind)
    root = requested[0] if requested else requested_id
    found: list[tuple[int, str, int | None, dict]] = []
    find_lineage = getattr(store, "find_lineage", None)
    rows = (
        find_lineage(id_field, requested_id, kind)
        if callable(find_lineage)
        else _retained_rows(store)
    )
    for row in rows:
        row_id = row.get(id_field)
        if not isinstance(row_id, str):
            continue
        info = parse_lineage_id(row_id, kind)
        if row_id == root:
            found.append((1, row_id, None, row))
        elif info is not None and info[0] == root:
            found.append((info[1], row_id, info[2], row))

    # A retried duplicate is normally collapsed on ingest, but de-duplicate by
    # child id defensively so lineage completeness cannot be inflated.
    unique: dict[str, tuple[int, str, int | None, dict]] = {}
    for item in found:
        unique.setdefault(item[1], item)
    ordered = sorted(unique.values(), key=lambda item: (item[0], item[1]))
    totals = {item[2] for item in ordered if item[2] is not None}
    expected = next(iter(totals)) if len(totals) == 1 else (max(totals) if totals else None)
    if expected is None:
        complete = None
    else:
        indices = {item[0] for item in ordered}
        complete = len(totals) == 1 and indices == set(range(1, expected + 1))
    return root, expected, complete, [item[3] for item in ordered]


def _lineage_response(
    store,
    *,
    id_field: str,
    requested_id: str,
    kind: LineageKind,
) -> LineageResponse[dict]:  # type: ignore[no-untyped-def]
    root, expected, complete, rows = _lineage_rows(
        store,
        id_field=id_field,
        requested_id=requested_id,
        kind=kind,
    )
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="lineage not found")
    return LineageResponse[dict](
        lineage_id=root,
        expected_chunks=expected,
        received_chunks=len(rows),
        complete=complete,
        records=rows,
    )


_ASSET_KIND_ORDER = (
    "security_product",
    "service",
    "port",
    "account",
    "credential",
    "container",
    "image",
    "package",
)
_ASSET_KIND_RANK = {kind: index for index, kind in enumerate(_ASSET_KIND_ORDER)}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _bounded_page(requested: int, total: int, page_size: int) -> int:
    return min(requested, max(0, (total - 1) // page_size))


def _merged_assets(reports: list[AssetReport]) -> list[Asset]:
    """Deduplicate by asset_id while preserving first position and latest value."""
    by_id: dict[str, Asset] = {}
    for report in reports:
        for asset in report.assets:
            by_id[asset.asset_id] = asset
    return sorted(
        by_id.values(),
        key=lambda asset: _ASSET_KIND_RANK.get(asset.kind, len(_ASSET_KIND_ORDER)),
    )


def _vulnerability_key(item: Vulnerability) -> tuple[str, str, str, str, str]:
    return (
        item.source,
        item.vuln_id,
        item.affected_asset_id,
        item.parent_asset_id or "",
        item.evidence or "",
    )


def _merged_vulnerabilities(
    reports: list[AssetReport], detections: list[DetectionResult]
) -> list[Vulnerability]:
    """Mirror the detail view's exact-copy merge without collapsing evidence sites."""
    merged: dict[tuple[str, str, str, str, str], Vulnerability] = {}
    groups = [
        *(report.vulnerabilities for report in reports),
        *(row.vulnerabilities for row in detections),
    ]
    for group in groups:
        for item in group:
            key = _vulnerability_key(item)
            current = merged.get(key)
            if current is None:
                merged[key] = item
                continue
            references = list(dict.fromkeys([*current.references, *item.references]))[
                :MAX_NESTED_LIST_ITEMS
            ]
            merged[key] = item.model_copy(
                update={
                    "cvss_score": item.cvss_score
                    if item.cvss_score is not None
                    else current.cvss_score,
                    "evidence": item.evidence if item.evidence is not None else current.evidence,
                    "references": references,
                }
            )
    return sorted(
        merged.values(),
        key=lambda item: (
            -_SEVERITY_RANK[item.severity],
            -(item.cvss_score or 0.0),
        ),
    )


def _detection_summary(item: DetectionResult) -> DetectionRecordSummary:
    return DetectionRecordSummary(
        report_id=item.report_id,
        host_id=item.host_id,
        collected_at=item.collected_at,
        ecosystem=item.ecosystem,
        detection_status=item.detection_status,
        status_reason=item.status_reason,
        scanned_package_count=item.scanned_package_count,
        unresolved_package_count=item.unresolved_package_count,
        uncovered_package_count=item.uncovered_package_count,
        truncated=item.truncated,
        truncation_reason=item.truncation_reason,
        coverage=item.coverage,
    )


def _build_report_projection(request: Request, report_id: str) -> _ReportProjection:
    asset_root, asset_expected, asset_complete, raw_reports = _lineage_rows(
        request.app.state.asset_report_store,
        id_field="report_id",
        requested_id=report_id,
        kind="asset",
    )
    if not raw_reports:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    reports = [AssetReport.model_validate(row) for row in raw_reports]

    detection_root, detection_expected, detection_complete, raw_detections = _lineage_rows(
        request.app.state.vulnerability_store,
        id_field="report_id",
        requested_id=asset_root,
        kind="asset",
    )
    detections = [DetectionResult.model_validate(row) for row in raw_detections]
    expected = asset_expected if asset_expected is not None else detection_expected
    if expected is not None:
        combined_detection_complete: bool | None = (
            len(detections) == expected and asset_complete is not False
        )
    else:
        combined_detection_complete = detection_complete

    assets = _merged_assets(reports)
    findings = _merged_vulnerabilities(reports, detections)
    asset_kind_totals = {kind: 0 for kind in _ASSET_KIND_ORDER}
    for asset in assets:
        asset_kind_totals[asset.kind] = asset_kind_totals.get(asset.kind, 0) + 1

    first = reports[0]
    return _ReportProjection(
        report=ReportHeader(
            report_id=asset_root,
            collected_at=first.collected_at,
            scanner_version=first.scanner_version,
            source_agent_id=first.source_agent_id,
            source_target_id=first.source_target_id,
            host=first.host,
            detector_runs=first.detector_runs,
        ),
        asset_lineage=LineageSummary(
            lineage_id=asset_root,
            expected_chunks=asset_expected,
            received_chunks=len(reports),
            complete=asset_complete,
        ),
        assets=tuple(assets),
        asset_kind_totals=tuple(asset_kind_totals.items()),
        detection_lineage=LineageSummary(
            lineage_id=detection_root,
            expected_chunks=expected,
            received_chunks=len(detections),
            complete=combined_detection_complete,
        ),
        detection_records=tuple(_detection_summary(item) for item in detections),
        vulnerabilities=tuple(findings),
    )


def _projection_estimated_bytes(projection: _ReportProjection) -> int:
    """Conservative wire-size estimate used only to enforce the memory bound."""
    models = chain(
        (
            projection.report,
            projection.asset_lineage,
            projection.detection_lineage,
        ),
        projection.assets,
        projection.detection_records,
        projection.vulnerabilities,
    )
    model_bytes = sum(len(item.model_dump_json().encode()) for item in models)
    totals_bytes = len(json.dumps(dict(projection.asset_kind_totals)).encode())
    # Pydantic model objects carry more overhead than their compact JSON form.
    return max(1, 2 * (model_bytes + totals_bytes))


def _projection_fingerprint(request: Request, report_id: str) -> StoreFingerprint:
    return (
        request.app.state.asset_report_store.lineage_fingerprint("report_id", report_id, "asset"),
        request.app.state.vulnerability_store.lineage_fingerprint("report_id", report_id, "asset"),
    )


def _get_report_projection(request: Request, report_id: str) -> _ReportProjection:
    cache: ReportProjectionCache[_ReportProjection] = request.app.state.report_projection_cache
    root = lineage_root(report_id, "asset")
    if not cache.enabled:
        return _build_report_projection(request, root)

    # Retry once if an ingest lands while the projection is being assembled.
    # The unstable result is still safe to return, but is never cached.
    projection: _ReportProjection | None = None
    for _ in range(2):
        before = _projection_fingerprint(request, root)
        cached = cache.get(root, before)
        if cached is not None:
            return cached
        projection = _build_report_projection(request, root)
        after = _projection_fingerprint(request, root)
        if before == after:
            cache.put(
                root,
                after,
                projection,
                estimated_bytes=_projection_estimated_bytes(projection),
            )
            return projection
    return projection


@router.get("/report-details/{report_id}", response_model=ReportDetailPage)
async def get_report_detail_page(
    report_id: str,
    request: Request,
    asset_page: int = Query(default=0, ge=0, le=1_000_000),
    asset_page_size: int = Query(default=50, ge=1, le=200),
    finding_page: int = Query(default=0, ge=0, le=1_000_000),
    finding_page_size: int = Query(default=50, ge=1, le=200),
) -> ReportDetailPage:
    """Return bounded assets/findings plus complete report and coverage metadata."""
    projection = _get_report_projection(request, report_id)
    assets = projection.assets
    findings = projection.vulnerabilities
    actual_asset_page = _bounded_page(asset_page, len(assets), asset_page_size)
    actual_finding_page = _bounded_page(finding_page, len(findings), finding_page_size)
    asset_start = actual_asset_page * asset_page_size
    finding_start = actual_finding_page * finding_page_size
    paged_assets = assets[asset_start : asset_start + asset_page_size]
    paged_findings = findings[finding_start : finding_start + finding_page_size]
    return ReportDetailPage(
        report=projection.report,
        asset_lineage=projection.asset_lineage,
        assets=paged_assets,
        asset_total=len(assets),
        asset_kind_totals=dict(projection.asset_kind_totals),
        asset_page=actual_asset_page,
        asset_page_size=asset_page_size,
        asset_has_more=asset_start + len(paged_assets) < len(assets),
        detection_lineage=projection.detection_lineage,
        detection_records=list(projection.detection_records),
        vulnerabilities=paged_findings,
        vulnerability_total=len(findings),
        finding_page=actual_finding_page,
        finding_page_size=finding_page_size,
        finding_has_more=finding_start + len(paged_findings) < len(findings),
    )


@router.get("/asset-reports", response_model=list[AssetReport])
async def list_asset_reports(
    request: Request,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List retained asset reports, newest first, with stable logical paging."""
    return _list_rows(
        request.app.state.asset_report_store,
        limit=limit,
        offset=offset,
        page=page,
        cursor=cursor,
        scope="asset-reports",
        response=response,
    )


@router.get("/asset-reports/{report_id}", response_model=AssetReport)
async def get_asset_report(report_id: str, request: Request) -> dict:
    """Fetch a single ingested asset report by its report ID."""
    record = request.app.state.asset_report_store.find_one("report_id", report_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report not found")
    return record


@router.get(
    "/asset-reports/{report_id}/lineage",
    response_model=LineageResponse[AssetReport],
)
async def get_asset_report_lineage(report_id: str, request: Request) -> LineageResponse[dict]:
    """Return every retained child envelope for one logical asset report."""
    return _lineage_response(
        request.app.state.asset_report_store,
        id_field="report_id",
        requested_id=report_id,
        kind="asset",
    )


@router.get("/trace-batches", response_model=list[TraceBatch])
async def list_trace_batches(
    request: Request,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List retained trace batches, newest first, with stable logical paging."""
    return _list_rows(
        request.app.state.trace_batch_store,
        limit=limit,
        offset=offset,
        page=page,
        cursor=cursor,
        scope="trace-batches",
        response=response,
    )


@router.get("/mde-security-batches", response_model=list[MdeSecurityBatch])
async def list_mde_security_batches(
    request: Request,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List normalized MDE cloud sync chunks, newest first."""
    return _list_rows(
        request.app.state.mde_security_store,
        limit=limit,
        offset=offset,
        page=page,
        cursor=cursor,
        scope="mde-security-batches",
        response=response,
    )


@router.get("/mde-security-batches/{batch_id}", response_model=MdeSecurityBatch)
async def get_mde_security_batch(batch_id: str, request: Request) -> dict:
    record = request.app.state.mde_security_store.find_one("batch_id", batch_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MDE batch not found")
    return record


@router.get("/mdvm-vulnerability-batches", response_model=list[MdvmVulnerabilityBatch])
async def list_mdvm_vulnerability_batches(
    request: Request,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List normalized MDVM snapshot handoffs, newest first."""
    return _list_rows(
        request.app.state.mdvm_vulnerability_store,
        limit=limit,
        offset=offset,
        page=page,
        cursor=cursor,
        scope="mdvm-vulnerability-batches",
        response=response,
    )


@router.get("/mdvm-vulnerability-batches/{batch_id}", response_model=MdvmVulnerabilityBatch)
async def get_mdvm_vulnerability_batch(batch_id: str, request: Request) -> dict:
    record = request.app.state.mdvm_vulnerability_store.find_one("batch_id", batch_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MDVM batch not found")
    return record


@router.get("/vulnerabilities", response_model=list[DetectionResult])
async def list_vulnerabilities(
    request: Request,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List retained detection results, newest first, with stable logical paging."""
    return _list_rows(
        request.app.state.vulnerability_store,
        limit=limit,
        offset=offset,
        page=page,
        cursor=cursor,
        scope="vulnerabilities",
        response=response,
    )


@router.get("/vulnerabilities/{report_id}", response_model=DetectionResult)
async def get_report_detections(report_id: str, request: Request) -> dict:
    """Fetch the detection result for a single asset report (by its report ID)."""
    record = request.app.state.vulnerability_store.find_one("report_id", report_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no detections for report"
        )
    return record


@router.get(
    "/vulnerabilities/{report_id}/lineage",
    response_model=LineageResponse[DetectionResult],
)
async def get_detection_lineage(report_id: str, request: Request) -> LineageResponse[dict]:
    """Batch-fetch detection status/findings for every retained report chunk."""
    asset_root, expected, asset_complete, asset_rows = _lineage_rows(
        request.app.state.asset_report_store,
        id_field="report_id",
        requested_id=report_id,
        kind="asset",
    )
    root, detection_expected, detection_complete, detections = _lineage_rows(
        request.app.state.vulnerability_store,
        id_field="report_id",
        requested_id=asset_root,
        kind="asset",
    )
    if not asset_rows and not detections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="lineage not found")
    expected = expected if expected is not None else detection_expected
    if expected is not None:
        complete: bool | None = len(detections) == expected and bool(asset_complete is not False)
    else:
        complete = detection_complete
    return LineageResponse[dict](
        lineage_id=root,
        expected_chunks=expected,
        received_chunks=len(detections),
        complete=complete,
        records=detections,
    )


@router.get("/guard-events", response_model=list[GuardEventBatch])
async def list_guard_events(
    request: Request,
    response: Response,
    host_id: str | None = Query(default=None, description="filter to one host"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    page: int | None = Query(default=None, ge=0, le=10000),
    cursor: str | None = Query(default=None, min_length=1, max_length=4096),
) -> list[dict]:
    """List the most recent real-time protection event batches, newest first.

    Optionally filter to a single ``host_id`` (e.g. the host a guard scan targets).
    """
    if host_id is None:
        return _list_rows(
            request.app.state.guard_event_store,
            limit=limit,
            offset=offset,
            page=page,
            cursor=cursor,
            scope="guard-events",
            response=response,
        )
    _validate_paging(offset=offset, page=page, cursor=cursor)
    if page is None and (cursor is not None or offset == 0):
        scope = "guard-events:" + hashlib.sha256(host_id.encode()).hexdigest()
        return _cursor_rows(
            request.app.state.guard_event_store,
            limit=limit,
            cursor=cursor,
            scope=scope,
            response=response,
            field="host_id",
            value=host_id,
        )
    if page is None:
        return _guard_rows(
            request.app.state.guard_event_store,
            host_id=host_id,
            limit=limit,
            offset=offset,
        )
    rows, has_more = _guard_page_rows(
        request.app.state.guard_event_store,
        host_id=host_id,
        limit=limit,
        page=page,
    )
    response.headers[_PAGE_HEADER] = "true" if has_more else "false"
    return rows


@router.get(
    "/trace-batches/{batch_id}/lineage",
    response_model=LineageResponse[TraceBatch],
)
async def get_trace_batch_lineage(batch_id: str, request: Request) -> LineageResponse[dict]:
    """Return every retained child envelope for one logical trace batch."""
    return _lineage_response(
        request.app.state.trace_batch_store,
        id_field="batch_id",
        requested_id=batch_id,
        kind="trace",
    )
