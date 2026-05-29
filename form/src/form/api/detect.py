"""On-demand vulnerability detection endpoint.

Accepts an `AssetReport` and matches its packages against the OSV store
loaded at app startup, returning a `DetectionResult`. Stateless: it neither
reads the ingest stores nor persists results, so it composes cleanly with
`/ingest/asset-report` (ingest to store + auto-detect, this for ad-hoc runs).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..detect import detect_report, resolve_ecosystem
from ..schemas import AssetReport, DetectionResult

router = APIRouter(prefix="/detect", tags=["detect"])


@router.post("/asset-report", response_model=DetectionResult)
async def detect_asset_report(report: AssetReport, request: Request) -> DetectionResult:
    ecosystem = resolve_ecosystem(report, request.app.state.osv_ecosystem)
    if not ecosystem:
        raise HTTPException(
            status_code=422,
            detail=(
                f"cannot derive OSV ecosystem from host.os {report.host.os!r}; "
                "set FORM_OSV_ECOSYSTEM"
            ),
        )

    vulnerabilities = detect_report(report, request.app.state.osv_store, ecosystem)
    return DetectionResult(
        report_id=report.report_id,
        host_id=report.host.host_id,
        collected_at=report.collected_at,
        ecosystem=ecosystem,
        vulnerabilities=vulnerabilities,
    )
