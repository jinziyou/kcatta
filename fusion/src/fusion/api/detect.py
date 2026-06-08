"""On-demand vulnerability detection endpoint.

Accepts an `AssetReport` and matches its packages against the OSV store
loaded at app startup, returning a `DetectionResult`. Stateless: it neither
reads the ingest stores nor persists results, so it composes cleanly with
`/ingest/asset-report` (ingest to store + auto-detect, this for ad-hoc runs).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from ..detect import combine_findings, detect_report, resolve_ecosystem, scanner_findings
from ..schemas import AssetReport, DetectionResult

router = APIRouter(prefix="/detect", tags=["detect"])


@router.post("/asset-report", response_model=DetectionResult)
async def detect_asset_report(report: AssetReport, request: Request) -> DetectionResult:
    """Match an asset report against the OSV store and return findings without persisting."""
    malware = scanner_findings(report)
    ecosystem = resolve_ecosystem(report, request.app.state.osv_ecosystem) or ""

    osv_vulns: list = []
    store = request.app.state.osv_store
    if store.record_count > 0:
        if not ecosystem:
            if not malware:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"cannot derive OSV ecosystem from host.os {report.host.os!r}; "
                        "set FUSION_OSV_ECOSYSTEM"
                    ),
                )
        else:
            osv_vulns = detect_report(report, store, ecosystem)

    vulnerabilities = combine_findings(osv_vulns, malware)
    return DetectionResult(
        report_id=report.report_id,
        host_id=report.host.host_id,
        collected_at=report.collected_at,
        ecosystem=ecosystem,
        vulnerabilities=vulnerabilities,
    )
