"""Microsoft Defender Antivirus adapter for Form-managed Windows scans.

The Rust host collector remains responsible for portable inventory and posture
checks.  On WinRM targets Form delegates malware scanning to the Defender
installation already present on Windows, then converts its bounded local status,
threat history, and Operational log evidence into the shared AssetReport contract.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from analyzer.schemas import (
    DetectorKind,
    DetectorRun,
    DetectorRunStatus,
    SecurityProduct,
    Severity,
    StrictModel,
    Timestamp,
    Vulnerability,
)
from analyzer.schemas.common import MAX_NESTED_LIST_ITEMS
from pydantic import Field

from ._util import read_artifact_text

DEFENDER_ARTIFACT = "defender.json"
DEFENDER_ASSET_ID = "security-product-microsoft-defender"
DEFENDER_SOURCE = "microsoft-defender"
DEFENDER_EVENT_SOURCE = "microsoft-defender-event"
DEFENDER_EVENT_IDS = (1116, 1117, 1118, 1119, 1121, 1123, 1126, 1127)
DEFENDER_MAX_RECORDS = 128
DEFENDER_QUERY_RECORDS = DEFENDER_MAX_RECORDS + 1
DEFENDER_EVENT_LOOKBACK_DAYS = 30

DefenderScan = Literal["none", "quick", "full"]
DefenderScanStatus = Literal["not_requested", "complete", "failed"]


class _Session(Protocol):
    def exec(self, ps_script: str): ...

    def download_file(self, remote: str, local: Path) -> None: ...


class DefenderStatus(StrictModel):
    product_version: str | None = None
    engine_version: str | None = None
    signature_version: str | None = None
    signature_updated_at: Timestamp | None = None
    signatures_out_of_date: bool | None = None
    running_mode: str | None = None
    service_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    real_time_protection: bool | None = None
    behavior_monitor: bool | None = None
    ioav_protection: bool | None = None
    tamper_protection: bool | None = None
    cloud_protection: bool | None = None
    last_quick_scan_at: Timestamp | None = None
    last_full_scan_at: Timestamp | None = None


class DefenderThreat(StrictModel):
    threat_id: str
    name: str | None = None
    severity_id: int | None = None
    category_id: int | None = None
    active: bool | None = None
    executed: bool | None = None
    resources: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)


class DefenderDetection(StrictModel):
    threat_id: str
    detection_id: str | None = None
    initial_detection_at: Timestamp | None = None
    last_status_change_at: Timestamp | None = None
    action_success: bool | None = None
    status_id: int | None = None
    status_error_code: int | None = None
    process_name: str | None = None
    resources: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)


class DefenderEvent(StrictModel):
    event_id: int
    record_id: int
    created_at: Timestamp
    level: str | None = None
    message: str | None = None


class DefenderSnapshot(StrictModel):
    schema_version: Literal[1] = 1
    collected_at: Timestamp
    enabled: bool
    requested_scan: DefenderScan | None = None
    scan_status: DefenderScanStatus = "not_requested"
    scan_error: str | None = None
    status: DefenderStatus | None = None
    threats: list[DefenderThreat] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    detections: list[DefenderDetection] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    events: list[DefenderEvent] = Field(
        default_factory=list, max_length=MAX_NESTED_LIST_ITEMS
    )
    errors: list[str] = Field(default_factory=list, max_length=MAX_NESTED_LIST_ITEMS)


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _powershell_snapshot(remote_path: str, requested_scan: DefenderScan | None) -> str:
    enabled = "$true" if requested_scan is not None else "$false"
    requested = "$null" if requested_scan is None else _ps_literal(requested_scan)
    scan_command = ""
    if requested_scan in {"quick", "full"}:
        scan_type = "QuickScan" if requested_scan == "quick" else "FullScan"
        scan_command = f"""
try {{
    Start-MpScan -ScanType {scan_type} -ErrorAction Stop
    $result.scan_status = 'complete'
}} catch {{
    $result.scan_status = 'failed'
    $result.scan_error = Limit-Text $_.Exception.Message
    $result.errors += 'defender_scan_failed'
}}
"""

    event_ids = ",".join(str(item) for item in DEFENDER_EVENT_IDS)
    return f"""
$ErrorActionPreference = 'Stop'
function To-UtcString($Value) {{
    if ($null -eq $Value) {{ return $null }}
    try {{ return ([DateTime]$Value).ToUniversalTime().ToString('o') }} catch {{ return $null }}
}}
function Limit-Text($Value) {{
    if ($null -eq $Value) {{ return $null }}
    $text = [string]$Value
    if ($text.Length -gt 4096) {{ return $text.Substring(0, 4096) }}
    return $text
}}
function String-Array($Value) {{
    if ($null -eq $Value) {{ return @() }}
    return @(
        $Value |
        Select-Object -First {MAX_NESTED_LIST_ITEMS} |
        ForEach-Object {{ Limit-Text $_ }}
    )
}}
$result = [ordered]@{{
    schema_version = 1
    collected_at = [DateTime]::UtcNow.ToString('o')
    enabled = {enabled}
    requested_scan = {requested}
    scan_status = 'not_requested'
    scan_error = $null
    status = $null
    threats = @()
    detections = @()
    events = @()
    errors = @()
}}

if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {{
    $result.errors += 'defender_cmdlets_unavailable'
}} else {{
{scan_command}
    try {{
        $s = Get-MpComputerStatus -ErrorAction Stop
        $cloud = $null
        try {{
            $pref = Get-MpPreference -ErrorAction Stop
            if ($null -ne $pref.MAPSReporting) {{ $cloud = ([int]$pref.MAPSReporting -ne 0) }}
        }} catch {{
            $result.errors += 'defender_preference_unavailable'
        }}
        $result.status = [ordered]@{{
            product_version = Limit-Text $s.AMProductVersion
            engine_version = Limit-Text $s.AMEngineVersion
            signature_version = Limit-Text $s.AntivirusSignatureVersion
            signature_updated_at = To-UtcString $s.AntivirusSignatureLastUpdated
            signatures_out_of_date = $s.DefenderSignaturesOutOfDate
            running_mode = Limit-Text $s.AMRunningMode
            service_enabled = $s.AMServiceEnabled
            antivirus_enabled = $s.AntivirusEnabled
            real_time_protection = $s.RealTimeProtectionEnabled
            behavior_monitor = $s.BehaviorMonitorEnabled
            ioav_protection = $s.IoavProtectionEnabled
            tamper_protection = $s.IsTamperProtected
            cloud_protection = $cloud
            last_quick_scan_at = To-UtcString $s.QuickScanEndTime
            last_full_scan_at = To-UtcString $s.FullScanEndTime
        }}
    }} catch {{
        $result.errors += 'defender_status_unavailable'
    }}

    if ($result.enabled) {{
        try {{
            $threatRows = @(
                Get-MpThreat -ErrorAction Stop |
                Sort-Object IsActive -Descending |
                Select-Object -First {DEFENDER_QUERY_RECORDS}
            )
            if ($threatRows.Count -gt {DEFENDER_MAX_RECORDS}) {{
                $result.errors += 'defender_threat_history_truncated'
            }}
            $result.threats = @(
                $threatRows |
                Select-Object -First {DEFENDER_MAX_RECORDS} |
                ForEach-Object {{
                [ordered]@{{
                    threat_id = [string]$_.ThreatID
                    name = Limit-Text $_.ThreatName
                    severity_id = $_.SeverityID
                    category_id = $_.CategoryID
                    active = $_.IsActive
                    executed = $_.DidThreatExecute
                    resources = String-Array $_.Resources
                }}
                }}
            )
        }} catch {{
            $result.errors += 'defender_threat_history_unavailable'
        }}
        try {{
            $detectionRows = @(
                Get-MpThreatDetection -ErrorAction Stop |
                Sort-Object InitialDetectionTime -Descending |
                Select-Object -First {DEFENDER_QUERY_RECORDS}
            )
            if ($detectionRows.Count -gt {DEFENDER_MAX_RECORDS}) {{
                $result.errors += 'defender_detection_history_truncated'
            }}
            $result.detections = @(
                $detectionRows |
                Select-Object -First {DEFENDER_MAX_RECORDS} |
                ForEach-Object {{
                [ordered]@{{
                    threat_id = [string]$_.ThreatID
                    detection_id = Limit-Text $_.DetectionID
                    initial_detection_at = To-UtcString $_.InitialDetectionTime
                    last_status_change_at = To-UtcString $_.LastThreatStatusChangeTime
                    action_success = $_.ActionSuccess
                    status_id = $_.ThreatStatusID
                    status_error_code = $_.ThreatStatusErrorCode
                    process_name = Limit-Text $_.ProcessName
                    resources = String-Array $_.Resources
                }}
                }}
            )
        }} catch {{
            $result.errors += 'defender_detection_history_unavailable'
        }}
        try {{
            $filter = @{{
                LogName = 'Microsoft-Windows-Windows Defender/Operational'
                Id = @({event_ids})
                StartTime = (Get-Date).AddDays(-{DEFENDER_EVENT_LOOKBACK_DAYS})
            }}
            $eventRows = @(
                Get-WinEvent -FilterHashtable $filter `
                    -MaxEvents {DEFENDER_QUERY_RECORDS} -ErrorAction SilentlyContinue
            )
            if ($eventRows.Count -gt {DEFENDER_MAX_RECORDS}) {{
                $result.errors += 'defender_operational_log_truncated'
            }}
            $result.events = @(
                $eventRows |
                Select-Object -First {DEFENDER_MAX_RECORDS} |
                ForEach-Object {{
                [ordered]@{{
                    event_id = $_.Id
                    record_id = $_.RecordId
                    created_at = To-UtcString $_.TimeCreated
                    level = Limit-Text $_.LevelDisplayName
                    message = Limit-Text $_.Message
                }}
                }}
            )
        }} catch {{
            $result.errors += 'defender_operational_log_unavailable'
        }}
    }}
}}
$json = $result | ConvertTo-Json -Depth 6 -Compress
[IO.File]::WriteAllText({_ps_literal(remote_path)}, $json, (New-Object Text.UTF8Encoding($false)))
""".strip()


def failed_snapshot(
    *, enabled: bool, requested_scan: DefenderScan | None, reason: str
) -> DefenderSnapshot:
    """Return a bounded explicit failure record without losing the host inventory."""

    return DefenderSnapshot(
        collected_at=datetime.now(UTC),
        enabled=enabled,
        requested_scan=requested_scan,
        scan_status="failed" if requested_scan in {"quick", "full"} else "not_requested",
        scan_error=reason,
        errors=[reason],
    )


def load_defender_snapshot(path: Path) -> DefenderSnapshot:
    return DefenderSnapshot.model_validate_json(read_artifact_text(path))


def collect_defender_snapshot(
    session: _Session,
    *,
    remote_path: str,
    output_dir: Path,
    requested_scan: DefenderScan | None,
) -> Path:
    """Collect a snapshot, degrading to an explicit failed artifact on Defender errors."""

    if requested_scan not in {None, "none", "quick", "full"}:
        raise ValueError("Defender scan must be one of none, quick, or full")
    output_dir.mkdir(parents=True, exist_ok=True)
    local_path = output_dir / DEFENDER_ARTIFACT
    try:
        response = session.exec(_powershell_snapshot(remote_path, requested_scan))
        if getattr(response, "status_code", 0) != 0:
            stderr = getattr(response, "std_err", b"")
            detail = (
                stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr)
            )[:512]
            raise RuntimeError(detail or "Defender PowerShell adapter failed")
        session.download_file(remote_path, local_path)
        load_defender_snapshot(local_path)
    except InterruptedError:
        raise
    except Exception:
        snapshot = failed_snapshot(
            enabled=requested_scan is not None,
            requested_scan=requested_scan,
            reason="defender_collection_failed",
        )
        local_path.write_text(snapshot.model_dump_json(), encoding="utf-8")
    return local_path


def security_product(snapshot: DefenderSnapshot) -> SecurityProduct:
    status = snapshot.status
    mode = status.running_mode if status is not None else None
    if status is None:
        product_status = "unavailable"
    elif mode is not None and "passive" in mode.casefold():
        product_status = "passive"
    elif status.service_enabled and status.antivirus_enabled:
        product_status = "active"
    else:
        product_status = "disabled"
    return SecurityProduct(
        asset_id=DEFENDER_ASSET_ID,
        parent_asset_id=None,
        name="Microsoft Defender Antivirus",
        vendor="Microsoft",
        status=product_status,
        mode=mode,
        product_version=status.product_version if status is not None else None,
        engine_version=status.engine_version if status is not None else None,
        signature_version=status.signature_version if status is not None else None,
        signature_updated_at=status.signature_updated_at if status is not None else None,
        signatures_out_of_date=(status.signatures_out_of_date if status is not None else None),
        real_time_protection=(status.real_time_protection if status is not None else None),
        behavior_monitor=status.behavior_monitor if status is not None else None,
        ioav_protection=status.ioav_protection if status is not None else None,
        tamper_protection=status.tamper_protection if status is not None else None,
        cloud_protection=status.cloud_protection if status is not None else None,
        last_quick_scan_at=status.last_quick_scan_at if status is not None else None,
        last_full_scan_at=status.last_full_scan_at if status is not None else None,
    )


def _severity(severity_id: int | None) -> Severity:
    if severity_id in {4, 5}:
        return Severity.CRITICAL
    if severity_id == 3:
        return Severity.HIGH
    if severity_id == 2:
        return Severity.MEDIUM
    if severity_id == 1:
        return Severity.LOW
    return Severity.INFO


def _evidence(parts: list[str]) -> str | None:
    value = "; ".join(part for part in parts if part)
    return value[:4096] or None


def defender_findings(snapshot: DefenderSnapshot) -> list[Vulnerability]:
    """Convert bounded local Defender history and security events to findings."""

    if not snapshot.enabled:
        return []
    threats = {item.threat_id: item for item in snapshot.threats}
    findings: list[Vulnerability] = []
    detected_threat_ids: set[str] = set()
    for index, detection in enumerate(snapshot.detections):
        threat = threats.get(detection.threat_id)
        detected_threat_ids.add(detection.threat_id)
        token = detection.detection_id or f"{detection.threat_id}-{index}"
        findings.append(
            Vulnerability(
                vuln_id=f"DEFENDER-{token}"[:256],
                severity=_severity(threat.severity_id if threat is not None else None),
                affected_asset_id=DEFENDER_ASSET_ID,
                source=DEFENDER_SOURCE,
                evidence=_evidence(
                    [
                        f"threat={threat.name}" if threat and threat.name else "",
                        f"threat_id={detection.threat_id}",
                        (
                            f"detected_at={detection.initial_detection_at.isoformat()}"
                            if detection.initial_detection_at
                            else ""
                        ),
                        f"action_success={detection.action_success}",
                        f"process={detection.process_name}" if detection.process_name else "",
                        (
                            "resources=" + ",".join(detection.resources[:8])
                            if detection.resources
                            else ""
                        ),
                    ]
                ),
            )
        )
    for threat in snapshot.threats:
        if threat.threat_id in detected_threat_ids:
            continue
        findings.append(
            Vulnerability(
                vuln_id=f"DEFENDER-THREAT-{threat.threat_id}"[:256],
                severity=_severity(threat.severity_id),
                affected_asset_id=DEFENDER_ASSET_ID,
                source=DEFENDER_SOURCE,
                evidence=_evidence(
                    [
                        f"threat={threat.name}" if threat.name else "",
                        f"active={threat.active}",
                        f"executed={threat.executed}",
                        "resources=" + ",".join(threat.resources[:8]) if threat.resources else "",
                    ]
                ),
            )
        )
    event_severity = {
        1116: Severity.HIGH,
        1117: Severity.INFO,
        1118: Severity.MEDIUM,
        1119: Severity.HIGH,
        1121: Severity.HIGH,
        1123: Severity.HIGH,
        1126: Severity.HIGH,
        1127: Severity.HIGH,
    }
    for event in snapshot.events:
        findings.append(
            Vulnerability(
                vuln_id=f"DEFENDER-EVENT-{event.event_id}-{event.record_id}",
                severity=event_severity.get(event.event_id, Severity.INFO),
                affected_asset_id=DEFENDER_ASSET_ID,
                source=DEFENDER_EVENT_SOURCE,
                evidence=_evidence(
                    [
                        f"created_at={event.created_at.isoformat()}",
                        f"level={event.level}" if event.level else "",
                        event.message or "",
                    ]
                ),
            )
        )
    return findings


def defender_detector_run(
    snapshot: DefenderSnapshot, *, finding_count: int
) -> DetectorRun | None:
    if not snapshot.enabled:
        return None
    if snapshot.status is None:
        status = DetectorRunStatus.FAILED
        reason = "defender_unavailable"
    elif snapshot.scan_status == "failed":
        status = DetectorRunStatus.PARTIAL
        reason = "defender_scan_failed"
    elif snapshot.errors:
        status = DetectorRunStatus.PARTIAL
        reason = "defender_telemetry_partial"
    else:
        status = DetectorRunStatus.COMPLETE
        reason = None
    return DetectorRun(
        detector=DetectorKind.DEFENDER,
        status=status,
        finding_count=finding_count,
        reason=reason,
    )
