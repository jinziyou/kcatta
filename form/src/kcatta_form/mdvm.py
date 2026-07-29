"""Read-only Microsoft Defender Vulnerability Management materialization."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from analyzer.schemas import (
    MdvmDeviceSnapshot,
    MdvmSoftwareVulnerability,
    MdvmVulnerabilityBatch,
)

from . import metrics as metrics_mod
from .analyzer_client import AnalyzerUpstreamError
from .mde import (
    MAX_GRAPH_RESPONSE_BYTES,
    MAX_TOKEN_RESPONSE_BYTES,
    MdeConfigurationError,
    MdeHostMapper,
    MdeUpstreamError,
    _optional_text,
    _read_secret,
    _retry_after,
    _severity,
    _timestamp,
)

logger = logging.getLogger("kcatta_form.mdvm")

MDVM_SCOPE = "https://api.securitycenter.microsoft.com/.default"
_BASELINE_PATH = "/api/machines/SoftwareVulnerabilitiesByMachine"
_DELTA_PATH = "/api/machines/SoftwareVulnerabilityChangesByMachine"
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_SAFE_ID = re.compile(r"^[A-Za-z0-9.-]{1,256}$")
_ALLOWED_API_HOSTS = frozenset(
    {
        "api.security.microsoft.com",
        "us.api.security.microsoft.com",
        "eu.api.security.microsoft.com",
        "uk.api.security.microsoft.com",
        "au.api.security.microsoft.com",
        "swa.api.security.microsoft.com",
        "ina.api.security.microsoft.com",
        "aea.api.security.microsoft.com",
    }
)


@dataclass(frozen=True)
class MdvmConfig:
    enabled: bool
    tenant_id: str = ""
    client_id: str = ""
    client_secret_file: Path | None = None
    host_map_file: Path | None = None
    state_path: Path = Path("data/mdvm-sync.db")
    api_host: str = "api.security.microsoft.com"
    poll_seconds: float = 21_600.0
    baseline_refresh_hours: float = 168.0
    delta_overlap_seconds: float = 21_600.0
    timeout_seconds: float = 60.0
    page_size: int = 1000
    max_pages: int = 200
    max_items: int = 50_000
    findings_per_snapshot: int = 512
    snapshots_per_batch: int = 32
    batch_max_bytes: int = 3 * 1024 * 1024
    state_max_findings: int = 200_000
    state_max_bytes: int = 256 * 1024 * 1024
    max_attempts: int = 4

    @classmethod
    def from_env(cls, data_dir: Path) -> MdvmConfig:
        enabled = _env_bool("FORM_MDVM_ENABLED", False)
        if not enabled:
            return cls(enabled=False, state_path=data_dir / "mdvm-sync.db")
        tenant = os.getenv("FORM_MDVM_TENANT_ID", "").strip() or os.getenv(
            "FORM_MDE_TENANT_ID", ""
        ).strip()
        client = os.getenv("FORM_MDVM_CLIENT_ID", "").strip() or os.getenv(
            "FORM_MDE_CLIENT_ID", ""
        ).strip()
        secret_raw = os.getenv("FORM_MDVM_CLIENT_SECRET_FILE", "").strip() or os.getenv(
            "FORM_MDE_CLIENT_SECRET_FILE", ""
        ).strip()
        map_raw = os.getenv("FORM_MDVM_HOST_MAP_FILE", "").strip() or os.getenv(
            "FORM_MDE_HOST_MAP_FILE", ""
        ).strip()
        state_raw = os.getenv("FORM_MDVM_STATE_PATH", "").strip()
        api_host = os.getenv("FORM_MDVM_API_HOST", "api.security.microsoft.com").strip().lower()
        config = cls(
            enabled=True,
            tenant_id=tenant,
            client_id=client,
            client_secret_file=Path(secret_raw) if secret_raw else None,
            host_map_file=Path(map_raw) if map_raw else None,
            state_path=Path(state_raw) if state_raw else data_dir / "mdvm-sync.db",
            api_host=api_host,
            poll_seconds=_positive_float("FORM_MDVM_POLL_SECONDS", 21_600.0),
            baseline_refresh_hours=_positive_float(
                "FORM_MDVM_BASELINE_REFRESH_HOURS", 168.0
            ),
            delta_overlap_seconds=_positive_float(
                "FORM_MDVM_DELTA_OVERLAP_SECONDS", 21_600.0
            ),
            timeout_seconds=_positive_float("FORM_MDVM_TIMEOUT_SECONDS", 60.0),
            page_size=_positive_int("FORM_MDVM_PAGE_SIZE", 1000),
            max_pages=_positive_int("FORM_MDVM_MAX_PAGES", 200),
            max_items=_positive_int("FORM_MDVM_MAX_ITEMS", 50_000),
            findings_per_snapshot=_positive_int(
                "FORM_MDVM_FINDINGS_PER_SNAPSHOT", 512
            ),
            snapshots_per_batch=_positive_int("FORM_MDVM_SNAPSHOTS_PER_BATCH", 32),
            batch_max_bytes=_positive_int(
                "FORM_MDVM_BATCH_MAX_BYTES", 3 * 1024 * 1024
            ),
            state_max_findings=_positive_int("FORM_MDVM_STATE_MAX_FINDINGS", 200_000),
            state_max_bytes=_positive_int(
                "FORM_MDVM_STATE_MAX_BYTES", 256 * 1024 * 1024
            ),
            max_attempts=_positive_int("FORM_MDVM_MAX_ATTEMPTS", 4),
        )
        if not config.tenant_id or not _SAFE_ID.fullmatch(config.tenant_id):
            raise MdeConfigurationError("FORM_MDVM_TENANT_ID is missing or invalid")
        if not config.client_id or not _SAFE_ID.fullmatch(config.client_id):
            raise MdeConfigurationError("FORM_MDVM_CLIENT_ID is missing or invalid")
        if config.client_secret_file is None:
            raise MdeConfigurationError(
                "FORM_MDVM_CLIENT_SECRET_FILE is required when FORM_MDVM_ENABLED=true"
            )
        if config.api_host not in _ALLOWED_API_HOSTS:
            raise MdeConfigurationError("FORM_MDVM_API_HOST is not an allowed Microsoft host")
        if config.page_size > 10_000:
            raise MdeConfigurationError("FORM_MDVM_PAGE_SIZE cannot exceed 10000")
        if config.findings_per_snapshot > 4096:
            raise MdeConfigurationError("FORM_MDVM_FINDINGS_PER_SNAPSHOT cannot exceed 4096")
        if config.snapshots_per_batch > 256:
            raise MdeConfigurationError("FORM_MDVM_SNAPSHOTS_PER_BATCH cannot exceed 256")
        if config.batch_max_bytes > 8 * 1024 * 1024:
            raise MdeConfigurationError("FORM_MDVM_BATCH_MAX_BYTES cannot exceed 8 MiB")
        if config.delta_overlap_seconds > 86_400:
            raise MdeConfigurationError("FORM_MDVM_DELTA_OVERLAP_SECONDS cannot exceed 86400")
        return config


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise MdeConfigurationError(f"{name} must be a boolean")


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise MdeConfigurationError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise MdeConfigurationError(f"{name} must be a positive integer")
    return value


def _positive_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise MdeConfigurationError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise MdeConfigurationError(f"{name} must be a positive number")
    return value


def _validate_api_url(url: str, path: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() not in _ALLOWED_API_HOSTS
        or parsed.path != path
        or parsed.fragment
    ):
        raise MdeUpstreamError("MDVM returned an invalid pagination URL")


class MdvmClient:
    """Legacy-audience MDE API client limited to MDVM baseline and delta GETs."""

    def __init__(
        self,
        config: MdvmConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.config = config
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )
        self._sleep = sleeper
        self._access_token: str | None = None
        self._token_expires_at = 0.0

    async def close(self) -> None:
        await self._client.aclose()

    async def _token(self) -> str:
        if self._access_token and time.monotonic() < self._token_expires_at - 60:
            return self._access_token
        assert self.config.client_secret_file is not None
        secret = _read_secret(self.config.client_secret_file)
        url = (
            "https://login.microsoftonline.com/"
            f"{self.config.tenant_id}/oauth2/v2.0/token"
        )
        try:
            response = await self._client.post(
                url,
                data={
                    "client_id": self.config.client_id,
                    "client_secret": secret,
                    "scope": MDVM_SCOPE,
                    "grant_type": "client_credentials",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.RequestError as exc:
            raise MdeUpstreamError("Microsoft identity platform is unavailable") from exc
        if response.status_code != 200:
            raise MdeUpstreamError(
                f"Microsoft identity platform rejected the MDVM credential ({response.status_code})"
            )
        if len(response.content) > MAX_TOKEN_RESPONSE_BYTES:
            raise MdeUpstreamError("Microsoft identity platform returned an oversized response")
        try:
            payload = response.json()
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError) as exc:
            raise MdeUpstreamError("Microsoft identity platform returned invalid JSON") from exc
        if not isinstance(token, str) or not token or len(token) > 32_768:
            raise MdeUpstreamError("Microsoft identity platform returned an invalid token")
        self._access_token = token
        self._token_expires_at = time.monotonic() + max(60, expires_in)
        return token

    async def _get(self, url: str, params: Mapping[str, str] | None, path: str) -> dict[str, Any]:
        _validate_api_url(url, path)
        for attempt in range(self.config.max_attempts):
            token = await self._token()
            try:
                response = await self._client.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
            except httpx.RequestError as exc:
                if attempt + 1 == self.config.max_attempts:
                    raise MdeUpstreamError("MDVM API is unavailable") from exc
                await self._sleep(min(30.0, 2.0**attempt))
                continue
            if response.status_code == 401 and attempt == 0:
                self._access_token = None
                self._token_expires_at = 0.0
                continue
            if (
                response.status_code == 429 or 500 <= response.status_code < 600
            ) and attempt + 1 < self.config.max_attempts:
                await self._sleep(_retry_after(response))
                continue
            if response.status_code != 200:
                raise MdeUpstreamError(f"MDVM request failed ({response.status_code})")
            if len(response.content) > MAX_GRAPH_RESPONSE_BYTES:
                raise MdeUpstreamError("MDVM returned an oversized response")
            try:
                payload = response.json()
            except ValueError as exc:
                raise MdeUpstreamError("MDVM returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise MdeUpstreamError("MDVM returned an invalid response object")
            return payload
        raise MdeUpstreamError("MDVM retry budget exhausted")

    async def _fetch(
        self,
        path: str,
        params: dict[str, str] | None,
    ) -> list[dict[str, Any]]:
        url = f"https://{self.config.api_host}{path}"
        records: list[dict[str, Any]] = []
        for _page in range(self.config.max_pages):
            payload = await self._get(url, params, path)
            values = payload.get("value")
            if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                raise MdeUpstreamError("MDVM response has an invalid value list")
            if len(records) + len(values) > self.config.max_items:
                raise MdeUpstreamError("MDVM result exceeds FORM_MDVM_MAX_ITEMS")
            records.extend(values)
            next_link = payload.get("@odata.nextLink")
            if next_link is None:
                return records
            if not isinstance(next_link, str):
                raise MdeUpstreamError("MDVM returned an invalid nextLink")
            _validate_api_url(next_link, path)
            url = next_link
            params = None
        raise MdeUpstreamError("MDVM result exceeds FORM_MDVM_MAX_PAGES")

    async def baseline(self) -> list[dict[str, Any]]:
        return await self._fetch(_BASELINE_PATH, {"pageSize": str(self.config.page_size)})

    async def delta(self, since: datetime) -> list[dict[str, Any]]:
        instant = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return await self._fetch(
            _DELTA_PATH,
            {"pageSize": str(self.config.page_size), "sinceTime": instant},
        )


def _identifier(value: Any) -> str | None:
    if isinstance(value, (str, int)):
        text = str(value).strip()
        return text[:4096] if text else None
    return None


def _optional_time(value: Any, field: str) -> datetime | None:
    return _timestamp(value, field) if value is not None and str(value).strip() else None


def _cvss(value: Any) -> float | None:
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise MdeUpstreamError("MDVM record has an invalid cvssScore") from exc
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise MdeUpstreamError("MDVM record has an invalid cvssScore")
    return score


def _https_url(value: Any) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    parsed = urlsplit(text)
    return text if parsed.scheme == "https" and parsed.hostname else None


def _path_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip()[:1024] for item in value if isinstance(item, str) and item.strip()][
        :64
    ]


@dataclass(frozen=True)
class _MdvmChange:
    record_key: str
    action: Literal["upsert", "fixed"]
    device_id: str
    device_name: str
    os_platform: str
    os_version: str | None
    os_architecture: str | None
    observed_at: datetime
    finding: MdvmSoftwareVulnerability


def normalize_mdvm_record(
    raw: Mapping[str, Any],
    *,
    mode: Literal["baseline", "delta"],
    fallback_time: datetime,
) -> _MdvmChange | None:
    cve_id = _identifier(raw.get("cveId"))
    if cve_id is None:
        return None
    cve_id = cve_id.upper()
    if not _CVE.fullmatch(cve_id):
        raise MdeUpstreamError("MDVM record contains an invalid cveId")
    record_id = _identifier(raw.get("id"))
    device_id = _identifier(raw.get("deviceId"))
    if not record_id or not device_id:
        raise MdeUpstreamError("MDVM record is missing id or deviceId")
    status = str(raw.get("status") or "").strip().lower()
    if mode == "delta" and status not in {"new", "updated", "fixed"}:
        raise MdeUpstreamError("MDVM delta record has an unknown status")
    event_at = _optional_time(raw.get("eventTimestamp"), "mdvm.eventTimestamp")
    last_seen = _optional_time(raw.get("lastSeenTimestamp"), "mdvm.lastSeenTimestamp")
    first_seen = _optional_time(raw.get("firstSeenTimestamp"), "mdvm.firstSeenTimestamp")
    observed = event_at or last_seen or first_seen or fallback_time
    rbac_id = _identifier(raw.get("rbacGroupId"))
    rbac_name = _optional_text(raw.get("rbacGroupName"))
    scope = rbac_id or rbac_name or ""
    record_key = hashlib.sha256(f"{record_id}\0{scope}".encode()).hexdigest()
    disk_raw = raw.get("diskPaths")
    registry_raw = raw.get("registryPaths")
    disk_paths = _path_list(disk_raw)
    registry_paths = _path_list(registry_raw)
    finding = MdvmSoftwareVulnerability(
        record_id=record_id,
        cve_id=cve_id,
        software_vendor=_optional_text(raw.get("softwareVendor")) or "unknown",
        software_name=_optional_text(raw.get("softwareName")) or "unknown",
        software_version=_optional_text(raw.get("softwareVersion")) or "unknown",
        severity=_severity(raw.get("vulnerabilitySeverityLevel")),
        cvss_score=_cvss(raw.get("cvssScore")),
        exploitability_level=_optional_text(raw.get("exploitabilityLevel")),
        recommended_security_update=_optional_text(raw.get("recommendedSecurityUpdate")),
        recommended_security_update_id=_identifier(raw.get("recommendedSecurityUpdateId")),
        recommended_security_update_url=_https_url(raw.get("recommendedSecurityUpdateUrl")),
        recommendation_reference=_identifier(raw.get("recommendationReference")),
        security_update_available=(
            raw.get("securityUpdateAvailable")
            if isinstance(raw.get("securityUpdateAvailable"), bool)
            else None
        ),
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        last_event_at=event_at,
        rbac_group_id=rbac_id,
        rbac_group_name=rbac_name,
        disk_paths=disk_paths,
        registry_paths=registry_paths,
        evidence_truncated=(
            isinstance(disk_raw, list) and len(disk_raw) > len(disk_paths)
        )
        or (isinstance(registry_raw, list) and len(registry_raw) > len(registry_paths)),
    )
    return _MdvmChange(
        record_key=record_key,
        action="fixed" if mode == "delta" and status == "fixed" else "upsert",
        device_id=device_id,
        device_name=_optional_text(raw.get("deviceName")) or device_id,
        os_platform=_optional_text(raw.get("osPlatform")) or "Microsoft Defender device",
        os_version=_optional_text(raw.get("osVersion")),
        os_architecture=_optional_text(raw.get("osArchitecture")),
        observed_at=observed,
        finding=finding,
    )


class MdvmSyncState:
    """Materialized active MDVM set plus atomic watermark and cross-process lease."""

    def __init__(
        self,
        path: Path,
        *,
        max_findings: int = 200_000,
        max_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.max_findings = max_findings
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mdvm_sync_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                watermark TEXT,
                last_baseline_at TEXT,
                lease_owner TEXT,
                lease_until REAL,
                last_attempt_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                active_device_count INTEGER NOT NULL DEFAULT 0,
                active_finding_count INTEGER NOT NULL DEFAULT 0,
                last_change_count INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO mdvm_sync_state (singleton) VALUES (1);
            CREATE TABLE IF NOT EXISTS mdvm_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                os_platform TEXT NOT NULL,
                os_version TEXT,
                os_architecture TEXT,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mdvm_findings (
                record_key TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mdvm_findings_device
            ON mdvm_findings (device_id);
            """
        )
        self._conn.commit()

    def acquire(self, owner: str, now: datetime, lease_seconds: float) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            changed = self._conn.execute(
                """
                UPDATE mdvm_sync_state
                SET lease_owner = ?, lease_until = ?, last_attempt_at = ?
                WHERE singleton = 1
                  AND (lease_owner IS NULL OR COALESCE(lease_until, 0) <= ? OR lease_owner = ?)
                """,
                (owner, now.timestamp() + lease_seconds, now.isoformat(), now.timestamp(), owner),
            ).rowcount
            self._conn.commit()
        return changed == 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM mdvm_sync_state WHERE singleton = 1").fetchone()
        return dict(row) if row else {}

    def _assert_owner(self, owner: str) -> None:
        row = self._conn.execute(
            "SELECT lease_owner FROM mdvm_sync_state WHERE singleton = 1"
        ).fetchone()
        if row is None or row["lease_owner"] != owner:
            raise RuntimeError("MDVM synchronization lease was lost")

    def _upsert_device(self, change: _MdvmChange) -> None:
        self._conn.execute(
            """
            INSERT INTO mdvm_devices (
                device_id, device_name, os_platform, os_version, os_architecture, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name = excluded.device_name,
                os_platform = excluded.os_platform,
                os_version = excluded.os_version,
                os_architecture = excluded.os_architecture,
                observed_at = CASE
                    WHEN excluded.observed_at > mdvm_devices.observed_at
                    THEN excluded.observed_at ELSE mdvm_devices.observed_at END
            """,
            (
                change.device_id,
                change.device_name,
                change.os_platform,
                change.os_version,
                change.os_architecture,
                change.observed_at.isoformat(),
            ),
        )

    def _ensure_capacity(self) -> None:
        row = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM mdvm_findings"
        ).fetchone()
        count = int(row[0])
        size = int(row[1])
        if count > self.max_findings:
            raise MdeUpstreamError("MDVM active state exceeds FORM_MDVM_STATE_MAX_FINDINGS")
        if size > self.max_bytes:
            raise MdeUpstreamError("MDVM active state exceeds FORM_MDVM_STATE_MAX_BYTES")

    def replace_baseline(self, owner: str, changes: Sequence[_MdvmChange]) -> set[str]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._assert_owner(owner)
                self._conn.execute("DELETE FROM mdvm_findings")
                self._conn.execute("DELETE FROM mdvm_devices")
                for change in changes:
                    self._upsert_device(change)
                    self._conn.execute(
                        "INSERT OR REPLACE INTO mdvm_findings VALUES (?, ?, ?)",
                        (
                            change.record_key,
                            change.device_id,
                            change.finding.model_dump_json(),
                        ),
                    )
                self._ensure_capacity()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return {change.device_id for change in changes}

    def apply_delta(self, owner: str, changes: Sequence[_MdvmChange]) -> set[str]:
        actions: dict[tuple[str, datetime], Literal["upsert", "fixed"]] = {}
        for change in changes:
            key = (change.record_key, change.observed_at)
            previous = actions.get(key)
            if previous is not None and previous != change.action:
                raise MdeUpstreamError(
                    "MDVM delta contains ambiguous same-time fixed and active records"
                )
            actions[key] = change.action
        ordered = sorted(
            changes,
            key=lambda item: (
                item.observed_at,
                {"upsert": 0, "fixed": 1}[item.action],
            ),
        )
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._assert_owner(owner)
                for change in ordered:
                    self._upsert_device(change)
                    if change.action == "fixed":
                        self._conn.execute(
                            "DELETE FROM mdvm_findings WHERE record_key = ?",
                            (change.record_key,),
                        )
                    else:
                        self._conn.execute(
                            "INSERT OR REPLACE INTO mdvm_findings VALUES (?, ?, ?)",
                            (
                                change.record_key,
                                change.device_id,
                                change.finding.model_dump_json(),
                            ),
                        )
                self._ensure_capacity()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return {change.device_id for change in changes}

    def device_snapshots(
        self,
        device_ids: set[str],
        *,
        tenant_id: str,
        mode: Literal["baseline", "delta"],
        mapper: MdeHostMapper,
        findings_per_snapshot: int,
    ) -> list[MdvmDeviceSnapshot]:
        if not device_ids:
            return []
        with self._lock:
            device_rows = self._conn.execute("SELECT * FROM mdvm_devices").fetchall()
            finding_rows = self._conn.execute(
                "SELECT device_id, payload FROM mdvm_findings ORDER BY record_key"
            ).fetchall()
        devices = {
            str(row["device_id"]): row
            for row in device_rows
            if str(row["device_id"]) in device_ids
        }
        findings: dict[str, list[MdvmSoftwareVulnerability]] = defaultdict(list)
        for row in finding_rows:
            device_id = str(row["device_id"])
            if device_id in devices:
                findings[device_id].append(
                    MdvmSoftwareVulnerability.model_validate_json(row["payload"])
                )
        output: list[MdvmDeviceSnapshot] = []
        for device_id in sorted(devices):
            device = devices[device_id]
            rows = findings[device_id]
            parts = max(1, math.ceil(len(rows) / findings_per_snapshot))
            for part_index in range(parts):
                part = rows[
                    part_index * findings_per_snapshot : (part_index + 1)
                    * findings_per_snapshot
                ]
                content = json.dumps(
                    {
                        "tenant": tenant_id,
                        "device": device_id,
                        "observed": device["observed_at"],
                        "part": part_index + 1,
                        "total": parts,
                        "findings": [item.model_dump(mode="json") for item in part],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                report_id = f"mdvm-report-{hashlib.sha256(content.encode()).hexdigest()}"
                device_name = str(device["device_name"])
                host_id = mapper.resolve(
                    mde_device_id=device_id,
                    azure_ad_device_id=None,
                    dns_name=device_name,
                    hostname=device_name.split(".", 1)[0],
                ) or MdeHostMapper._fallback("mde", device_id)
                output.append(
                    MdvmDeviceSnapshot(
                        report_id=report_id,
                        device_id=device_id,
                        host_id=host_id,
                        device_name=device_name,
                        os_platform=str(device["os_platform"]),
                        os_version=device["os_version"],
                        os_architecture=device["os_architecture"],
                        observed_at=_timestamp(device["observed_at"], "stored MDVM observation"),
                        part_index=part_index + 1,
                        part_total=parts,
                        vulnerabilities=part,
                    )
                )
        return output

    def success(
        self,
        owner: str,
        watermark: datetime,
        *,
        mode: Literal["baseline", "delta"],
        changes: int,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            device_count = int(
                self._conn.execute(
                    "SELECT COUNT(DISTINCT device_id) FROM mdvm_findings"
                ).fetchone()[0]
            )
            finding_count = int(
                self._conn.execute("SELECT COUNT(*) FROM mdvm_findings").fetchone()[0]
            )
            changed = self._conn.execute(
                """
                UPDATE mdvm_sync_state
                SET watermark = ?,
                    last_baseline_at = CASE WHEN ? = 'baseline' THEN ? ELSE last_baseline_at END,
                    last_success_at = ?, last_error = NULL,
                    active_device_count = ?, active_finding_count = ?, last_change_count = ?,
                    lease_owner = NULL, lease_until = NULL
                WHERE singleton = 1 AND lease_owner = ?
                """,
                (
                    watermark.isoformat(),
                    mode,
                    watermark.isoformat(),
                    now,
                    device_count,
                    finding_count,
                    changes,
                    owner,
                ),
            ).rowcount
            self._conn.commit()
        if changed != 1:
            raise RuntimeError("MDVM synchronization lease was lost before commit")

    def failure(self, owner: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE mdvm_sync_state
                SET last_error = ?, lease_owner = NULL, lease_until = NULL
                WHERE singleton = 1 AND lease_owner = ?
                """,
                (error[:2048], owner),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


@dataclass(frozen=True)
class MdvmSyncOutcome:
    acquired: bool
    mode: Literal["baseline", "delta"] | None = None
    changes: int = 0
    devices: int = 0
    findings: int = 0
    batches: int = 0


class MdvmSyncEngine:
    def __init__(
        self,
        config: MdvmConfig,
        client: MdvmClient,
        analyzer: Any,
        state: MdvmSyncState,
    ) -> None:
        self.config = config
        self.client = client
        self.analyzer = analyzer
        self.state = state

    def _batches(
        self,
        mode: Literal["baseline", "delta"],
        snapshots: list[MdvmDeviceSnapshot],
    ) -> list[MdvmVulnerabilityBatch]:
        groups: list[list[MdvmDeviceSnapshot]] = []
        current: list[MdvmDeviceSnapshot] = []
        current_bytes = 0
        for snapshot in snapshots:
            size = len(snapshot.model_dump_json().encode())
            if size > self.config.batch_max_bytes:
                raise MdeUpstreamError("one MDVM device snapshot exceeds the batch byte limit")
            if current and (
                len(current) >= self.config.snapshots_per_batch
                or current_bytes + size > self.config.batch_max_bytes
            ):
                groups.append(current)
                current = []
                current_bytes = 0
            current.append(snapshot)
            current_bytes += size
        if current:
            groups.append(current)
        output: list[MdvmVulnerabilityBatch] = []
        for group in groups:
            content = json.dumps(
                {
                    "tenant": self.config.tenant_id,
                    "mode": mode,
                    "snapshots": [item.model_dump(mode="json") for item in group],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            output.append(
                MdvmVulnerabilityBatch(
                    batch_id=f"mdvm-sync-{hashlib.sha256(content.encode()).hexdigest()}",
                    collected_at=max(item.observed_at for item in group),
                    tenant_id=self.config.tenant_id,
                    mode=mode,
                    snapshots=group,
                )
            )
        return output

    async def sync_once(self, now: datetime | None = None) -> MdvmSyncOutcome:
        started = (now or datetime.now(UTC)).astimezone(UTC)
        owner = uuid.uuid4().hex
        lease_seconds = max(900.0, self.config.poll_seconds * 3)
        if not self.state.acquire(owner, started, lease_seconds):
            return MdvmSyncOutcome(acquired=False)
        try:
            metadata = self.state.snapshot()
            watermark = (
                _timestamp(metadata["watermark"], "stored MDVM watermark")
                if metadata.get("watermark")
                else None
            )
            last_baseline = (
                _timestamp(metadata["last_baseline_at"], "stored MDVM baseline")
                if metadata.get("last_baseline_at")
                else None
            )
            baseline_due = (
                watermark is None
                or last_baseline is None
                or started - last_baseline
                >= timedelta(hours=self.config.baseline_refresh_hours)
                or started - watermark >= timedelta(days=13)
            )
            mode: Literal["baseline", "delta"] = "baseline" if baseline_due else "delta"
            if mode == "baseline":
                raw = await self.client.baseline()
            else:
                assert watermark is not None
                since = watermark - timedelta(seconds=self.config.delta_overlap_seconds)
                raw = await self.client.delta(since)
            changes = [
                normalized
                for item in raw
                if (
                    normalized := normalize_mdvm_record(
                        item,
                        mode=mode,
                        fallback_time=started,
                    )
                )
                is not None
            ]
            if mode == "baseline":
                affected = self.state.replace_baseline(owner, changes)
            else:
                affected = self.state.apply_delta(owner, changes)
            mapper = MdeHostMapper.load(self.config.host_map_file)
            snapshots = self.state.device_snapshots(
                affected,
                tenant_id=self.config.tenant_id,
                mode=mode,
                mapper=mapper,
                findings_per_snapshot=self.config.findings_per_snapshot,
            )
            batches = self._batches(mode, snapshots)
            for batch in batches:
                response = await self.analyzer.ingest(
                    "/ingest/mdvm-vulnerability-batch",
                    batch,
                )
                if response.extensions.get("kcatta_derived_status") != "complete":
                    raise AnalyzerUpstreamError(
                        f"analyzer did not completely derive MDVM batch {batch.batch_id}"
                    )
            self.state.success(owner, started, mode=mode, changes=len(changes))
            active = self.state.snapshot()
            metrics_mod.inc("kcatta_mdvm_sync_success_total")
            metrics_mod.inc("kcatta_mdvm_changes_total", float(len(changes)))
            metrics_mod.set_gauge(
                "kcatta_mdvm_active_findings",
                float(active.get("active_finding_count") or 0),
            )
            metrics_mod.set_gauge("kcatta_mdvm_last_success_timestamp", started.timestamp())
            return MdvmSyncOutcome(
                acquired=True,
                mode=mode,
                changes=len(changes),
                devices=len(affected),
                findings=sum(len(item.vulnerabilities) for item in snapshots),
                batches=len(batches),
            )
        except Exception as exc:
            self.state.failure(owner, f"{type(exc).__name__}: {exc}")
            metrics_mod.inc("kcatta_mdvm_sync_failures_total")
            raise


class MdvmSyncWorker:
    def __init__(self, config: MdvmConfig, analyzer: Any) -> None:
        self.config = config
        self.analyzer = analyzer
        self._state: MdvmSyncState | None = (
            MdvmSyncState(
                config.state_path,
                max_findings=config.state_max_findings,
                max_bytes=config.state_max_bytes,
            )
            if config.enabled
            else None
        )
        self._client: MdvmClient | None = None
        self._engine: MdvmSyncEngine | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self._standby = False

    @property
    def healthy(self) -> bool:
        return not self.config.enabled or (self._task is not None and not self._task.done())

    async def start(self) -> None:
        if not self.config.enabled or self._task is not None:
            return
        if self._state is None:
            self._state = MdvmSyncState(
                self.config.state_path,
                max_findings=self.config.state_max_findings,
                max_bytes=self.config.state_max_bytes,
            )
        self._client = MdvmClient(self.config)
        self._engine = MdvmSyncEngine(self.config, self._client, self.analyzer, self._state)
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="form-mdvm-sync-worker")

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._client is not None:
            await self._client.close()
            self._client = None
        if self._state is not None:
            self._state.close()
            self._state = None

    async def _run(self) -> None:
        assert self._engine is not None
        while not self._stopping:
            try:
                outcome = await self._engine.sync_once()
                self._standby = not outcome.acquired
                if outcome.acquired:
                    logger.info(
                        "MDVM %s accepted %d change(s), %d device(s), %d finding(s)",
                        outcome.mode,
                        outcome.changes,
                        outcome.devices,
                        outcome.findings,
                    )
            except Exception as exc:  # noqa: BLE001 - bounded poll retries transient faults
                self._standby = False
                logger.warning("MDVM read-only synchronization failed: %s", exc)
            await asyncio.sleep(self.config.poll_seconds)

    def readiness(self) -> dict[str, Any]:
        if not self.config.enabled:
            return {"mdvm": "disabled", "mdvm_enabled": False}
        snapshot = self._state.snapshot() if self._state is not None else {}
        if snapshot.get("last_error"):
            status = "degraded"
        elif self._standby:
            status = "standby"
        elif snapshot.get("last_success_at"):
            status = "ready"
        else:
            status = "starting"
        return {
            "mdvm": status,
            "mdvm_enabled": True,
            "mdvm_watermark": snapshot.get("watermark"),
            "mdvm_last_baseline_at": snapshot.get("last_baseline_at"),
            "mdvm_last_attempt_at": snapshot.get("last_attempt_at"),
            "mdvm_last_success_at": snapshot.get("last_success_at"),
            "mdvm_last_error": snapshot.get("last_error"),
            "mdvm_affected_device_count": snapshot.get("active_device_count", 0),
            "mdvm_active_finding_count": snapshot.get("active_finding_count", 0),
            "mdvm_last_change_count": snapshot.get("last_change_count", 0),
        }
