"""Read-only Microsoft Defender for Endpoint cloud synchronization.

The connector owns its Graph credential and durable watermark. It never exposes
the credential to Agent/Admin requests and never calls a Defender response API.
"""

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
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from analyzer.schemas import MdeAlert, MdeEvidence, MdeIncident, MdeSecurityBatch, Severity

from . import metrics as metrics_mod
from .analyzer_client import AnalyzerUpstreamError

logger = logging.getLogger("kcatta_form.mde")

GRAPH_ROOT = "https://graph.microsoft.com/v1.0/security"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_SECRET_BYTES = 16 * 1024
MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024
MAX_GRAPH_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE = 256
MAX_RELATIONSHIPS = 256
_SAFE_DIRECTORY_ID = re.compile(r"^[A-Za-z0-9.-]{1,256}$")


class MdeConfigurationError(RuntimeError):
    """The operator enabled MDE without a safe, complete configuration."""


class MdeUpstreamError(RuntimeError):
    """Microsoft Graph was unavailable or returned an invalid bounded response."""


def _bool_env(name: str, default: bool) -> bool:
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
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise MdeConfigurationError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise MdeConfigurationError(f"{name} must be a positive integer")
    return value


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise MdeConfigurationError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise MdeConfigurationError(f"{name} must be a positive number")
    return value


@dataclass(frozen=True)
class MdeConfig:
    enabled: bool
    tenant_id: str = ""
    client_id: str = ""
    client_secret_file: Path | None = None
    host_map_file: Path | None = None
    state_path: Path = Path("data/mde-sync.db")
    poll_seconds: float = 300.0
    initial_lookback_hours: float = 48.0
    overlap_seconds: float = 300.0
    timeout_seconds: float = 30.0
    page_size: int = 100
    max_pages: int = 200
    max_items: int = 20_000
    chunk_size: int = 128
    max_attempts: int = 4

    @classmethod
    def from_env(cls, data_dir: Path) -> MdeConfig:
        enabled = _bool_env("FORM_MDE_ENABLED", False)
        if not enabled:
            # A disabled optional integration must not make the control plane
            # unbootable because of stale, otherwise-unused tuning variables.
            return cls(enabled=False, state_path=data_dir / "mde-sync.db")
        secret_raw = os.getenv("FORM_MDE_CLIENT_SECRET_FILE", "").strip()
        map_raw = os.getenv("FORM_MDE_HOST_MAP_FILE", "").strip()
        state_raw = os.getenv("FORM_MDE_STATE_PATH", "").strip()
        config = cls(
            enabled=enabled,
            tenant_id=os.getenv("FORM_MDE_TENANT_ID", "").strip(),
            client_id=os.getenv("FORM_MDE_CLIENT_ID", "").strip(),
            client_secret_file=Path(secret_raw) if secret_raw else None,
            host_map_file=Path(map_raw) if map_raw else None,
            state_path=Path(state_raw) if state_raw else data_dir / "mde-sync.db",
            poll_seconds=_positive_float("FORM_MDE_POLL_SECONDS", 300.0),
            initial_lookback_hours=_positive_float("FORM_MDE_INITIAL_LOOKBACK_HOURS", 48.0),
            overlap_seconds=_positive_float("FORM_MDE_OVERLAP_SECONDS", 300.0),
            timeout_seconds=_positive_float("FORM_MDE_TIMEOUT_SECONDS", 30.0),
            page_size=_positive_int("FORM_MDE_PAGE_SIZE", 100),
            max_pages=_positive_int("FORM_MDE_MAX_PAGES", 200),
            max_items=_positive_int("FORM_MDE_MAX_ITEMS", 20_000),
            chunk_size=_positive_int("FORM_MDE_CHUNK_SIZE", 128),
            max_attempts=_positive_int("FORM_MDE_MAX_ATTEMPTS", 4),
        )
        if config.page_size > 100:
            raise MdeConfigurationError("FORM_MDE_PAGE_SIZE cannot exceed 100")
        if config.chunk_size > 200:
            raise MdeConfigurationError("FORM_MDE_CHUNK_SIZE cannot exceed 200")
        if not config.tenant_id or not _SAFE_DIRECTORY_ID.fullmatch(config.tenant_id):
            raise MdeConfigurationError("FORM_MDE_TENANT_ID is missing or invalid")
        if not config.client_id or not _SAFE_DIRECTORY_ID.fullmatch(config.client_id):
            raise MdeConfigurationError("FORM_MDE_CLIENT_ID is missing or invalid")
        if config.client_secret_file is None:
            raise MdeConfigurationError(
                "FORM_MDE_CLIENT_SECRET_FILE is required when FORM_MDE_ENABLED=true"
            )
        return config


def _read_secret(path: Path) -> str:
    try:
        size = path.stat().st_size
        if not path.is_file() or size <= 0 or size > MAX_SECRET_BYTES:
            raise MdeConfigurationError("MDE client secret file has an invalid size")
        secret = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MdeConfigurationError("MDE client secret file cannot be read") from exc
    if not secret or len(secret.encode("utf-8")) > MAX_SECRET_BYTES:
        raise MdeConfigurationError("MDE client secret file is empty or oversized")
    return secret


def _retry_after(response: httpx.Response) -> float:
    value = response.headers.get("retry-after", "").strip()
    try:
        return min(60.0, max(0.0, float(value)))
    except ValueError:
        return 1.0


def _validate_graph_url(url: str, resource: Literal["alerts_v2", "incidents"]) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "graph.microsoft.com"
        or parsed.path != f"/v1.0/security/{resource}"
        or parsed.fragment
    ):
        raise MdeUpstreamError("Microsoft Graph returned an invalid pagination URL")


class MdeGraphClient:
    """Bounded Graph client with token caching, pagination and throttling retries."""

    def __init__(
        self,
        config: MdeConfig,
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
                    "scope": GRAPH_SCOPE,
                    "grant_type": "client_credentials",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.RequestError as exc:
            raise MdeUpstreamError("Microsoft identity platform is unavailable") from exc
        if response.status_code != 200:
            raise MdeUpstreamError(
                f"Microsoft identity platform rejected the credential ({response.status_code})"
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

    async def _get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None,
        resource: Literal["alerts_v2", "incidents"],
    ) -> dict[str, Any]:
        _validate_graph_url(url, resource)
        for attempt in range(self.config.max_attempts):
            token = await self._token()
            try:
                response = await self._client.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                        "Prefer": "include-unknown-enum-members",
                    },
                )
            except httpx.RequestError as exc:
                if attempt + 1 == self.config.max_attempts:
                    raise MdeUpstreamError("Microsoft Graph is unavailable") from exc
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
                raise MdeUpstreamError(
                    f"Microsoft Graph {resource} request failed ({response.status_code})"
                )
            if len(response.content) > MAX_GRAPH_RESPONSE_BYTES:
                raise MdeUpstreamError("Microsoft Graph returned an oversized response")
            try:
                payload = response.json()
            except ValueError as exc:
                raise MdeUpstreamError("Microsoft Graph returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise MdeUpstreamError("Microsoft Graph returned an invalid response object")
            return payload
        raise MdeUpstreamError(f"Microsoft Graph {resource} retry budget exhausted")

    async def fetch(
        self,
        resource: Literal["alerts_v2", "incidents"],
        since: datetime,
    ) -> list[dict[str, Any]]:
        url = f"{GRAPH_ROOT}/{resource}"
        instant = since.astimezone(UTC).isoformat().replace("+00:00", "Z")
        params = {
            "$filter": f"lastUpdateDateTime ge {instant}",
            "$top": str(self.config.page_size),
        }
        if resource == "incidents":
            params["$expand"] = "alerts"
        records: list[dict[str, Any]] = []
        for _page in range(self.config.max_pages):
            payload = await self._get(url, params=params, resource=resource)
            values = payload.get("value")
            if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                raise MdeUpstreamError("Microsoft Graph response has an invalid value list")
            if len(records) + len(values) > self.config.max_items:
                raise MdeUpstreamError("Microsoft Graph result exceeds FORM_MDE_MAX_ITEMS")
            records.extend(values)
            next_link = payload.get("@odata.nextLink")
            if next_link is None:
                return records
            if not isinstance(next_link, str):
                raise MdeUpstreamError("Microsoft Graph returned an invalid nextLink")
            _validate_graph_url(next_link, resource)
            url = next_link
            params = None
        raise MdeUpstreamError("Microsoft Graph result exceeds FORM_MDE_MAX_PAGES")


def _text(value: Any, field: str, *, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise MdeUpstreamError(f"Microsoft Graph record is missing {field}")
    return value.strip()[:4096]


def _optional_text(value: Any) -> str | None:
    return value.strip()[:4096] if isinstance(value, str) and value.strip() else None


def _timestamp(value: Any, field: str) -> datetime:
    raw = _text(value, field)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MdeUpstreamError(f"Microsoft Graph record has invalid {field}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _optional_timestamp(value: Any, field: str) -> datetime | None:
    return _timestamp(value, field) if value is not None else None


def _string_list(value: Any, *, limit: int = MAX_RELATIONSHIPS) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip()[:4096] for item in value if isinstance(item, str) and item.strip()][
        :limit
    ]


def _https_url(value: Any) -> str | None:
    text = _optional_text(value)
    if text is None:
        return None
    parsed = urlsplit(text)
    return text if parsed.scheme == "https" and parsed.hostname else None


class MdeHostMapper:
    """Explicit cloud-device to Kcatta host mapping with isolated fallbacks."""

    def __init__(self, entries: Mapping[str, str] | None = None) -> None:
        self.entries = {
            key.strip().lower(): value.strip() for key, value in (entries or {}).items()
        }

    @classmethod
    def load(cls, path: Path | None) -> MdeHostMapper:
        if path is None:
            return cls()
        try:
            if path.stat().st_size > 1024 * 1024:
                raise MdeConfigurationError("MDE host map file exceeds 1 MiB")
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MdeConfigurationError("MDE host map file cannot be read") from exc
        if not isinstance(payload, dict) or len(payload) > 20_000:
            raise MdeConfigurationError("MDE host map must be a bounded JSON object")
        entries: dict[str, str] = {}
        for key, value in payload.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key.strip()
                or not value.strip()
                or len(key) > 4096
                or len(value) > 256
            ):
                raise MdeConfigurationError("MDE host map contains an invalid entry")
            entries[key] = value
        return cls(entries)

    @staticmethod
    def _fallback(prefix: str, value: str) -> str:
        candidate = f"{prefix}:{value.strip().lower()}"
        if len(candidate) <= 256:
            return candidate
        return f"{prefix}:sha256:{hashlib.sha256(value.encode()).hexdigest()}"

    def resolve(
        self,
        *,
        mde_device_id: str | None,
        azure_ad_device_id: str | None,
        dns_name: str | None,
        hostname: str | None,
    ) -> str | None:
        candidates = (
            ("mde", mde_device_id),
            ("aad", azure_ad_device_id),
            ("dns", dns_name),
            ("host", hostname),
        )
        for prefix, value in candidates:
            if value and (mapped := self.entries.get(f"{prefix}:{value}".lower())):
                return mapped
        if mde_device_id:
            return self._fallback("mde", mde_device_id)
        if azure_ad_device_id:
            return self._fallback("aad", azure_ad_device_id)
        if dns_name:
            return self._fallback("mde-dns", dns_name)
        return None


def _evidence_type(raw: Mapping[str, Any]) -> str:
    value = _optional_text(raw.get("@odata.type")) or "unknown"
    return value.rsplit(".", 1)[-1].lstrip("#")


def _normalize_evidence(raw: Mapping[str, Any], mapper: MdeHostMapper) -> MdeEvidence:
    mde_id = _optional_text(raw.get("mdeDeviceId"))
    aad_id = _optional_text(raw.get("azureAdDeviceId"))
    dns_name = _optional_text(raw.get("deviceDnsName"))
    hostname = _optional_text(raw.get("hostName"))
    ips = _string_list(raw.get("ipInterfaces"))
    if ip := _optional_text(raw.get("ipAddress")):
        ips = list(dict.fromkeys([ip, *ips]))[:MAX_RELATIONSHIPS]
    summary = next(
        (
            value
            for key in (
                "displayName",
                "fileName",
                "accountName",
                "userPrincipalName",
                "processCommandLine",
                "url",
            )
            if (value := _optional_text(raw.get(key)))
        ),
        None,
    )
    return MdeEvidence(
        evidence_type=_evidence_type(raw),
        created_at=_optional_timestamp(raw.get("createdDateTime"), "evidence.createdDateTime"),
        verdict=_optional_text(raw.get("verdict")),
        remediation_status=_optional_text(raw.get("remediationStatus")),
        roles=_string_list(raw.get("roles")),
        summary=summary,
        mde_device_id=mde_id,
        azure_ad_device_id=aad_id,
        device_dns_name=dns_name,
        hostname=hostname,
        os_platform=_optional_text(raw.get("osPlatform")),
        os_build=_optional_text(raw.get("osBuild")),
        ip_addresses=ips,
        canonical_host_id=mapper.resolve(
            mde_device_id=mde_id,
            azure_ad_device_id=aad_id,
            dns_name=dns_name,
            hostname=hostname,
        ),
    )


def _severity(value: Any) -> Severity:
    return {
        "informational": Severity.INFO,
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }.get(str(value).strip().lower(), Severity.INFO)


def normalize_alert(raw: Mapping[str, Any], mapper: MdeHostMapper) -> MdeAlert:
    evidence_raw = raw.get("evidence")
    evidence_rows = evidence_raw if isinstance(evidence_raw, list) else []
    evidence = [
        _normalize_evidence(item, mapper)
        for item in evidence_rows[:MAX_EVIDENCE]
        if isinstance(item, dict)
    ]
    assets = list(
        dict.fromkeys(item.canonical_host_id for item in evidence if item.canonical_host_id)
    )[:MAX_RELATIONSHIPS]
    updated = _timestamp(raw.get("lastUpdateDateTime"), "alert.lastUpdateDateTime")
    return MdeAlert(
        alert_id=_text(raw.get("id"), "alert.id"),
        provider_alert_id=_optional_text(raw.get("providerAlertId")),
        incident_id=_optional_text(raw.get("incidentId")),
        title=_text(raw.get("title"), "alert.title", default="Untitled Microsoft alert"),
        description=_optional_text(raw.get("description")) or "",
        severity=_severity(raw.get("severity")),
        provider_status=_text(raw.get("status"), "alert.status", default="unknown"),
        classification=_optional_text(raw.get("classification")),
        determination=_optional_text(raw.get("determination")),
        service_source=_optional_text(raw.get("serviceSource")),
        product_name=_optional_text(raw.get("productName")),
        detection_source=_optional_text(raw.get("detectionSource")),
        created_at=_optional_timestamp(raw.get("createdDateTime"), "alert.createdDateTime")
        or updated,
        first_activity_at=_optional_timestamp(
            raw.get("firstActivityDateTime"), "alert.firstActivityDateTime"
        ),
        last_activity_at=_optional_timestamp(
            raw.get("lastActivityDateTime"), "alert.lastActivityDateTime"
        ),
        last_updated_at=updated,
        resolved_at=_optional_timestamp(raw.get("resolvedDateTime"), "alert.resolvedDateTime"),
        portal_url=_https_url(raw.get("alertWebUrl")),
        mitre_techniques=_string_list(raw.get("mitreTechniques")),
        related_asset_ids=assets,
        evidence=evidence,
        evidence_truncated=len(evidence_rows) > MAX_EVIDENCE,
    )


def normalize_incident(
    raw: Mapping[str, Any],
    alerts_by_id: Mapping[str, MdeAlert],
) -> MdeIncident:
    embedded = raw.get("alerts")
    embedded_rows = embedded if isinstance(embedded, list) else []
    ids = [
        item_id
        for item in embedded_rows
        if isinstance(item, dict) and (item_id := _optional_text(item.get("id")))
    ]
    incident_id = _text(raw.get("id"), "incident.id")
    if not ids:
        ids = [item.alert_id for item in alerts_by_id.values() if item.incident_id == incident_id]
    ids = list(dict.fromkeys(ids))
    assets: list[str] = []
    for alert_id in ids:
        if alert := alerts_by_id.get(alert_id):
            assets.extend(alert.related_asset_ids)
    updated = _timestamp(raw.get("lastUpdateDateTime"), "incident.lastUpdateDateTime")
    return MdeIncident(
        incident_id=incident_id,
        display_name=_text(
            raw.get("displayName"), "incident.displayName", default="Untitled Microsoft incident"
        ),
        description=_optional_text(raw.get("description")) or "",
        severity=_severity(raw.get("severity")),
        provider_status=_text(raw.get("status"), "incident.status", default="unknown"),
        classification=_optional_text(raw.get("classification")),
        determination=_optional_text(raw.get("determination")),
        created_at=_optional_timestamp(raw.get("createdDateTime"), "incident.createdDateTime")
        or updated,
        last_updated_at=updated,
        resolved_at=_optional_timestamp(
            raw.get("resolvedDateTime"), "incident.resolvedDateTime"
        ),
        portal_url=_https_url(raw.get("incidentWebUrl")),
        alert_ids=ids[:MAX_RELATIONSHIPS],
        related_asset_ids=list(dict.fromkeys(assets))[:MAX_RELATIONSHIPS],
        relationships_truncated=len(ids) > MAX_RELATIONSHIPS
        or len(set(assets)) > MAX_RELATIONSHIPS,
    )


class MdeSyncState:
    """SQLite watermark and cross-process lease; one successful poll commits both."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mde_sync_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                watermark TEXT,
                lease_owner TEXT,
                lease_until REAL,
                last_attempt_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                alert_count INTEGER NOT NULL DEFAULT 0,
                incident_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._conn.execute("INSERT OR IGNORE INTO mde_sync_state (singleton) VALUES (1)")
        self._conn.commit()

    def acquire(self, owner: str, now: datetime, lease_seconds: float) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            changed = self._conn.execute(
                """
                UPDATE mde_sync_state
                SET lease_owner = ?, lease_until = ?, last_attempt_at = ?
                WHERE singleton = 1
                  AND (lease_owner IS NULL OR COALESCE(lease_until, 0) <= ? OR lease_owner = ?)
                """,
                (owner, now.timestamp() + lease_seconds, now.isoformat(), now.timestamp(), owner),
            ).rowcount
            self._conn.commit()
        return changed == 1

    def watermark(self) -> datetime | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT watermark FROM mde_sync_state WHERE singleton = 1"
            ).fetchone()
        value = row["watermark"] if row else None
        return _timestamp(value, "stored watermark") if value else None

    def success(
        self,
        owner: str,
        watermark: datetime,
        *,
        alerts: int,
        incidents: int,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            changed = self._conn.execute(
                """
                UPDATE mde_sync_state
                SET watermark = ?, last_success_at = ?, last_error = NULL,
                    alert_count = ?, incident_count = ?, lease_owner = NULL, lease_until = NULL
                WHERE singleton = 1 AND lease_owner = ?
                """,
                (watermark.isoformat(), now, alerts, incidents, owner),
            ).rowcount
            self._conn.commit()
        if changed != 1:
            raise RuntimeError("MDE synchronization lease was lost before commit")

    def failure(self, owner: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE mde_sync_state
                SET last_error = ?, lease_owner = NULL, lease_until = NULL
                WHERE singleton = 1 AND lease_owner = ?
                """,
                (error[:2048], owner),
            )
            self._conn.commit()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM mde_sync_state WHERE singleton = 1").fetchone()
        return dict(row) if row else {}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


@dataclass(frozen=True)
class MdeSyncOutcome:
    acquired: bool
    alerts: int = 0
    incidents: int = 0
    batches: int = 0


class MdeSyncEngine:
    def __init__(
        self,
        config: MdeConfig,
        graph: MdeGraphClient,
        analyzer: Any,
        state: MdeSyncState,
    ) -> None:
        self.config = config
        self.graph = graph
        self.analyzer = analyzer
        self.state = state

    @staticmethod
    def _dedupe_alert_rows(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        by_id: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            item_id = _optional_text(row.get("id"))
            if item_id:
                current = by_id.get(item_id)
                row_updated = row.get("lastUpdateDateTime")
                current_updated = current.get("lastUpdateDateTime") if current else None
                row_rank = (
                    isinstance(row_updated, str),
                    row_updated if isinstance(row_updated, str) else "",
                    len(row),
                )
                current_rank = (
                    isinstance(current_updated, str),
                    current_updated if isinstance(current_updated, str) else "",
                    len(current) if current else 0,
                )
                if current is None or row_rank > current_rank:
                    by_id[item_id] = row
        return list(by_id.values())

    def _batches(
        self,
        since: datetime,
        alerts: list[MdeAlert],
        incidents: list[MdeIncident],
    ) -> list[MdeSecurityBatch]:
        items: list[tuple[str, MdeAlert | MdeIncident]] = [
            *(('alert', item) for item in alerts),
            *(('incident', item) for item in incidents),
        ]
        output: list[MdeSecurityBatch] = []
        for index in range(0, len(items), self.config.chunk_size):
            part = items[index : index + self.config.chunk_size]
            part_alerts = [item for kind, item in part if kind == "alert"]
            part_incidents = [item for kind, item in part if kind == "incident"]
            updated = [item.last_updated_at for _kind, item in part]
            content = json.dumps(
                {
                    "tenant": self.config.tenant_id,
                    "since": since.isoformat(),
                    "alerts": [item.model_dump(mode="json") for item in part_alerts],
                    "incidents": [item.model_dump(mode="json") for item in part_incidents],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            digest = hashlib.sha256(content.encode()).hexdigest()
            output.append(
                MdeSecurityBatch(
                    batch_id=f"mde-sync-{digest}",
                    collected_at=max(updated),
                    tenant_id=self.config.tenant_id,
                    query_started_at=since,
                    alerts=part_alerts,
                    incidents=part_incidents,
                )
            )
        return output

    async def sync_once(self, now: datetime | None = None) -> MdeSyncOutcome:
        started = (now or datetime.now(UTC)).astimezone(UTC)
        owner = uuid.uuid4().hex
        lease_seconds = max(300.0, self.config.poll_seconds * 3)
        if not self.state.acquire(owner, started, lease_seconds):
            return MdeSyncOutcome(acquired=False)
        try:
            watermark = self.state.watermark()
            if watermark is None:
                since = started - timedelta(hours=self.config.initial_lookback_hours)
            else:
                since = watermark - timedelta(seconds=self.config.overlap_seconds)
            mapper = MdeHostMapper.load(self.config.host_map_file)
            raw_alerts = await self.graph.fetch("alerts_v2", since)
            raw_incidents = await self.graph.fetch("incidents", since)
            embedded_alerts = [
                alert
                for incident in raw_incidents
                for alert in (
                    incident.get("alerts")
                    if isinstance(incident.get("alerts"), list)
                    else []
                )
                if isinstance(alert, dict)
            ]
            alert_rows = self._dedupe_alert_rows([*raw_alerts, *embedded_alerts])
            if len(alert_rows) + len(raw_incidents) > self.config.max_items:
                raise MdeUpstreamError("combined Microsoft Graph result exceeds FORM_MDE_MAX_ITEMS")
            alerts = [normalize_alert(row, mapper) for row in alert_rows]
            alerts.sort(key=lambda item: (item.last_updated_at, item.alert_id))
            by_id = {item.alert_id: item for item in alerts}
            incidents = [normalize_incident(row, by_id) for row in raw_incidents]
            incidents.sort(key=lambda item: (item.last_updated_at, item.incident_id))
            batches = self._batches(since, alerts, incidents)
            for batch in batches:
                response = await self.analyzer.ingest("/ingest/mde-security-batch", batch)
                status = response.extensions.get("kcatta_derived_status")
                if status != "complete":
                    raise AnalyzerUpstreamError(
                        f"analyzer did not completely derive MDE batch {batch.batch_id}"
                    )
            self.state.success(owner, started, alerts=len(alerts), incidents=len(incidents))
            metrics_mod.inc("kcatta_mde_sync_success_total")
            metrics_mod.inc("kcatta_mde_alerts_total", float(len(alerts)))
            metrics_mod.inc("kcatta_mde_incidents_total", float(len(incidents)))
            metrics_mod.set_gauge("kcatta_mde_last_success_timestamp", started.timestamp())
            return MdeSyncOutcome(
                acquired=True,
                alerts=len(alerts),
                incidents=len(incidents),
                batches=len(batches),
            )
        except Exception as exc:
            reason = f"{type(exc).__name__}: {exc}"
            self.state.failure(owner, reason)
            metrics_mod.inc("kcatta_mde_sync_failures_total")
            raise


class MdeSyncWorker:
    """Lifespan-owned polling worker; disabled mode is a first-class healthy state."""

    def __init__(self, config: MdeConfig, analyzer: Any) -> None:
        self.config = config
        self.analyzer = analyzer
        self._state: MdeSyncState | None = (
            MdeSyncState(config.state_path) if config.enabled else None
        )
        self._graph: MdeGraphClient | None = None
        self._engine: MdeSyncEngine | None = None
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
            self._state = MdeSyncState(self.config.state_path)
        assert self._state is not None
        self._graph = MdeGraphClient(self.config)
        self._engine = MdeSyncEngine(self.config, self._graph, self.analyzer, self._state)
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="form-mde-sync-worker")

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._graph is not None:
            await self._graph.close()
            self._graph = None
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
                        "MDE sync accepted %d alert(s), %d incident(s) in %d batch(es)",
                        outcome.alerts,
                        outcome.incidents,
                        outcome.batches,
                    )
            except Exception as exc:  # noqa: BLE001 - retry on the next bounded poll
                self._standby = False
                logger.warning("MDE read-only synchronization failed: %s", exc)
            await asyncio.sleep(self.config.poll_seconds)

    def readiness(self) -> dict[str, Any]:
        if not self.config.enabled:
            return {"mde": "disabled", "mde_enabled": False}
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
            "mde": status,
            "mde_enabled": True,
            "mde_watermark": snapshot.get("watermark"),
            "mde_last_attempt_at": snapshot.get("last_attempt_at"),
            "mde_last_success_at": snapshot.get("last_success_at"),
            "mde_last_error": snapshot.get("last_error"),
            "mde_alert_count": snapshot.get("alert_count", 0),
            "mde_incident_count": snapshot.get("incident_count", 0),
        }
