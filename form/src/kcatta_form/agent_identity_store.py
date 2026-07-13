"""Transactional Form registry for server-owned agent identities.

The registry stores stable target/host/scope bindings and public certificate
metadata only.  Leaf private keys are intentionally outside this module and
must never be written to this database.  ``BEGIN IMMEDIATE`` plus SQLite's WAL
locking makes generation transitions safe across threads and Form processes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .schemas.agent_identity import (
    AgentCertificate,
    AgentCertificateState,
    AgentIdentity,
    AgentIdentityState,
    AgentScope,
    VerifiedAgentIdentity,
)

DEFAULT_DB_FILENAME = "form-agent-identities.db"
DEFAULT_ROTATION_OVERLAP = timedelta(minutes=10)
MAX_ROTATION_OVERLAP = timedelta(hours=1)

_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_LOCKS_GUARD = threading.Lock()
_DB_LOCKS: dict[Path, threading.RLock] = {}


class AgentIdentityStoreError(RuntimeError):
    """Base error for durable agent identity operations."""


class AgentIdentityNotFoundError(AgentIdentityStoreError):
    """The requested stable agent identity does not exist."""


class AgentCertificateNotFoundError(AgentIdentityStoreError):
    """The requested certificate generation does not exist."""


class AgentIdentityConflictError(AgentIdentityStoreError):
    """A stable binding or certificate lifecycle precondition conflicts."""


def _shared_lock(path: Path) -> threading.RLock:
    key = path.absolute()
    with _LOCKS_GUARD:
        return _DB_LOCKS.setdefault(key, threading.RLock())


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _micros(value: datetime | None) -> int | None:
    return None if value is None else int(_utc(value).timestamp() * 1_000_000)


def _from_micros(value: int | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _required_text(value: str, field: str, *, max_length: int = 256) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > max_length:
        raise ValueError(f"{field} must not exceed {max_length} characters")
    return normalized


def _normalize_agent_id(value: str) -> str:
    normalized = value.strip()
    if not _AGENT_ID_PATTERN.fullmatch(normalized):
        raise ValueError("agent_id must be a URI-safe identifier of at most 128 characters")
    return normalized


def _normalize_scopes(scopes: Iterable[AgentScope | str]) -> tuple[AgentScope, ...]:
    try:
        normalized = {AgentScope(scope) for scope in scopes}
    except ValueError as exc:
        raise ValueError(f"unsupported agent scope: {exc}") from exc
    if not normalized:
        raise ValueError("at least one agent scope is required")
    return tuple(sorted(normalized, key=lambda scope: scope.value))


def _normalize_hex(value: str, field: str, *, length: int | None = None) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if not normalized or not _HEX_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field} must be hexadecimal")
    if length is not None and len(normalized) != length:
        raise ValueError(f"{field} must contain exactly {length} hexadecimal characters")
    return normalized


def _normalize_serial(value: str) -> str:
    normalized = _normalize_hex(value, "serial_number")
    # The TLS protocol reports Python's canonical ``format(serial, 'x')`` form.
    return normalized.lstrip("0") or "0"


def _idempotency_hash(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        raise ValueError("idempotency_key must not be empty")
    if len(normalized) > 1024:
        raise ValueError("idempotency_key must not exceed 1024 characters")
    # The raw job id/key never enters SQLite.
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class AgentIdentityRepository:
    """SQLite identity heads and immutable certificate generations."""

    def __init__(self, data_dir: Path, *, db_filename: str = DEFAULT_DB_FILENAME) -> None:
        filename = _required_text(db_filename, "db_filename", max_length=255)
        if Path(filename).name != filename:
            raise ValueError("db_filename must be a plain filename")
        self.db_path = Path(data_dir) / filename
        self._lock = _shared_lock(self.db_path)
        self._closed = False
        self._ensure_schema()

    def _connect(
        self,
        *,
        write: bool = False,
        configure_journal: bool = False,
    ) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("agent identity repository is closed")
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(
            self.db_path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        if configure_journal:
            connection.execute("PRAGMA journal_mode=WAL")
        if write:
            connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _ensure_schema(self) -> None:
        with self._lock:
            connection = self._connect(write=True, configure_journal=True)
            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS agent_identities (
                        agent_id TEXT PRIMARY KEY,
                        target_id TEXT NOT NULL UNIQUE,
                        canonical_host_id TEXT NOT NULL UNIQUE,
                        scopes_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
                        generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
                        created_at_us INTEGER NOT NULL,
                        updated_at_us INTEGER NOT NULL,
                        revoked_at_us INTEGER,
                        revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0)
                    );
                    CREATE INDEX IF NOT EXISTS idx_agent_identities_updated
                        ON agent_identities(updated_at_us DESC, agent_id);

                    CREATE TABLE IF NOT EXISTS agent_certificates (
                        agent_id TEXT NOT NULL
                            REFERENCES agent_identities(agent_id) ON DELETE CASCADE,
                        generation INTEGER NOT NULL CHECK (generation >= 1),
                        serial_number TEXT NOT NULL UNIQUE,
                        cert_sha256 TEXT NOT NULL UNIQUE,
                        spki_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL
                            CHECK (state IN ('staged', 'active', 'retired', 'revoked')),
                        certificate_pem TEXT NOT NULL,
                        idempotency_key_sha256 TEXT,
                        not_before_us INTEGER NOT NULL,
                        not_after_us INTEGER NOT NULL,
                        created_at_us INTEGER NOT NULL,
                        activated_at_us INTEGER,
                        retired_at_us INTEGER,
                        overlap_until_us INTEGER,
                        revoked_at_us INTEGER,
                        PRIMARY KEY (agent_id, generation),
                        CHECK (not_after_us > not_before_us)
                    );
                    """
                )
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(agent_certificates)")
                }
                if "idempotency_key_sha256" not in columns:
                    try:
                        connection.execute(
                            "ALTER TABLE agent_certificates ADD COLUMN idempotency_key_sha256 TEXT"
                        )
                    except sqlite3.OperationalError:
                        # Another Form process may have completed the same
                        # additive migration while this connection waited for
                        # SQLite's schema lock.  Ignore only that exact outcome.
                        refreshed = {
                            row["name"]
                            for row in connection.execute("PRAGMA table_info(agent_certificates)")
                        }
                        if "idempotency_key_sha256" not in refreshed:
                            raise
                connection.executescript(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_certificate_staged
                        ON agent_certificates(agent_id) WHERE state = 'staged';
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_certificate_active
                        ON agent_certificates(agent_id) WHERE state = 'active';
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_certificate_idempotency_key
                        ON agent_certificates(agent_id, idempotency_key_sha256)
                        WHERE idempotency_key_sha256 IS NOT NULL;
                    CREATE INDEX IF NOT EXISTS idx_agent_certificate_state
                        ON agent_certificates(agent_id, state, generation DESC);
                    """
                )
            finally:
                connection.close()
            # ACL-only/non-POSIX filesystems may not implement chmod.  The
            # database still contains no private key or bearer secret.
            with suppress(OSError):
                os.chmod(self.db_path, 0o600)

    @contextmanager
    def _transaction(self):  # type: ignore[no-untyped-def]
        with self._lock:
            connection = self._connect(write=True)
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _read_connection(self) -> sqlite3.Connection:
        return self._connect()

    @staticmethod
    def _certificate_from_row(row: sqlite3.Row) -> AgentCertificate:
        return AgentCertificate(
            agent_id=row["agent_id"],
            generation=row["generation"],
            serial_number=row["serial_number"],
            cert_sha256=row["cert_sha256"],
            spki_sha256=row["spki_sha256"],
            state=row["state"],
            not_before=_from_micros(row["not_before_us"]),
            not_after=_from_micros(row["not_after_us"]),
            created_at=_from_micros(row["created_at_us"]),
            activated_at=_from_micros(row["activated_at_us"]),
            retired_at=_from_micros(row["retired_at_us"]),
            overlap_until=_from_micros(row["overlap_until_us"]),
            revoked_at=_from_micros(row["revoked_at_us"]),
        )

    def _identity_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AgentIdentity:
        certificate_rows = connection.execute(
            """
            SELECT * FROM agent_certificates
            WHERE agent_id = ? ORDER BY generation ASC
            """,
            (row["agent_id"],),
        ).fetchall()
        return AgentIdentity(
            agent_id=row["agent_id"],
            target_id=row["target_id"],
            canonical_host_id=row["canonical_host_id"],
            scopes=json.loads(row["scopes_json"]),
            state=row["state"],
            generation=row["generation"],
            created_at=_from_micros(row["created_at_us"]),
            updated_at=_from_micros(row["updated_at_us"]),
            revoked_at=_from_micros(row["revoked_at_us"]),
            certificates=[self._certificate_from_row(item) for item in certificate_rows],
        )

    @staticmethod
    def _identity_row(
        connection: sqlite3.Connection,
        agent_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM agent_identities WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            raise AgentIdentityNotFoundError(f"unknown agent identity: {agent_id}")
        return row

    @staticmethod
    def _certificate_row(
        connection: sqlite3.Connection,
        agent_id: str,
        generation: int,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM agent_certificates
            WHERE agent_id = ? AND generation = ?
            """,
            (agent_id, generation),
        ).fetchone()
        if row is None:
            raise AgentCertificateNotFoundError(
                f"unknown certificate generation: {agent_id}/{generation}"
            )
        return row

    def get_or_create(
        self,
        target_id: str,
        canonical_host_id: str,
        scopes: Iterable[AgentScope | str],
        *,
        agent_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[AgentIdentity, bool]:
        """Return a stable binding, creating it exactly once.

        Reusing a target with a different host or scope set is rejected rather
        than silently rebinding credentials.  The same applies when a canonical
        host is already owned by a different target.
        """

        target = _required_text(target_id, "target_id")
        host = _required_text(canonical_host_id, "canonical_host_id")
        canonical_scopes = _normalize_scopes(scopes)
        scopes_json = json.dumps(
            [scope.value for scope in canonical_scopes],
            separators=(",", ":"),
        )
        requested_agent_id = _normalize_agent_id(agent_id) if agent_id is not None else None
        timestamp = _utc(now or datetime.now(UTC))
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM agent_identities WHERE target_id = ?",
                (target,),
            ).fetchone()
            if row is not None:
                mismatches: list[str] = []
                if row["canonical_host_id"] != host:
                    mismatches.append("canonical_host_id")
                if row["scopes_json"] != scopes_json:
                    mismatches.append("scopes")
                if requested_agent_id is not None and row["agent_id"] != requested_agent_id:
                    mismatches.append("agent_id")
                if mismatches:
                    raise AgentIdentityConflictError(
                        f"target {target} is already bound with different " + ", ".join(mismatches)
                    )
                return self._identity_from_row(connection, row), False

            allocated_agent_id = requested_agent_id or f"agent-{uuid.uuid4().hex}"
            try:
                connection.execute(
                    """
                    INSERT INTO agent_identities (
                        agent_id, target_id, canonical_host_id, scopes_json, state,
                        generation, created_at_us, updated_at_us, revision
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?, 0)
                    """,
                    (
                        allocated_agent_id,
                        target,
                        host,
                        scopes_json,
                        _micros(timestamp),
                        _micros(timestamp),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AgentIdentityConflictError(
                    "agent_id, target_id, or canonical_host_id is already bound"
                ) from exc
            return self._identity_from_row(
                connection,
                self._identity_row(connection, allocated_agent_id),
            ), True

    def get(self, agent_id: str) -> AgentIdentity:
        normalized = _normalize_agent_id(agent_id)
        connection = self._read_connection()
        try:
            return self._identity_from_row(connection, self._identity_row(connection, normalized))
        finally:
            connection.close()

    def get_by_target(self, target_id: str) -> AgentIdentity:
        target = _required_text(target_id, "target_id")
        connection = self._read_connection()
        try:
            row = connection.execute(
                "SELECT * FROM agent_identities WHERE target_id = ?",
                (target,),
            ).fetchone()
            if row is None:
                raise AgentIdentityNotFoundError(f"unknown target identity: {target}")
            return self._identity_from_row(connection, row)
        finally:
            connection.close()

    def list(self, *, limit: int = 1000) -> list[AgentIdentity]:
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        connection = self._read_connection()
        try:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT * FROM agent_identities
                ORDER BY created_at_us ASC, agent_id ASC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            identities = [self._identity_from_row(connection, row) for row in rows]
            connection.commit()
            return identities
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_certificate(self, agent_id: str, generation: int) -> AgentCertificate:
        normalized = _normalize_agent_id(agent_id)
        if generation < 1:
            raise ValueError("generation must be positive")
        connection = self._read_connection()
        try:
            return self._certificate_from_row(
                self._certificate_row(connection, normalized, generation)
            )
        finally:
            connection.close()

    def list_certificates(self, agent_id: str) -> list[AgentCertificate]:
        return self.get(agent_id).certificates

    def get_by_idempotency_key(
        self,
        agent_id: str,
        idempotency_key: str,
    ) -> AgentCertificate | None:
        """Find the non-aborted generation reserved by a hashed deployment key."""

        normalized_agent_id = _normalize_agent_id(agent_id)
        key_hash = _idempotency_hash(idempotency_key)
        connection = self._read_connection()
        try:
            self._identity_row(connection, normalized_agent_id)
            row = connection.execute(
                """
                SELECT * FROM agent_certificates
                WHERE agent_id = ? AND idempotency_key_sha256 = ?
                """,
                (normalized_agent_id, key_hash),
            ).fetchone()
            return None if row is None else self._certificate_from_row(row)
        finally:
            connection.close()

    def stage_certificate(
        self,
        agent_id: str,
        *,
        generation: int,
        serial_number: str,
        cert_sha256: str,
        spki_sha256: str,
        certificate_pem: str,
        not_before: datetime,
        not_after: datetime,
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> tuple[AgentIdentity, bool]:
        """Persist the next generation, or replay its staged metadata.

        The boolean is true only when this call created the generation.  With
        an idempotency key, a concurrent/repeated call returns the same staged
        identity and ``False``; it must not reuse its newly generated private
        material because that material does not match the persisted leaf.
        """

        normalized_agent_id = _normalize_agent_id(agent_id)
        serial = _normalize_serial(serial_number)
        fingerprint = _normalize_hex(cert_sha256, "cert_sha256", length=64)
        public_key_fingerprint = _normalize_hex(spki_sha256, "spki_sha256", length=64)
        pem = _required_text(certificate_pem, "certificate_pem", max_length=64 * 1024)
        key_hash = _idempotency_hash(idempotency_key)
        start = _utc(not_before)
        end = _utc(not_after)
        timestamp = _utc(now or datetime.now(UTC))
        # Validate the complete metadata before opening a write transaction.
        AgentCertificate(
            agent_id=normalized_agent_id,
            generation=generation,
            serial_number=serial,
            cert_sha256=fingerprint,
            spki_sha256=public_key_fingerprint,
            state=AgentCertificateState.STAGED,
            not_before=start,
            not_after=end,
            created_at=timestamp,
        )
        with self._transaction() as connection:
            identity = self._identity_row(connection, normalized_agent_id)
            if identity["state"] != AgentIdentityState.ACTIVE.value:
                raise AgentIdentityConflictError(
                    "cannot stage a certificate for a revoked identity"
                )
            replay = None
            if key_hash is not None:
                replay = connection.execute(
                    """
                    SELECT * FROM agent_certificates
                    WHERE agent_id = ? AND idempotency_key_sha256 = ?
                    """,
                    (normalized_agent_id, key_hash),
                ).fetchone()
            if replay is not None:
                return self._identity_from_row(connection, identity), False
            staged = connection.execute(
                """
                SELECT * FROM agent_certificates
                WHERE agent_id = ? AND state = 'staged'
                """,
                (normalized_agent_id,),
            ).fetchone()
            if staged is not None:
                raise AgentIdentityConflictError(
                    f"certificate generation {staged['generation']} is already staged"
                )
            expected_generation = int(identity["generation"]) + 1
            if generation != expected_generation:
                raise AgentIdentityConflictError(
                    f"expected certificate generation {expected_generation}, got {generation}"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO agent_certificates (
                        agent_id, generation, serial_number, cert_sha256, spki_sha256,
                        state, certificate_pem, idempotency_key_sha256,
                        not_before_us, not_after_us, created_at_us
                    ) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_agent_id,
                        generation,
                        serial,
                        fingerprint,
                        public_key_fingerprint,
                        pem,
                        key_hash,
                        _micros(start),
                        _micros(end),
                        _micros(timestamp),
                    ),
                )
                changed = connection.execute(
                    """
                    UPDATE agent_identities
                    SET generation = ?, updated_at_us = ?, revision = revision + 1
                    WHERE agent_id = ? AND generation = ? AND state = 'active'
                    """,
                    (
                        generation,
                        _micros(timestamp),
                        normalized_agent_id,
                        generation - 1,
                    ),
                ).rowcount
            except sqlite3.IntegrityError as exc:
                raise AgentIdentityConflictError(
                    "certificate generation, serial, fingerprint, or staged slot conflicts"
                ) from exc
            if changed != 1:
                raise AgentIdentityConflictError("identity generation changed while staging")
            return (
                self._identity_from_row(
                    connection,
                    self._identity_row(connection, normalized_agent_id),
                ),
                True,
            )

    def activate(
        self,
        agent_id: str,
        generation: int,
        *,
        overlap: timedelta = DEFAULT_ROTATION_OVERLAP,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Activate a staged generation and briefly accept the prior active one."""

        normalized_agent_id = _normalize_agent_id(agent_id)
        if generation < 1:
            raise ValueError("generation must be positive")
        if overlap < timedelta(0) or overlap > MAX_ROTATION_OVERLAP:
            raise ValueError(
                f"overlap must be between zero and {MAX_ROTATION_OVERLAP.total_seconds():.0f}s"
            )
        timestamp = _utc(now or datetime.now(UTC))
        timestamp_us = _micros(timestamp)
        overlap_until_us = _micros(timestamp + overlap)
        with self._transaction() as connection:
            identity = self._identity_row(connection, normalized_agent_id)
            if identity["state"] != AgentIdentityState.ACTIVE.value:
                raise AgentIdentityConflictError("cannot activate a revoked identity")
            certificate = self._certificate_row(connection, normalized_agent_id, generation)
            if certificate["state"] == AgentCertificateState.ACTIVE.value:
                return self._identity_from_row(connection, identity)
            if certificate["state"] != AgentCertificateState.STAGED.value:
                raise AgentIdentityConflictError(
                    f"certificate generation {generation} is {certificate['state']}, not staged"
                )
            if int(certificate["not_after_us"]) <= int(timestamp_us):
                raise AgentIdentityConflictError("cannot activate an expired certificate")

            # At most the immediately previous active generation receives an
            # overlap window.  Older retired generations are closed now, which
            # prevents rapid rotations from creating a three-certificate window.
            connection.execute(
                """
                UPDATE agent_certificates
                SET overlap_until_us = ?
                WHERE agent_id = ? AND state = 'retired'
                  AND overlap_until_us IS NOT NULL AND overlap_until_us > ?
                """,
                (timestamp_us, normalized_agent_id, timestamp_us),
            )
            connection.execute(
                """
                UPDATE agent_certificates
                SET state = 'retired', retired_at_us = ?,
                    overlap_until_us = MIN(not_after_us, ?)
                WHERE agent_id = ? AND state = 'active'
                """,
                (timestamp_us, overlap_until_us, normalized_agent_id),
            )
            changed = connection.execute(
                """
                UPDATE agent_certificates
                SET state = 'active', activated_at_us = ?,
                    retired_at_us = NULL, overlap_until_us = NULL
                WHERE agent_id = ? AND generation = ? AND state = 'staged'
                """,
                (timestamp_us, normalized_agent_id, generation),
            ).rowcount
            if changed != 1:
                raise AgentIdentityConflictError("certificate changed while activating")
            connection.execute(
                """
                UPDATE agent_identities
                SET updated_at_us = ?, revision = revision + 1 WHERE agent_id = ?
                """,
                (timestamp_us, normalized_agent_id),
            )
            return self._identity_from_row(
                connection,
                self._identity_row(connection, normalized_agent_id),
            )

    def abort(
        self,
        agent_id: str,
        generation: int,
        *,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Abort a staged deployment without ever reusing its generation."""

        normalized_agent_id = _normalize_agent_id(agent_id)
        if generation < 1:
            raise ValueError("generation must be positive")
        timestamp = _utc(now or datetime.now(UTC))
        with self._transaction() as connection:
            identity = self._identity_row(connection, normalized_agent_id)
            certificate = self._certificate_row(connection, normalized_agent_id, generation)
            if certificate["state"] == AgentCertificateState.REVOKED.value:
                return self._identity_from_row(connection, identity)
            if certificate["state"] != AgentCertificateState.STAGED.value:
                raise AgentIdentityConflictError(
                    f"certificate generation {generation} is {certificate['state']}, not staged"
                )
            connection.execute(
                """
                UPDATE agent_certificates
                SET state = 'revoked', revoked_at_us = ?, overlap_until_us = NULL,
                    idempotency_key_sha256 = NULL
                WHERE agent_id = ? AND generation = ? AND state = 'staged'
                """,
                (_micros(timestamp), normalized_agent_id, generation),
            )
            connection.execute(
                """
                UPDATE agent_identities
                SET updated_at_us = ?, revision = revision + 1 WHERE agent_id = ?
                """,
                (_micros(timestamp), normalized_agent_id),
            )
            return self._identity_from_row(
                connection,
                self._identity_row(connection, normalized_agent_id),
            )

    def revoke(
        self,
        agent_id: str,
        *,
        generation: int | None = None,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Revoke one generation, or the whole identity when generation is absent."""

        normalized_agent_id = _normalize_agent_id(agent_id)
        if generation is not None and generation < 1:
            raise ValueError("generation must be positive")
        timestamp = _utc(now or datetime.now(UTC))
        timestamp_us = _micros(timestamp)
        with self._transaction() as connection:
            identity = self._identity_row(connection, normalized_agent_id)
            if generation is None:
                if identity["state"] == AgentIdentityState.REVOKED.value:
                    return self._identity_from_row(connection, identity)
                connection.execute(
                    """
                    UPDATE agent_identities
                    SET state = 'revoked', revoked_at_us = ?, updated_at_us = ?,
                        revision = revision + 1
                    WHERE agent_id = ?
                    """,
                    (timestamp_us, timestamp_us, normalized_agent_id),
                )
                connection.execute(
                    """
                    UPDATE agent_certificates
                    SET state = 'revoked', revoked_at_us = ?, overlap_until_us = NULL
                    WHERE agent_id = ? AND state != 'revoked'
                    """,
                    (timestamp_us, normalized_agent_id),
                )
            else:
                certificate = self._certificate_row(
                    connection,
                    normalized_agent_id,
                    generation,
                )
                if certificate["state"] != AgentCertificateState.REVOKED.value:
                    connection.execute(
                        """
                        UPDATE agent_certificates
                        SET state = 'revoked', revoked_at_us = ?, overlap_until_us = NULL
                        WHERE agent_id = ? AND generation = ?
                        """,
                        (timestamp_us, normalized_agent_id, generation),
                    )
                    connection.execute(
                        """
                        UPDATE agent_identities
                        SET updated_at_us = ?, revision = revision + 1 WHERE agent_id = ?
                        """,
                        (timestamp_us, normalized_agent_id),
                    )
            return self._identity_from_row(
                connection,
                self._identity_row(connection, normalized_agent_id),
            )

    def revoke_certificates(
        self,
        agent_id: str,
        *,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Revoke every credential while preserving the stable target binding.

        Guard stop/cancellation is a credential teardown, not target
        decommissioning. Keeping the identity active lets a later Guard start
        issue the next immutable generation, while every previously copied key
        becomes unusable immediately. Full identity revocation remains the
        explicit administrative decommission operation in :meth:`revoke`.
        """

        normalized_agent_id = _normalize_agent_id(agent_id)
        timestamp = _utc(now or datetime.now(UTC))
        timestamp_us = _micros(timestamp)
        with self._transaction() as connection:
            self._identity_row(connection, normalized_agent_id)
            changed = connection.execute(
                """
                UPDATE agent_certificates
                SET state = 'revoked', revoked_at_us = ?, overlap_until_us = NULL,
                    idempotency_key_sha256 = NULL
                WHERE agent_id = ? AND state != 'revoked'
                """,
                (timestamp_us, normalized_agent_id),
            ).rowcount
            if changed:
                connection.execute(
                    """
                    UPDATE agent_identities
                    SET updated_at_us = ?, revision = revision + 1 WHERE agent_id = ?
                    """,
                    (timestamp_us, normalized_agent_id),
                )
            return self._identity_from_row(
                connection,
                self._identity_row(connection, normalized_agent_id),
            )

    def verify(
        self,
        *,
        cert_sha256: str | None = None,
        serial_number: str | None = None,
        now: datetime | None = None,
        allow_staged: bool = False,
    ) -> VerifiedAgentIdentity | None:
        """Resolve a verified peer-certificate identifier to an active principal.

        The caller must pass metadata obtained from the TLS transport.  No
        client-supplied ``agent_id``, host id, or scope participates in this
        lookup.  Revocation is read from SQLite on every call so it takes effect
        across Form processes immediately.
        """

        if cert_sha256 is None and serial_number is None:
            raise ValueError("cert_sha256 or serial_number is required")
        fingerprint = (
            _normalize_hex(cert_sha256, "cert_sha256", length=64)
            if cert_sha256 is not None
            else None
        )
        serial = _normalize_serial(serial_number) if serial_number is not None else None
        conditions: list[str] = []
        parameters: list[Any] = []
        if fingerprint is not None:
            conditions.append("c.cert_sha256 = ?")
            parameters.append(fingerprint)
        if serial is not None:
            conditions.append("c.serial_number = ?")
            parameters.append(serial)
        connection = self._read_connection()
        try:
            row = connection.execute(
                """
                SELECT
                    c.*,
                    i.target_id AS identity_target_id,
                    i.canonical_host_id AS identity_canonical_host_id,
                    i.scopes_json AS identity_scopes_json,
                    i.state AS identity_state
                FROM agent_certificates AS c
                JOIN agent_identities AS i ON i.agent_id = c.agent_id
                WHERE """
                + " AND ".join(conditions),
                parameters,
            ).fetchone()
            if row is None or row["identity_state"] != AgentIdentityState.ACTIVE.value:
                return None
            timestamp_us = _micros(_utc(now or datetime.now(UTC)))
            if not (int(row["not_before_us"]) <= int(timestamp_us) < int(row["not_after_us"])):
                return None
            state = AgentCertificateState(row["state"])
            accepted = state is AgentCertificateState.ACTIVE
            if state is AgentCertificateState.RETIRED:
                overlap_until = row["overlap_until_us"]
                accepted = overlap_until is not None and int(timestamp_us) < int(overlap_until)
            elif state is AgentCertificateState.STAGED:
                accepted = allow_staged
            if not accepted:
                return None
            certificate = self._certificate_from_row(row)
            return VerifiedAgentIdentity(
                agent_id=row["agent_id"],
                target_id=row["identity_target_id"],
                canonical_host_id=row["identity_canonical_host_id"],
                scopes=json.loads(row["identity_scopes_json"]),
                certificate=certificate,
            )
        finally:
            connection.close()

    def close(self) -> None:
        """Prevent new operations; connections are otherwise short lived."""

        self._closed = True


__all__ = [
    "AgentCertificateNotFoundError",
    "AgentIdentityConflictError",
    "AgentIdentityNotFoundError",
    "AgentIdentityRepository",
    "AgentIdentityStoreError",
    "DEFAULT_DB_FILENAME",
    "DEFAULT_ROTATION_OVERLAP",
    "MAX_ROTATION_OVERLAP",
]
