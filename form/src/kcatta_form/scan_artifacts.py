"""Durable hand-off spool between remote collection and Analyzer forwarding.

A scan may finish on the target immediately before Form or Analyzer restarts.
Persisting the collected envelope before forwarding lets a retried worker send
the exact same report/batch identifiers instead of deploying the scan again.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from analyzer.storage import StorageCapacityError
from pydantic import BaseModel

from .schemas import AssetReport, ScanResult, TraceBatch
from .telemetry_chunks import parse_unbounded_asset_report, parse_unbounded_trace_batch

try:  # POSIX Form deployments use a process-shared sidecar lock.
    import fcntl
except ImportError:  # pragma: no cover - Windows local development fallback
    fcntl = None  # type: ignore[assignment]

ArtifactKind = Literal["asset-report", "trace-batch", "scan-result"]

DEFAULT_MAX_ARTIFACT_BYTES = 36 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_JOB_ID = re.compile(r"^[A-Za-z0-9._-]{1,256}$")


def _positive_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class StoredScanArtifact:
    """Metadata returned after a durable write or verified read."""

    job_id: str
    kind: ArtifactKind
    size: int
    sha256: str


class ScanArtifactStore:
    """Small, bounded, atomic JSON spool owned by Form's durable worker."""

    def __init__(
        self,
        root: Path,
        *,
        max_artifact_bytes: int | None = None,
        max_total_bytes: int | None = None,
    ) -> None:
        self.root = root
        self.max_artifact_bytes = max_artifact_bytes or _positive_env(
            "FORM_SCAN_SPOOL_MAX_ARTIFACT_BYTES", DEFAULT_MAX_ARTIFACT_BYTES
        )
        self.max_total_bytes = max_total_bytes or _positive_env(
            "FORM_SCAN_SPOOL_MAX_TOTAL_BYTES", DEFAULT_MAX_TOTAL_BYTES
        )
        if self.max_artifact_bytes > self.max_total_bytes:
            raise ValueError("scan spool per-artifact limit cannot exceed its total limit")
        self._thread_lock = threading.RLock()
        self._ensure_root()

    def _ensure_root(self) -> None:
        if self.root.is_symlink():
            raise RuntimeError(f"scan artifact spool must not be a symlink: {self.root}")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            stat = self.root.stat()
            if stat.st_uid != os.getuid():
                raise RuntimeError(f"scan artifact spool is not owned by this user: {self.root}")
            os.chmod(self.root, 0o700)

    def _path(self, job_id: str) -> Path:
        if not _JOB_ID.fullmatch(job_id):
            raise ValueError("job_id contains characters unsafe for the artifact spool")
        return self.root / f"{job_id}.json"

    @contextmanager
    def _locked(self):  # type: ignore[no-untyped-def]
        with self._thread_lock:
            lock_path = self.root / ".lock"
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def save(self, job_id: str, kind: ArtifactKind, payload: BaseModel) -> StoredScanArtifact:
        """Atomically persist one validated model under hard item/total quotas."""
        path = self._path(job_id)
        expected_type: type[BaseModel]
        if kind == "asset-report":
            expected_type = AssetReport
        elif kind == "trace-batch":
            expected_type = TraceBatch
        else:
            expected_type = ScanResult
        if not isinstance(payload, expected_type):
            raise TypeError(f"artifact kind {kind} requires {expected_type.__name__}")
        payload_data = payload.model_dump(mode="json")
        payload_encoded = json.dumps(
            payload_data,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = json.dumps(
            {
                "version": 1,
                "job_id": job_id,
                "kind": kind,
                "payload_sha256": hashlib.sha256(payload_encoded).hexdigest(),
                "payload": payload_data,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > self.max_artifact_bytes:
            raise StorageCapacityError(
                f"scan artifact for {job_id} is {len(encoded)} bytes; "
                f"spool limit is {self.max_artifact_bytes}"
            )
        digest = hashlib.sha256(encoded).hexdigest()
        with self._locked():
            self._cleanup_temporary_files_locked()
            existing_size = path.stat().st_size if path.is_file() and not path.is_symlink() else 0
            total = self._spool_bytes_locked()
            if total - existing_size + len(encoded) > self.max_total_bytes:
                raise StorageCapacityError(
                    f"scan artifact spool would exceed {self.max_total_bytes} bytes"
                )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{job_id}.", suffix=".tmp", dir=self.root
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    descriptor = -1
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
                self._fsync_root()
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()
        return StoredScanArtifact(job_id, kind, len(encoded), digest)

    def load(
        self, job_id: str
    ) -> tuple[StoredScanArtifact, AssetReport | TraceBatch | ScanResult] | None:
        """Read, bound, parse and schema-validate a previously stored artifact."""
        path = self._path(job_id)
        with self._locked():
            if not path.exists():
                return None
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"scan artifact is not a regular file: {path}")
            size = path.stat().st_size
            if size > self.max_artifact_bytes:
                raise StorageCapacityError(
                    f"scan artifact for {job_id} exceeds {self.max_artifact_bytes} bytes"
                )
            with path.open("rb") as source:
                encoded = source.read(self.max_artifact_bytes + 1)
        if len(encoded) > self.max_artifact_bytes:
            raise StorageCapacityError(
                f"scan artifact for {job_id} grew beyond its configured limit"
            )
        envelope = json.loads(encoded)
        if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
            raise ValueError(f"invalid durable scan artifact envelope for {job_id}")
        if envelope.get("version") != 1 or envelope.get("job_id") != job_id:
            raise ValueError(f"durable scan artifact identity mismatch for {job_id}")
        payload_encoded = json.dumps(
            envelope["payload"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_digest = envelope.get("payload_sha256")
        actual_digest = hashlib.sha256(payload_encoded).hexdigest()
        if not isinstance(expected_digest, str) or not hmac.compare_digest(
            expected_digest, actual_digest
        ):
            raise ValueError(f"durable scan artifact checksum mismatch for {job_id}")
        kind = envelope.get("kind")
        payload_text = payload_encoded.decode("utf-8")
        if kind == "asset-report":
            payload: AssetReport | TraceBatch | ScanResult = parse_unbounded_asset_report(
                payload_text
            )
        elif kind == "trace-batch":
            payload = parse_unbounded_trace_batch(payload_text)
        elif kind == "scan-result":
            payload = ScanResult.model_validate(envelope["payload"])
        else:
            raise ValueError(f"unknown durable scan artifact kind for {job_id}: {kind!r}")
        metadata = StoredScanArtifact(
            job_id=job_id,
            kind=kind,
            size=len(encoded),
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
        return metadata, payload

    def delete(self, job_id: str) -> None:
        """Remove an acknowledged/cancelled artifact durably and idempotently."""
        path = self._path(job_id)
        with self._locked():
            if path.is_symlink():
                raise RuntimeError(f"refusing to unlink symlinked scan artifact: {path}")
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
                self._fsync_root()

    def reconcile(self, retain: Callable[[str], bool]) -> int:
        """Remove crash leftovers and artifacts no durable head can still use."""
        removed = 0
        with self._locked():
            removed += self._cleanup_temporary_files_locked()
            for path in self.root.glob("*.json"):
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError(f"scan artifact is not a regular file: {path}")
                job_id = path.stem
                if not _JOB_ID.fullmatch(job_id) or not retain(job_id):
                    path.unlink()
                    removed += 1
            if removed:
                self._fsync_root()
        return removed

    def _cleanup_temporary_files_locked(self) -> int:
        removed = 0
        for path in self.root.glob(".*.tmp"):
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"scan artifact temporary is not a regular file: {path}")
            path.unlink()
            removed += 1
        return removed

    def _spool_bytes_locked(self) -> int:
        total = 0
        for path in self.root.iterdir():
            if path.name == ".lock":
                continue
            if path.is_symlink():
                raise RuntimeError(f"scan artifact spool contains a symlink: {path}")
            if path.is_file():
                total += path.stat().st_size
        return total

    def _fsync_root(self) -> None:
        if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
            return
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
