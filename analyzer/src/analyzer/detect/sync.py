"""Download OSV advisory data into the local store.

OSV publishes per-ecosystem zip exports of every record in a public GCS
bucket. We fetch one top-level ecosystem (e.g. ``Debian``, ``Ubuntu``,
``PyPI``) and atomically build a package index under ``<dest>/<ecosystem>/``;
expanded JSON can optionally be retained for inspection. Detection queries the
index via :class:`~analyzer.detect.store.OsvStore`.

Only the stdlib is used (``urllib`` + ``zipfile``); detection itself never
touches the network, so this stays an explicit, offline-friendly refresh step.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .osv import OsvRecord
from .store import OsvIndexWriter

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"

# Complete default corpus for every *supported* package ecosystem emitted by
# the bundled host collectors. Release-qualified values (for example
# ``Debian:12``) map to these top-level OSV exports. The collector also emits
# ``Windows:<major>`` inventory, but OSV defines no Windows ecosystem/export;
# those packages are retained and explicitly reported as unsupported coverage.
DEFAULT_OSV_ECOSYSTEMS = (
    "Debian",
    "Ubuntu",
    "Alpine",
    "Rocky Linux",
    "AlmaLinux",
    "openSUSE",
    "PyPI",
    "npm",
)

UNSUPPORTED_COLLECTED_ECOSYSTEMS = frozenset({"Windows"})


@dataclass(frozen=True)
class OsvSyncManifest:
    """Trusted per-ecosystem record counts from one atomic sync."""

    ecosystems: frozenset[str]
    record_counts: dict[str, int]


def ecosystem_family(ecosystem: str) -> str:
    """Return the top-level OSV export name for a release-qualified value."""
    return ecosystem.split(":", 1)[0].strip()


def read_complete_manifest(directory: str | Path) -> OsvSyncManifest | None:
    """Read the atomic sync manifest, returning ``None`` when it is not trustworthy.

    Merely finding a file named ``.complete`` is insufficient: older/manual
    markers carried no ecosystem inventory, so they cannot prove that a report's
    package ecosystems were actually downloaded.
    """
    marker = Path(directory) / ".complete"
    try:
        raw = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    ecosystems = raw.get("ecosystems") if isinstance(raw, dict) else None
    record_counts = raw.get("record_counts") if isinstance(raw, dict) else None
    if not isinstance(ecosystems, list) or not ecosystems:
        return None
    if not isinstance(record_counts, dict):
        return None
    values: set[str] = set()
    for value in ecosystems:
        if not isinstance(value, str) or not value.strip():
            return None
        values.add(value.strip())
    counts: dict[str, int] = {}
    for ecosystem in values:
        count = record_counts.get(ecosystem)
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            return None
        counts[ecosystem] = count
    if set(record_counts) != values:
        return None
    return OsvSyncManifest(ecosystems=frozenset(values), record_counts=counts)


def read_complete_marker(directory: str | Path) -> frozenset[str] | None:
    """Return ecosystems from a valid count-bearing atomic sync manifest."""
    manifest = read_complete_manifest(directory)
    return manifest.ecosystems if manifest else None


def write_complete_manifest(
    directory: str | Path,
    ecosystems: list[str],
    record_counts: dict[str, int],
) -> None:
    """Durably publish the final count-bearing marker with an atomic rename."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            {"ecosystems": ecosystems, "record_counts": record_counts},
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    )
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=root,
            prefix=".complete.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, root / ".complete")
        temporary_name = None
        try:
            descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            descriptor = None
        if descriptor is not None:
            try:
                os.fsync(descriptor)
            except OSError:
                pass
            finally:
                os.close(descriptor)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _valid_records(payload: object, ecosystem: str) -> list[dict]:
    """Keep only usable, non-withdrawn records that can match this export."""
    family = ecosystem_family(ecosystem)
    raw_records = payload if isinstance(payload, list) else [payload]
    valid: list[dict] = []
    for raw in raw_records:
        if not isinstance(raw, dict):
            continue
        record_id = raw.get("id")
        if not isinstance(record_id, str) or not record_id.strip() or raw.get("withdrawn"):
            continue
        try:
            OsvRecord.from_dict(raw)
        except (KeyError, TypeError, ValueError):
            continue
        affected = raw.get("affected")
        if not isinstance(affected, list):
            continue
        matchable = False
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if not isinstance(package, dict):
                continue
            package_ecosystem = package.get("ecosystem")
            package_name = package.get("name")
            ranges = entry.get("ranges")
            versions = entry.get("versions")
            if (
                isinstance(package_ecosystem, str)
                and ecosystem_family(package_ecosystem) == family
                and isinstance(package_name, str)
                and package_name.strip()
                and (
                    (isinstance(ranges, list) and bool(ranges))
                    or (isinstance(versions, list) and bool(versions))
                )
            ):
                matchable = True
                break
        if matchable:
            valid.append(raw)
    return valid


def export_url(ecosystem: str) -> str:
    """Return the OSV bucket URL of the ``all.zip`` export for a top-level ecosystem."""
    # Several official ecosystem names contain spaces (for example
    # ``Rocky Linux``).  Passing those through urllib unescaped raises before a
    # request is made, which made the advertised default sync set only partly
    # usable.
    return f"{OSV_BUCKET}/{urllib.parse.quote(ecosystem, safe='')}/all.zip"


def sync_ecosystem(
    ecosystem: str,
    dest_dir: str | Path,
    timeout: float = 60.0,
    *,
    retain_json: bool = True,
) -> int:
    """Download ``<ecosystem>/all.zip`` and extract records under ``dest_dir``.

    Returns the number of JSON records written. ``ecosystem`` is the
    top-level OSV name without a release suffix (``Debian``, not
    ``Debian:12``); records inside carry the release-qualified ecosystem.
    """
    root = Path(dest_dir)
    root.mkdir(parents=True, exist_ok=True)

    url = export_url(ecosystem)
    with (
        urllib.request.urlopen(url, timeout=timeout) as response,  # noqa: S310 - fixed https host
        tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as archive_file,
    ):
        shutil.copyfileobj(response, archive_file, length=1024 * 1024)
        archive_file.seek(0)
        return _install_archive(ecosystem, root, archive_file, retain_json=retain_json)


def sync_ecosystem_archive(
    ecosystem: str,
    dest_dir: str | Path,
    archive_path: str | Path,
    *,
    retain_json: bool = True,
) -> int:
    """Install a previously downloaded OSV ``all.zip`` export.

    This is the offline/air-gapped sibling of :func:`sync_ecosystem`. The same
    validation and atomic replacement apply, so a corrupt or unusable archive
    cannot damage the currently active ecosystem snapshot.
    """
    root = Path(dest_dir)
    root.mkdir(parents=True, exist_ok=True)
    with Path(archive_path).open("rb") as archive_file:
        return _install_archive(ecosystem, root, archive_file, retain_json=retain_json)


def _install_archive(
    ecosystem: str,
    root: Path,
    archive_file: BinaryIO,
    *,
    retain_json: bool,
) -> int:
    """Validate and atomically install one seekable ecosystem archive stream."""
    target = root / ecosystem

    # Build a complete ecosystem snapshot beside the live directory and swap it
    # in only after the archive has been read successfully.  A failed refresh
    # therefore cannot leave Analyzer loading a half-written corpus, and records
    # removed upstream do not linger forever.
    prefix = ".osv-sync-" + "".join(c if c.isalnum() else "-" for c in ecosystem) + "-"
    wrote_any = False
    with tempfile.TemporaryDirectory(prefix=prefix, dir=root) as temporary:
        temporary_path = Path(temporary)
        staged = temporary_path / "staged"
        staged.mkdir()
        with (
            OsvIndexWriter(staged, ecosystem) as index_writer,
            zipfile.ZipFile(archive_file) as archive,
        ):
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    member_payload = json.loads(archive.read(member))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                records = _valid_records(member_payload, ecosystem)
                if not records:
                    continue
                if retain_json:
                    out_path = staged / Path(member).name
                    out_path.write_text(
                        json.dumps(records if isinstance(member_payload, list) else records[0]),
                        encoding="utf-8",
                    )
                for record in records:
                    wrote_any |= index_writer.add(record)

        if not wrote_any or index_writer.record_count <= 0:
            raise OSError(f"OSV export for {ecosystem} contained no valid matchable records")

        previous = temporary_path / "previous"
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise OSError(f"refusing to replace non-directory OSV target: {target}")
            os.replace(target, previous)
        try:
            os.replace(staged, target)
        except Exception:
            if previous.exists() and not target.exists():
                os.replace(previous, target)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    return index_writer.record_count
