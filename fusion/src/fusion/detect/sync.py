"""Download OSV advisory data into the local store.

OSV publishes per-ecosystem zip exports of every record in a public GCS
bucket. We fetch one top-level ecosystem (e.g. ``Debian``, ``Ubuntu``,
``PyPI``) and unpack the per-record JSON files under ``<dest>/<ecosystem>/``.
Detection then loads that directory via :class:`~fusion.detect.store.OsvStore`.

Only the stdlib is used (``urllib`` + ``zipfile``); detection itself never
touches the network, so this stays an explicit, offline-friendly refresh step.
"""

from __future__ import annotations

import io
import urllib.request
import zipfile
from pathlib import Path

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"


def export_url(ecosystem: str) -> str:
    """Return the OSV bucket URL of the ``all.zip`` export for a top-level ecosystem."""
    return f"{OSV_BUCKET}/{ecosystem}/all.zip"


def sync_ecosystem(ecosystem: str, dest_dir: str | Path, timeout: float = 60.0) -> int:
    """Download ``<ecosystem>/all.zip`` and extract records under ``dest_dir``.

    Returns the number of JSON records written. ``ecosystem`` is the
    top-level OSV name without a release suffix (``Debian``, not
    ``Debian:12``); records inside carry the release-qualified ecosystem.
    """
    target = Path(dest_dir) / ecosystem
    target.mkdir(parents=True, exist_ok=True)

    url = export_url(ecosystem)
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed https host
        payload = resp.read()

    written = 0
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.namelist():
            if not member.endswith(".json"):
                continue
            data = archive.read(member)
            out_path = target / Path(member).name
            out_path.write_bytes(data)
            written += 1
    return written
