"""OSV synchronisation safety and ecosystem URL handling."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from analyzer.detect import sync as sync_mod
from analyzer.detect.store import INDEX_FILENAME, OsvStore


def _archive(records: dict[str, dict]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, record in records.items():
            archive.writestr(name, json.dumps(record))
    return output.getvalue()


def _record(record_id: str, ecosystem: str = "Debian:12") -> dict:
    return {
        "id": record_id,
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": "sample"},
                "versions": ["1.0"],
            }
        ],
    }


def test_export_url_quotes_official_ecosystem_names() -> None:
    assert sync_mod.export_url("Rocky Linux").endswith("/Rocky%20Linux/all.zip")


def test_default_sync_excludes_unsupported_windows_inventory() -> None:
    assert "Windows" not in sync_mod.DEFAULT_OSV_ECOSYSTEMS
    assert "Windows" in sync_mod.UNSUPPORTED_COLLECTED_ECOSYSTEMS


def test_sync_replaces_complete_snapshot_and_removes_stale_records(tmp_path, monkeypatch) -> None:
    target = tmp_path / "Debian"
    target.mkdir()
    (target / "stale.json").write_text('{"id":"OLD"}', encoding="utf-8")
    payload = _archive({"nested/NEW.json": _record("NEW")})

    class _Response:
        def __init__(self):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _size: int = -1):
            value, self._payload = self._payload, b""
            return value

    monkeypatch.setattr(sync_mod.urllib.request, "urlopen", lambda *_a, **_k: _Response())
    assert sync_mod.sync_ecosystem("Debian", tmp_path) == 1
    assert not (target / "stale.json").exists()
    assert json.loads((target / "NEW.json").read_text()) == _record("NEW")


def test_sync_from_local_archive_uses_same_atomic_installer(tmp_path) -> None:
    archive_path = tmp_path / "Debian.zip"
    archive_path.write_bytes(_archive({"nested/LOCAL.json": _record("LOCAL")}))

    assert sync_mod.sync_ecosystem_archive("Debian", tmp_path / "db", archive_path) == 1
    installed = tmp_path / "db" / "Debian" / "LOCAL.json"
    assert json.loads(installed.read_text(encoding="utf-8")) == _record("LOCAL")
    assert (installed.parent / INDEX_FILENAME).is_file()

    installed.unlink()
    store = OsvStore.load_dir(tmp_path / "db")
    assert [record.id for record in store.lookup("Debian:12", "sample")] == ["LOCAL"]
    store.close()


def test_index_only_archive_is_directly_queryable(tmp_path) -> None:
    archive_path = tmp_path / "PyPI.zip"
    archive_path.write_bytes(_archive({"PYSEC.json": _record("PYSEC", "PyPI")}))

    assert (
        sync_mod.sync_ecosystem_archive(
            "PyPI",
            tmp_path / "db",
            archive_path,
            retain_json=False,
        )
        == 1
    )
    target = tmp_path / "db" / "PyPI"
    assert list(target.glob("*.json")) == []
    assert (target / INDEX_FILENAME).is_file()

    store = OsvStore.load_dir(tmp_path / "db")
    assert [record.id for record in store.lookup("PyPI", "sample")] == ["PYSEC"]
    store.close()


def test_failed_archive_keeps_previous_snapshot(tmp_path, monkeypatch) -> None:
    target = tmp_path / "Debian"
    target.mkdir()
    previous = target / "OLD.json"
    previous.write_text('{"id":"OLD"}', encoding="utf-8")

    class _Response:
        def __init__(self):
            self._payload = b"not-a-zip"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _size: int = -1):
            value, self._payload = self._payload, b""
            return value

    monkeypatch.setattr(sync_mod.urllib.request, "urlopen", lambda *_a, **_k: _Response())
    with pytest.raises(zipfile.BadZipFile):
        sync_mod.sync_ecosystem("Debian", tmp_path)
    assert previous.read_text(encoding="utf-8") == '{"id":"OLD"}'


@pytest.mark.parametrize(
    "records",
    [
        {"bad.json": {"id": "NO-AFFECTED", "affected": []}},
        {"wrong.json": _record("WRONG", "npm")},
    ],
)
def test_empty_or_unusable_export_keeps_previous_snapshot(tmp_path, monkeypatch, records) -> None:
    target = tmp_path / "Debian"
    target.mkdir()
    previous = target / "OLD.json"
    previous.write_text(json.dumps(_record("OLD")), encoding="utf-8")
    payload = _archive(records)

    class _Response:
        def __init__(self):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _size: int = -1):
            value, self._payload = self._payload, b""
            return value

    monkeypatch.setattr(sync_mod.urllib.request, "urlopen", lambda *_a, **_k: _Response())
    with pytest.raises(OSError, match="no valid matchable records"):
        sync_mod.sync_ecosystem("Debian", tmp_path)
    assert json.loads(previous.read_text(encoding="utf-8")) == _record("OLD")
