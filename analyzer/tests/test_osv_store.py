"""Bounded-memory disk-backed OSV store tests."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from analyzer.detect import OsvStore
from analyzer.detect.store import INDEX_FILENAME


def _record(record_id: str, ecosystem: str = "PyPI", name: str = "sample") -> dict:
    return {
        "id": record_id,
        "aliases": ["CVE-2099-0001"],
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "versions": ["1.0"],
            }
        ],
    }


def _write_record(root: Path, record: dict) -> Path:
    ecosystem = record["affected"][0]["package"]["ecosystem"].split(":", 1)[0]
    directory = root / ecosystem
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{record['id']}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_json_ecosystem_becomes_disk_backed_and_survives_without_source_json(
    tmp_path: Path,
) -> None:
    root = tmp_path / "osv"
    source = _write_record(root, _record("OSV-DISK"))

    store = OsvStore.load_dir(root)

    assert store.record_count == 1
    assert store.ecosystem_record_counts == {"PyPI": 1}
    assert store.disk_backed_ecosystems == frozenset({"PyPI"})
    assert [record.id for record in store.lookup("PyPI", "sample")] == ["OSV-DISK"]
    assert (root / "PyPI" / INDEX_FILENAME).is_file()
    store.close()

    # The immutable index is self-contained: Analyzer needs no JSON parsing or
    # resident advisory graph after the one-time migration.
    source.unlink()
    reopened = OsvStore.load_dir(root)
    assert reopened.record_count == 1
    assert [record.id for record in reopened.lookup("PyPI", "sample")] == ["OSV-DISK"]
    reopened.close()


def test_corrupt_index_is_atomically_rebuilt_from_json(tmp_path: Path) -> None:
    root = tmp_path / "osv"
    _write_record(root, _record("OSV-REBUILD"))
    index = root / "PyPI" / INDEX_FILENAME
    index.write_bytes(b"not sqlite")

    store = OsvStore.load_dir(root)

    assert [record.id for record in store.lookup("PyPI", "sample")] == ["OSV-REBUILD"]
    assert index.read_bytes().startswith(b"SQLite format 3")
    store.close()


def test_read_only_connection_is_safe_for_concurrent_lookups(tmp_path: Path) -> None:
    root = tmp_path / "osv"
    _write_record(root, _record("OSV-CONCURRENT"))
    store = OsvStore.load_dir(root)

    def lookup(_: int) -> list[str]:
        return [record.id for record in store.lookup("PyPI", "sample")]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lookup, range(64)))

    assert results == [["OSV-CONCURRENT"]] * 64
    store.close()


def test_multiple_ecosystems_report_index_counts_without_loading_records(tmp_path: Path) -> None:
    root = tmp_path / "osv"
    _write_record(root, _record("OSV-PYPI"))
    _write_record(root, _record("OSV-NPM", "npm", "left-pad"))

    store = OsvStore.load_dir(root)

    assert store.record_count == 2
    assert store.ecosystem_record_counts == {"PyPI": 1, "npm": 1}
    assert store.disk_backed_ecosystems == frozenset({"PyPI", "npm"})
    assert store.lookup("PyPI", "missing") == []
    store.close()
