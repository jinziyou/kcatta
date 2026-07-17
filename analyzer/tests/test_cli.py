"""CLI behaviour: the default OSV sync set + the empty-store startup warning.

Network is never touched — ``sync_ecosystem`` is monkeypatched, so this exercises
the argparse default and the per-ecosystem loop offline.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from analyzer import cli
from analyzer.api import create_app
from analyzer.detect import sync_debian_tracker


def test_default_ecosystems_cover_supported_agent_emission_surface() -> None:
    eco = set(cli.DEFAULT_OSV_ECOSYSTEMS)
    # The GHSA-bearing language ecosystems the agent emits — syncing these covers
    # GHSA-derived findings (GHSA is merged into the PyPI/npm OSV exports).
    assert {"PyPI", "npm"} <= eco
    # The OS surface the agent's osv_ecosystem() can actually produce.
    assert {
        "Debian",
        "Ubuntu",
        "Alpine",
        "Rocky Linux",
        "AlmaLinux",
        "openSUSE",
    } <= eco
    # OSV defines no Windows package ecosystem/export. Windows inventory still
    # flows, but is reported as explicitly unsupported instead of breaking sync.
    assert "Windows" not in eco
    # Dead weight stays OUT: SLES/RHEL/CentOS/Fedora (unreproducible OSV keying)
    # and language ecosystems with no agent collector.
    assert eco.isdisjoint({"SUSE", "Maven", "Go", "RubyGems", "crates.io", "NuGet", "CentOS"})


def test_osv_sync_defaults_to_full_set(tmp_path: Path, monkeypatch) -> None:
    synced: list[str] = []
    monkeypatch.setattr(
        cli,
        "sync_ecosystem",
        lambda eco, db, **_kwargs: synced.append(eco) or 1,
    )
    monkeypatch.setattr(sys, "argv", ["analyzer-osv-sync", "--db", str(tmp_path)])
    cli.osv_sync_main()
    assert synced == list(cli.DEFAULT_OSV_ECOSYSTEMS)
    assert json.loads((tmp_path / ".complete").read_text()) == {
        "ecosystems": list(cli.DEFAULT_OSV_ECOSYSTEMS),
        "record_counts": {ecosystem: 1 for ecosystem in cli.DEFAULT_OSV_ECOSYSTEMS},
    }


def test_osv_sync_explicit_list_overrides_default(tmp_path: Path, monkeypatch) -> None:
    synced: list[str] = []
    monkeypatch.setattr(
        cli,
        "sync_ecosystem",
        lambda eco, db, **_kwargs: synced.append(eco) or 1,
    )
    monkeypatch.setattr(
        sys, "argv", ["analyzer-osv-sync", "--ecosystem", "Debian", "PyPI", "--db", str(tmp_path)]
    )
    cli.osv_sync_main()
    assert synced == ["Debian", "PyPI"]
    assert json.loads((tmp_path / ".complete").read_text()) == {
        "ecosystems": ["Debian", "PyPI"],
        "record_counts": {"Debian": 1, "PyPI": 1},
    }


def test_osv_sync_can_import_predownloaded_archives(tmp_path: Path, monkeypatch) -> None:
    imported: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        cli,
        "sync_ecosystem_archive",
        lambda eco, _db, archive, **_kwargs: imported.append((eco, archive)) or 1,
    )
    archive_dir = tmp_path / "archives"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyzer-osv-sync",
            "--ecosystem",
            "Debian",
            "Rocky Linux",
            "--archive-dir",
            str(archive_dir),
            "--db",
            str(tmp_path / "db"),
        ],
    )

    cli.osv_sync_main()

    assert imported == [
        ("Debian", archive_dir / "Debian.zip"),
        ("Rocky Linux", archive_dir / "Rocky Linux.zip"),
    ]


def test_osv_sync_index_only_discards_expanded_json(tmp_path: Path, monkeypatch) -> None:
    retain_json: list[bool] = []
    monkeypatch.setattr(
        cli,
        "sync_ecosystem",
        lambda _eco, _db, **kwargs: retain_json.append(kwargs["retain_json"]) or 1,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyzer-osv-sync",
            "--ecosystem",
            "PyPI",
            "--index-only",
            "--db",
            str(tmp_path),
        ],
    )

    cli.osv_sync_main()

    assert retain_json == [False]


def test_osv_sync_refuses_zero_record_ecosystem_and_writes_no_marker(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(cli, "sync_ecosystem", lambda _eco, _db, **_kwargs: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        ["analyzer-osv-sync", "--ecosystem", "Debian", "--db", str(tmp_path)],
    )

    with pytest.raises(SystemExit):
        cli.osv_sync_main()

    assert not (tmp_path / ".complete").exists()


def test_osv_verify_only_checks_manifest_against_loaded_ecosystem_counts(
    tmp_path: Path, monkeypatch
) -> None:
    debian = tmp_path / "Debian"
    debian.mkdir()
    (debian / "one.json").write_text(
        json.dumps(
            {
                "id": "CVE-VERIFY",
                "affected": [
                    {
                        "package": {"ecosystem": "Debian:12", "name": "sample"},
                        "versions": ["1.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    marker = tmp_path / ".complete"
    marker.write_text(
        json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 1}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyzer-osv-sync",
            "--verify-only",
            "--ecosystem",
            "Debian",
            "--db",
            str(tmp_path),
        ],
    )
    cli.osv_sync_main()

    marker.write_text(
        json.dumps({"ecosystems": ["Debian"], "record_counts": {"Debian": 2}}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        cli.osv_sync_main()


def test_empty_osv_store_warns_at_startup(tmp_path: Path, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="analyzer.api"):
        create_app(data_dir=tmp_path, osv_dir=tmp_path / "no-such-osv")
    assert any(
        "OSV store" in r.message and "empty" in r.message and "DISABLED" in r.message
        for r in caplog.records
    ), "an empty OSV store must warn at startup so detection-off isn't read as 'clean'"


def test_populated_osv_store_does_not_warn(tmp_path: Path, caplog) -> None:
    osv = tmp_path / "osv" / "npm"
    osv.mkdir(parents=True)
    record = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "x"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    (osv / "GHSA-x.json").write_text(json.dumps(record), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="analyzer.api"):
        create_app(data_dir=tmp_path, osv_dir=tmp_path / "osv")
    assert not any("OSV store" in r.message and "empty" in r.message for r in caplog.records)


def test_debian_tracker_verify_rejects_stale_unless_explicitly_allowed(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "tracker.json"
    source.write_text(
        json.dumps(
            {
                "sample": {
                    "CVE-2099-0001": {
                        "releases": {
                            "trixie": {
                                "status": "open",
                                "repositories": {"trixie": "1.0"},
                            }
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    tracker = tmp_path / "tracker"
    sync_debian_tracker(tracker, json_file=source)
    old_sync = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with sqlite3.connect(tracker / "index.sqlite3") as connection:
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'synced_at'",
            (old_sync,),
        )
        connection.commit()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "analyzer-debian-tracker-sync",
            "--verify-only",
            "--max-age-hours",
            "1",
            "--db",
            str(tracker),
        ],
    )
    with pytest.raises(SystemExit):
        cli.debian_tracker_sync_main()

    sys.argv.append("--allow-stale")
    cli.debian_tracker_sync_main()
