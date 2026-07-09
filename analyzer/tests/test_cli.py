"""CLI behaviour: the default OSV sync set + the empty-store startup warning.

Network is never touched — ``sync_ecosystem`` is monkeypatched, so this exercises
the argparse default and the per-ecosystem loop offline.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from analyzer import cli
from analyzer.api import create_app


def test_default_ecosystems_cover_agent_emission_surface() -> None:
    eco = set(cli.DEFAULT_OSV_ECOSYSTEMS)
    # The GHSA-bearing language ecosystems the agent emits — syncing these covers
    # GHSA-derived findings (GHSA is merged into the PyPI/npm OSV exports).
    assert {"PyPI", "npm"} <= eco
    # The OS surface the agent's osv_ecosystem() can actually produce.
    assert {"Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "openSUSE"} <= eco
    # Dead weight stays OUT: SLES/RHEL/CentOS/Fedora (unreproducible OSV keying)
    # and language ecosystems with no agent collector.
    assert eco.isdisjoint({"SUSE", "Maven", "Go", "RubyGems", "crates.io", "NuGet", "CentOS"})


def test_osv_sync_defaults_to_full_set(tmp_path: Path, monkeypatch) -> None:
    synced: list[str] = []
    monkeypatch.setattr(cli, "sync_ecosystem", lambda eco, db: synced.append(eco) or 0)
    monkeypatch.setattr(sys, "argv", ["analyzer-osv-sync", "--db", str(tmp_path)])
    cli.osv_sync_main()
    assert synced == list(cli.DEFAULT_OSV_ECOSYSTEMS)


def test_osv_sync_explicit_list_overrides_default(tmp_path: Path, monkeypatch) -> None:
    synced: list[str] = []
    monkeypatch.setattr(cli, "sync_ecosystem", lambda eco, db: synced.append(eco) or 0)
    monkeypatch.setattr(
        sys, "argv", ["analyzer-osv-sync", "--ecosystem", "Debian", "PyPI", "--db", str(tmp_path)]
    )
    cli.osv_sync_main()
    assert synced == ["Debian", "PyPI"]


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
