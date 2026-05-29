"""Detection engine tests over a fixture OSV store.

Builds a tiny on-disk OSV store and an AssetReport, then asserts which
package versions match an advisory (introduced/fixed range) and how the
finding maps to the Vulnerability contract.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from form.detect import OsvStore, detect_report, ecosystem_for_os
from form.detect.debversion import dpkg_compare
from form.detect.osv import OsvRecord, is_version_affected
from form.schemas import AssetReport

ECOSYSTEM = "Debian:12"

OSV_OPENSSL = {
    "id": "DSA-TEST-openssl",
    "aliases": ["CVE-2099-0001"],
    "database_specific": {"severity": "High"},
    "references": [{"type": "ADVISORY", "url": "https://example.test/dsa"}],
    "affected": [
        {
            "package": {"ecosystem": ECOSYSTEM, "name": "openssl"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.2-1"}],
                }
            ],
        }
    ],
}


def _write_store(tmp_path: Path) -> OsvStore:
    db = tmp_path / "osv" / "Debian"
    db.mkdir(parents=True)
    (db / "DSA-TEST-openssl.json").write_text(json.dumps(OSV_OPENSSL), encoding="utf-8")
    return OsvStore.load_dir(tmp_path / "osv")


def _report(openssl_version: str) -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "r-1",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h-1", "hostname": "n", "os": "Debian GNU/Linux 12 (bookworm)"},
            "assets": [
                {
                    "kind": "package",
                    "asset_id": "pkg-openssl",
                    "name": "openssl",
                    "version": openssl_version,
                }
            ],
            "vulnerabilities": [],
        }
    )


def test_vulnerable_version_is_detected(tmp_path: Path) -> None:
    store = _write_store(tmp_path)
    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)

    assert len(vulns) == 1
    v = vulns[0]
    assert v.vuln_id == "CVE-2099-0001"  # CVE alias preferred over OSV id
    assert v.severity == "high"
    assert v.affected_asset_id == "pkg-openssl"
    assert v.source == "osv"
    assert "fixed in 3.0.2-1" in v.evidence
    assert "https://osv.dev/vulnerability/DSA-TEST-openssl" in v.references


def test_cvss_vector_sets_score_and_severity(tmp_path: Path) -> None:
    record = dict(OSV_OPENSSL)
    record["severity"] = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ]
    db = tmp_path / "osv" / "Debian"
    db.mkdir(parents=True)
    (db / "rec.json").write_text(json.dumps(record), encoding="utf-8")
    store = OsvStore.load_dir(tmp_path / "osv")

    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    # CVSS-derived score wins over the "High" database_specific word.
    assert vulns[0].cvss_score == 9.8
    assert vulns[0].severity == "critical"


def test_fixed_version_not_detected(tmp_path: Path) -> None:
    store = _write_store(tmp_path)
    assert detect_report(_report("3.0.2-1"), store, ECOSYSTEM) == []
    assert detect_report(_report("3.0.2-2"), store, ECOSYSTEM) == []


def test_unknown_package_not_detected(tmp_path: Path) -> None:
    store = _write_store(tmp_path)
    report = _report("3.0.2-0")
    report.assets[0].name = "curl"
    assert detect_report(report, store, ECOSYSTEM) == []


def test_wrong_ecosystem_not_detected(tmp_path: Path) -> None:
    store = _write_store(tmp_path)
    assert detect_report(_report("3.0.2-0"), store, "Debian:11") == []


@pytest.mark.parametrize(
    ("os_string", "expected"),
    [
        ("Ubuntu 22.04", "Ubuntu:22.04"),
        ("Debian GNU/Linux 12 (bookworm)", "Debian:12"),
        ("Kali GNU/Linux Rolling", None),
    ],
)
def test_ecosystem_for_os(os_string: str, expected: str | None) -> None:
    assert ecosystem_for_os(os_string) == expected


def test_explicit_versions_list_matches() -> None:
    entry = {
        "package": {"ecosystem": ECOSYSTEM, "name": "bash"},
        "versions": ["5.1-2", "5.1-3"],
    }
    affected, fixed = is_version_affected("5.1-2", entry, dpkg_compare)
    assert affected is True
    assert fixed is None


OSV_NPM_LODASH = {
    "id": "GHSA-test-lodash",
    "aliases": ["CVE-2099-2222"],
    "database_specific": {"severity": "High"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
        }
    ],
}

OSV_PYPI_DJANGO = {
    "id": "GHSA-test-django",
    "aliases": ["CVE-2099-3333"],
    "database_specific": {"severity": "Critical"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "4.0"}, {"fixed": "4.2.3"}],
                }
            ],
        }
    ],
}


def _lang_report(ecosystem_dir: str, name: str, version: str) -> AssetReport:
    return AssetReport.model_validate(
        {
            "report_id": "r-2",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h-2", "hostname": "n", "os": "container"},
            "assets": [
                {"kind": "package", "asset_id": f"pkg-{name}", "name": name, "version": version}
            ],
            "vulnerabilities": [],
        }
    )


def _write_one(tmp_path: Path, subdir: str, record: dict) -> OsvStore:
    db = tmp_path / "osv" / subdir
    db.mkdir(parents=True)
    (db / f"{record['id']}.json").write_text(json.dumps(record), encoding="utf-8")
    return OsvStore.load_dir(tmp_path / "osv")


def test_npm_semver_range_detected(tmp_path: Path) -> None:
    store = _write_one(tmp_path, "npm", OSV_NPM_LODASH)
    # 4.9.0 (semver) must read as < 4.17.21, not lexically greater.
    vulns = detect_report(_lang_report("npm", "lodash", "4.9.0"), store, "npm")
    assert len(vulns) == 1
    assert vulns[0].vuln_id == "CVE-2099-2222"
    # Fixed version is detected as not affected.
    assert detect_report(_lang_report("npm", "lodash", "4.17.21"), store, "npm") == []


def test_pypi_pep440_range_detected(tmp_path: Path) -> None:
    store = _write_one(tmp_path, "PyPI", OSV_PYPI_DJANGO)
    vulns = detect_report(_lang_report("PyPI", "django", "4.2"), store, "PyPI")
    assert len(vulns) == 1
    assert vulns[0].vuln_id == "CVE-2099-3333"
    assert vulns[0].severity == "critical"
    assert detect_report(_lang_report("PyPI", "django", "4.2.3"), store, "PyPI") == []
    # 3.2 is below the introduced bound -> not affected.
    assert detect_report(_lang_report("PyPI", "django", "3.2"), store, "PyPI") == []


def test_mixed_ecosystem_per_package(tmp_path: Path) -> None:
    # One store holding both a Debian and an npm advisory.
    osv = tmp_path / "osv"
    (osv / "Debian").mkdir(parents=True)
    (osv / "Debian" / "openssl.json").write_text(json.dumps(OSV_OPENSSL), encoding="utf-8")
    (osv / "npm").mkdir(parents=True)
    (osv / "npm" / "lodash.json").write_text(json.dumps(OSV_NPM_LODASH), encoding="utf-8")
    store = OsvStore.load_dir(osv)

    report = AssetReport.model_validate(
        {
            "report_id": "r-mix",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h", "hostname": "n", "os": "Debian GNU/Linux 12 (bookworm)"},
            "assets": [
                # OS package: no explicit ecosystem -> falls back to the host default.
                {
                    "kind": "package",
                    "asset_id": "pkg-openssl",
                    "name": "openssl",
                    "version": "3.0.2-0",
                },
                # Language package: carries its own ecosystem.
                {
                    "kind": "package",
                    "asset_id": "pkg-lodash",
                    "name": "lodash",
                    "version": "4.9.0",
                    "ecosystem": "npm",
                },
            ],
            "vulnerabilities": [],
        }
    )

    # Host default applies to the deb package; the npm package uses its own ecosystem.
    vulns = detect_report(report, store, ECOSYSTEM)
    ids = {v.vuln_id for v in vulns}
    assert ids == {"CVE-2099-0001", "CVE-2099-2222"}


def test_package_ecosystem_used_without_host_default(tmp_path: Path) -> None:
    store = _write_one(tmp_path, "npm", OSV_NPM_LODASH)
    report = AssetReport.model_validate(
        {
            "report_id": "r-nohost",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h", "hostname": "n", "os": "unknown"},
            "assets": [
                {
                    "kind": "package",
                    "asset_id": "pkg-lodash",
                    "name": "lodash",
                    "version": "4.9.0",
                    "ecosystem": "npm",
                }
            ],
            "vulnerabilities": [],
        }
    )
    # No host ecosystem passed; package's own ecosystem still drives matching.
    vulns = detect_report(report, store)
    assert {v.vuln_id for v in vulns} == {"CVE-2099-2222"}


OSV_ROCKY_NGINX = {
    "id": "RLSA-TEST-nginx",
    "aliases": ["CVE-2099-4444"],
    "database_specific": {"severity": "High"},
    "affected": [
        {
            "package": {"ecosystem": "Rocky Linux:9", "name": "nginx"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1:1.20.4-2.el9"}],
                }
            ],
        }
    ],
}

OSV_ALPINE_OPENSSL = {
    "id": "CVE-2099-5555",
    "database_specific": {"severity": "Critical"},
    "affected": [
        {
            "package": {"ecosystem": "Alpine:v3.18", "name": "openssl"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.1.4-r2"}],
                }
            ],
        }
    ],
}


def test_rpm_evr_range_detected(tmp_path: Path) -> None:
    store = _write_one(tmp_path, "Rocky", OSV_ROCKY_NGINX)
    eco = "Rocky Linux:9"
    # 1:1.20.4-1.el9 < fixed 1:1.20.4-2.el9 -> affected.
    vulns = detect_report(_lang_report(eco, "nginx", "1:1.20.4-1.el9"), store, eco)
    assert {v.vuln_id for v in vulns} == {"CVE-2099-4444"}
    assert detect_report(_lang_report(eco, "nginx", "1:1.20.4-2.el9"), store, eco) == []


def test_apk_range_detected(tmp_path: Path) -> None:
    store = _write_one(tmp_path, "Alpine", OSV_ALPINE_OPENSSL)
    eco = "Alpine:v3.18"
    # 3.1.4-r1 < fixed 3.1.4-r2 (revision compare, not semver prerelease).
    vulns = detect_report(_lang_report(eco, "openssl", "3.1.4-r1"), store, eco)
    assert {v.vuln_id for v in vulns} == {"CVE-2099-5555"}
    assert detect_report(_lang_report(eco, "openssl", "3.1.4-r2"), store, eco) == []


def test_semver_range_skipped_without_semver_comparator() -> None:
    entry = OSV_NPM_LODASH["affected"][0]
    # No semver comparator supplied -> SEMVER ranges are ignored.
    affected, _ = is_version_affected("4.9.0", entry, dpkg_compare)
    assert affected is False


def test_last_affected_range() -> None:
    record = OsvRecord.from_dict(
        {
            "id": "X",
            "affected": [
                {
                    "package": {"ecosystem": ECOSYSTEM, "name": "p"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0"}, {"last_affected": "2.0"}],
                        }
                    ],
                }
            ],
        }
    )
    entry = record.affected_entries(ECOSYSTEM, "p")[0]
    assert is_version_affected("1.5", entry, dpkg_compare)[0] is True
    assert is_version_affected("2.0", entry, dpkg_compare)[0] is True
    assert is_version_affected("2.1", entry, dpkg_compare)[0] is False
    assert is_version_affected("0.9", entry, dpkg_compare)[0] is False
