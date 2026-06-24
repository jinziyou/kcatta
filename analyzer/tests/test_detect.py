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

from analyzer.detect import OsvStore, detect_report, ecosystem_for_os
from analyzer.detect.debversion import dpkg_compare
from analyzer.detect.osv import OsvRecord, is_version_affected
from analyzer.schemas import AssetReport

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


def test_cvss_v4_only_critical_not_downgraded_to_medium(tmp_path: Path) -> None:
    # C2 regression: a CVE that ships only a CVSS_V4 vector (no v3, no severity
    # word) used to fall through to MEDIUM. A v4 full-impact/network vector is a
    # critical and must be reported as such.
    record = dict(OSV_OPENSSL)
    record.pop("database_specific", None)  # no severity word at all
    record["severity"] = [
        {
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        }
    ]
    db = tmp_path / "osv" / "Debian"
    db.mkdir(parents=True)
    (db / "v4only.json").write_text(json.dumps(record), encoding="utf-8")
    store = OsvStore.load_dir(tmp_path / "osv")

    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    assert vulns[0].severity == "critical"
    # We do not reproduce the v4 numeric base score, so cvss_score stays None ...
    assert vulns[0].cvss_score is None
    # ... but the qualitative severity is correct, which is what triage uses.


def test_cvss_v4_base_severity_word_fallback(tmp_path: Path) -> None:
    # When a v4 entry carries an explicit baseSeverity word, it is honoured as a
    # severity-word fallback rather than defaulting to MEDIUM.
    record = dict(OSV_OPENSSL)
    record.pop("database_specific", None)
    record["severity"] = [{"type": "CVSS_V4", "baseSeverity": "CRITICAL"}]  # no parseable vector
    db = tmp_path / "osv" / "Debian"
    db.mkdir(parents=True)
    (db / "v4word.json").write_text(json.dumps(record), encoding="utf-8")
    store = OsvStore.load_dir(tmp_path / "osv")

    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    assert vulns[0].severity == "critical"


def test_withdrawn_advisory_is_skipped(tmp_path: Path) -> None:
    # Q1: a withdrawn advisory must never match — indexing it would produce a
    # false positive that never ages out. It is also not counted by the store.
    record = dict(OSV_OPENSSL)
    record["id"] = "DSA-TEST-withdrawn"
    record["withdrawn"] = "2024-01-01T00:00:00Z"
    store = _write_one(tmp_path, "Debian", record)

    assert store.record_count == 0
    assert detect_report(_report("3.0.2-0"), store, ECOSYSTEM) == []


def test_cvss_picks_worst_of_multiple_v3_vectors(tmp_path: Path) -> None:
    # Q1: a record may list several CVSS_V3 vectors (e.g. NVD + a distro feed).
    # Severity must reflect the worst, not whichever is listed first.
    record = dict(OSV_OPENSSL)
    record.pop("database_specific", None)
    record["severity"] = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},  # low
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},  # 9.8
    ]
    store = _write_one(tmp_path, "Debian", record)

    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    # The 9.8 vector wins despite being listed second.
    assert vulns[0].cvss_score == 9.8
    assert vulns[0].severity == "critical"


def test_severity_is_max_of_word_and_vector(tmp_path: Path) -> None:
    # Q1: signals can disagree — a distro rates this Critical while the attached
    # v3 vector computes a low score. Taking the max means the finding is not
    # silently downgraded to the vector's severity, while the numeric score is
    # still reported faithfully.
    record = dict(OSV_OPENSSL)
    record["database_specific"] = {"severity": "Critical"}
    record["severity"] = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},  # ~1.6
    ]
    store = _write_one(tmp_path, "Debian", record)

    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    # Numeric score is preserved and low ...
    assert vulns[0].cvss_score is not None
    assert vulns[0].cvss_score < 4.0
    # ... but the reported severity is the worst signal: the Critical word.
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


def test_host_package_vuln_has_no_parent(tmp_path: Path) -> None:
    # Q5: a host-level package finding is not attributed to any image/container.
    store = _write_store(tmp_path)
    vulns = detect_report(_report("3.0.2-0"), store, ECOSYSTEM)
    assert len(vulns) == 1
    assert vulns[0].parent_asset_id is None


def test_image_package_vuln_carries_parent_asset_id(tmp_path: Path) -> None:
    # Q5: a package from a nested image/container scan propagates its owning
    # image/container asset_id onto the finding, so the console can group per image.
    store = _write_store(tmp_path)
    report = AssetReport.model_validate(
        {
            "report_id": "r-img",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h-1", "hostname": "n", "os": "Debian GNU/Linux 12 (bookworm)"},
            "assets": [
                {
                    "kind": "package",
                    "asset_id": "img-docker-abc123::pkg-openssl",
                    "name": "openssl",
                    "version": "3.0.2-0",
                    "parent_asset_id": "img-docker-abc123",
                }
            ],
            "vulnerabilities": [],
        }
    )
    vulns = detect_report(report, store, ECOSYSTEM)
    assert len(vulns) == 1
    assert vulns[0].parent_asset_id == "img-docker-abc123"
    assert vulns[0].affected_asset_id == "img-docker-abc123::pkg-openssl"


def test_wrong_ecosystem_not_detected(tmp_path: Path) -> None:
    store = _write_store(tmp_path)
    assert detect_report(_report("3.0.2-0"), store, "Debian:11") == []


@pytest.mark.parametrize(
    ("os_string", "expected"),
    [
        ("Ubuntu 22.04", "Ubuntu:22.04"),
        ("Debian GNU/Linux 12 (bookworm)", "Debian:12"),
        ("Windows 11 Pro 22H2", "Windows:11"),
        ("Windows 10 Pro", "Windows:10"),
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


# A GHSA advisory with NO CVE alias — common for ecosystem-specific npm/PyPI
# issues. OSV merges these into the language exports; matching keys on
# (ecosystem, name) with no id-prefix filter, so it must surface under its own
# GHSA id (primary_id falls back to the OSV id when no CVE alias exists).
OSV_NPM_GHSA_ONLY = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": [],
    "database_specific": {"severity": "High"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "left-pad"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "1.3.0"}],
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


def test_ghsa_only_advisory_surfaces_under_ghsa_id(tmp_path: Path) -> None:
    # GHSA advisories ride inside the npm/PyPI OSV exports; one without a CVE
    # alias must still be matched and reported under its GHSA id — proving GHSA
    # coverage comes free with syncing PyPI/npm (no separate feed needed).
    store = _write_one(tmp_path, "npm", OSV_NPM_GHSA_ONLY)
    vulns = detect_report(_lang_report("npm", "left-pad", "1.2.0"), store, "npm")
    assert len(vulns) == 1
    assert vulns[0].vuln_id == "GHSA-aaaa-bbbb-cccc"
    assert vulns[0].severity == "high"
    # Fixed version is not affected.
    assert detect_report(_lang_report("npm", "left-pad", "1.3.0"), store, "npm") == []


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


def test_multi_range_reports_nearest_fixed_version() -> None:
    # Two disjoint affected intervals [1.0,2.0) and [3.0,4.0). Regression: the
    # reported fixed version used to be overwritten by the LAST fixed (4.0) for
    # a version in the first interval; it must be that interval's own fixed.
    record = OsvRecord.from_dict(
        {
            "id": "X",
            "affected": [
                {
                    "package": {"ecosystem": ECOSYSTEM, "name": "p"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "1.0"},
                                {"fixed": "2.0"},
                                {"introduced": "3.0"},
                                {"fixed": "4.0"},
                            ],
                        }
                    ],
                }
            ],
        }
    )
    entry = record.affected_entries(ECOSYSTEM, "p")[0]
    assert is_version_affected("1.5", entry, dpkg_compare) == (True, "2.0")
    assert is_version_affected("3.5", entry, dpkg_compare) == (True, "4.0")
    assert is_version_affected("2.5", entry, dpkg_compare) == (False, None)  # gap
    assert is_version_affected("4.0", entry, dpkg_compare)[0] is False


def _posture_report() -> AssetReport:
    """An AssetReport carrying agent-attached findings: a posture misconfig, a
    malware hit, and a finding from an unknown source that must NOT be surfaced."""
    return AssetReport.model_validate(
        {
            "report_id": "r-posture",
            "collected_at": datetime(2026, 5, 29, tzinfo=UTC).isoformat(),
            "scanner_version": "0.1.0",
            "host": {"host_id": "h-9", "hostname": "n", "os": "Debian GNU/Linux 12"},
            "assets": [],
            "vulnerabilities": [
                {
                    "vuln_id": "POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES",
                    "severity": "high",
                    "affected_asset_id": "h-9",
                    "source": "posture",
                    "evidence": "/etc/ssh/sshd_config:1: `PermitRootLogin yes`",
                },
                {
                    "vuln_id": "EICAR-Test-File",
                    "severity": "critical",
                    "affected_asset_id": "h-9",
                    "source": "kcatta-malware",
                    "evidence": "infected file",
                },
                {
                    "vuln_id": "SOMETHING-ELSE",
                    "severity": "low",
                    "affected_asset_id": "h-9",
                    "source": "some-unknown-tool",
                },
            ],
        }
    )


def test_scanner_findings_surfaces_posture_not_unknown_sources() -> None:
    from analyzer.detect.combine import combine_findings, scanner_findings

    found = scanner_findings(_posture_report())
    ids = {v.vuln_id for v in found}
    assert "POSTURE-SSHD-PERMIT-ROOT-LOGIN-YES" in ids, "posture findings must surface"
    assert "EICAR-Test-File" in ids, "malware findings still surface"
    assert "SOMETHING-ELSE" not in ids, "an unknown source must NOT be trusted into results"
    # And they flow through combine_findings (OSV first, then scanner-native).
    combined = combine_findings([], found)
    assert {v.vuln_id for v in combined} == ids
