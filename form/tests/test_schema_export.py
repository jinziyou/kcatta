"""Form public schema/OpenAPI exports are deterministic and committed in sync."""

from __future__ import annotations

from pathlib import Path

from kcatta_form.schema_export import (
    DEFAULT_OPENAPI,
    DEFAULT_OUTPUT,
    EXPORTABLE,
    export_openapi,
    export_schemas,
)


def test_openapi_export_is_deterministic_and_committed(tmp_path: Path) -> None:
    first = export_openapi(tmp_path / "first.json").read_text(encoding="utf-8")
    second = export_openapi(tmp_path / "second.json").read_text(encoding="utf-8")

    assert first == second
    assert DEFAULT_OPENAPI.read_text(encoding="utf-8") == first


def test_openapi_export_never_reconciles_configured_runtime_data(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    live_data = tmp_path / "live-data"
    spool = live_data / "scan-artifacts"
    spool.mkdir(parents=True)
    sentinel = spool / "orphan.json"
    sentinel.write_text("operator sentinel", encoding="utf-8")
    monkeypatch.setenv("FORM_DATA_DIR", str(live_data))

    export_openapi(tmp_path / "contract.json")

    assert sentinel.read_text(encoding="utf-8") == "operator sentinel"


def test_public_schema_exports_are_committed_in_sync(tmp_path: Path) -> None:
    written = export_schemas(tmp_path)

    assert {path.stem.removesuffix(".schema") for path in written} == set(EXPORTABLE)
    for fresh in written:
        committed = DEFAULT_OUTPUT / fresh.name
        assert committed.read_text(encoding="utf-8") == fresh.read_text(encoding="utf-8")


def test_control_plane_models_are_part_of_public_contract() -> None:
    assert {
        "AgentIdentity",
        "ScanTarget",
        "ScanTargetInput",
        "ScanJob",
        "TriggerScanRequest",
        "CredentialInfo",
        "CredentialActionRequest",
        "CredentialTestResult",
        "CredentialRevokeResult",
        "GuardLifecycleStatus",
    } <= set(EXPORTABLE)
