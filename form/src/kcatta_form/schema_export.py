"""Export Form's public JSON Schema contracts."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .schemas import (
    AgentIdentity,
    Alert,
    AssetReport,
    AttackPath,
    CapabilityGraph,
    CredentialActionRequest,
    CredentialInfo,
    CredentialRevokeResult,
    CredentialTestResult,
    DetectionResult,
    GuardEventBatch,
    GuardLifecycleStatus,
    ScanJob,
    ScanTarget,
    ScanTargetInput,
    TraceBatch,
    TriggerScanRequest,
)

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"
DEFAULT_OPENAPI = Path(__file__).resolve().parents[2] / "openapi.json"

EXPORTABLE: dict[str, type] = {
    "AgentIdentity": AgentIdentity,
    "AssetReport": AssetReport,
    "TraceBatch": TraceBatch,
    "GuardEventBatch": GuardEventBatch,
    "Alert": Alert,
    "DetectionResult": DetectionResult,
    "CapabilityGraph": CapabilityGraph,
    "AttackPath": AttackPath,
    "ScanTarget": ScanTarget,
    "ScanTargetInput": ScanTargetInput,
    "ScanJob": ScanJob,
    "TriggerScanRequest": TriggerScanRequest,
    "CredentialInfo": CredentialInfo,
    "CredentialActionRequest": CredentialActionRequest,
    "CredentialTestResult": CredentialTestResult,
    "CredentialRevokeResult": CredentialRevokeResult,
    "GuardLifecycleStatus": GuardLifecycleStatus,
}


def export_schemas(out_dir: Path = DEFAULT_OUTPUT) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in EXPORTABLE.items():
        path = out_dir / f"{name}.schema.json"
        path.write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def export_schemas_main() -> None:
    parser = argparse.ArgumentParser(description="Export Form public JSON Schemas")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    for path in export_schemas(args.out):
        print(f"wrote {path}")


def export_openapi(out_path: Path = DEFAULT_OPENAPI) -> Path:
    """Export Form's deterministic public HTTP contract."""
    from .api import create_app

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # App construction initializes the durable queue and reconciles its spool.
    # Contract generation must never touch FORM_DATA_DIR, which may point at a
    # live deployment when an operator runs this command.
    with tempfile.TemporaryDirectory(prefix="kcatta-form-openapi-") as temporary:
        contract = create_app(
            data_dir=Path(temporary),
            api_token="openapi-control-contract",
            ingest_token="openapi-ingest-contract",
            analyzer_token="openapi-analyzer-contract",
        ).openapi()
    out_path.write_text(
        json.dumps(
            contract,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return out_path


def export_openapi_main() -> None:
    parser = argparse.ArgumentParser(description="Export Form public OpenAPI")
    parser.add_argument("--out", type=Path, default=DEFAULT_OPENAPI)
    args = parser.parse_args()
    print(f"wrote {export_openapi(args.out)}")
