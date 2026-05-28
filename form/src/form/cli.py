"""CLI entry points for the form package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .schemas import Alert, AssetReport, FlowBatch

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "schemas-json"

EXPORTABLE: dict[str, type] = {
    "AssetReport": AssetReport,
    "FlowBatch": FlowBatch,
    "Alert": Alert,
}


def export_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in EXPORTABLE.items():
        schema = model.model_json_schema()
        path = out_dir / f"{name}.schema.json"
        path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def export_schemas_main() -> None:
    parser = argparse.ArgumentParser(
        description="Export JSON Schemas for cyber-posture data contracts",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output directory (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    paths = export_schemas(args.out)
    for p in paths:
        print(f"wrote {p}")
