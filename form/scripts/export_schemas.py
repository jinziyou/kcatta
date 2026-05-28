#!/usr/bin/env python3
"""Convenience wrapper around the `form-export-schemas` entry point.

Useful when the project is not yet installed (e.g. in CI before the
editable install). Run from the `form/` directory:

    PYTHONPATH=src python scripts/export_schemas.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from form.cli import export_schemas_main  # noqa: E402

if __name__ == "__main__":
    export_schemas_main()
