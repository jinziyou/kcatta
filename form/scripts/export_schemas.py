#!/usr/bin/env python3
"""Source-tree wrapper for ``form-export-schemas``."""

from __future__ import annotations

import sys
from pathlib import Path

_FORM_SRC = Path(__file__).resolve().parents[1] / "src"
_ANALYZER_SRC = Path(__file__).resolve().parents[2] / "analyzer" / "src"
for directory in (_FORM_SRC, _ANALYZER_SRC):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from kcatta_form.schema_export import export_schemas_main  # noqa: E402

if __name__ == "__main__":
    export_schemas_main()
