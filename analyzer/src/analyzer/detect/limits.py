"""Generation-stage limits for vulnerability-derived output."""

from __future__ import annotations

MAX_FINDINGS = 4096
# Leave 1 MiB of the per-ingest derived budget for the DetectionResult
# envelope, JSON separators, and provenance fields.
MAX_FINDING_BYTES = 3 * 1024 * 1024
