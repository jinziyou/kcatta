"""Generation-stage limits for vulnerability-derived output."""

from __future__ import annotations

from dataclasses import dataclass

MAX_FINDINGS = 4096
# Leave 1 MiB of the per-ingest derived budget for the DetectionResult
# envelope, JSON separators, and provenance fields.
MAX_FINDING_BYTES = 3 * 1024 * 1024


@dataclass
class FindingLimitState:
    """Optional completeness signals for list-returning detector APIs.

    Keeping the detector return type as ``list[Vulnerability]`` preserves the
    public API while callers that persist/display results can opt into explicit
    completeness metadata.
    """

    truncated: bool = False
    reason: str | None = None
    incomplete: bool = False
    incomplete_reason: str | None = None

    def mark(self, reason: str) -> None:
        self.truncated = True
        if self.reason is None:
            self.reason = reason

    def mark_incomplete(self, reason: str) -> None:
        """Record a non-limit omission that makes a clean result unprovable."""
        self.incomplete = True
        if self.incomplete_reason is None:
            self.incomplete_reason = reason
