"""Explicitly opt analyzer unit tests into isolated no-auth development mode."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_isolated_test_app_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANALYZER_ALLOW_INSECURE_NO_AUTH", "true")
    # Production defaults to fsync-on-ack. Unit tests exercise durability logic
    # separately and disable per-record disk barriers to keep large fixtures fast.
    monkeypatch.setenv("ANALYZER_JSONL_FSYNC", "false")
