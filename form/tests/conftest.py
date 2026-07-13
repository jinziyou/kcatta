"""Explicitly opt Form unit tests into isolated no-auth development mode."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_isolated_test_app_without_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORM_ALLOW_INSECURE_NO_AUTH", "true")
