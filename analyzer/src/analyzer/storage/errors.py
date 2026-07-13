"""Storage failures that API callers can classify without backend coupling."""

from __future__ import annotations


class StorageCapacityError(RuntimeError):
    """The configured durable-storage budget cannot accept another record."""
