"""Storage failures that API callers can classify without backend coupling."""

from __future__ import annotations


class StorageCapacityError(RuntimeError):
    """The configured durable-storage budget cannot accept another record."""


class StorageCursorError(ValueError):
    """A storage cursor is malformed or no longer belongs to the retained snapshot."""
