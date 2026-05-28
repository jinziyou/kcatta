"""Persistence backends used by form's ingest pipeline."""

from .jsonl import JsonlStore

__all__ = ["JsonlStore"]
