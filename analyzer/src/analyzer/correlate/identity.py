"""Stable, content-derived alert identity (``alert_key``).

An ``alert_key`` is a hash over the *content* that defines a finding — its
indicator, type, and the hosts involved — deliberately **excluding the
batch_id**. The same indicator seen across many ``TraceBatch``es therefore
collapses to one triageable alert instead of a fresh alert per batch, which is
what lets triage state (status / assignee / note / suppress) and de-duplication
key on it.
"""

from __future__ import annotations

import hashlib

# Unit Separator: a delimiter that cannot appear in the indicator/host strings,
# so distinct part tuples can never hash to the same key by concatenation.
_SEP = "\x1f"


def alert_key_for(*parts: str) -> str:
    """Derive a stable ``alert_key`` from the content parts that define an alert."""
    digest = hashlib.sha1(_SEP.join(parts).encode("utf-8")).hexdigest()
    return f"ak-{digest[:24]}"
