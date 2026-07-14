"""Tamper-evident hash chaining for the SQLite audit log.

Each row commits to the previous row's hash, so any modification, deletion, or
reordering of an interior row breaks the chain and is detectable by
``verify_audit_chain``. Truncation from the end is only detectable against a
``expected_head`` checkpoint that was anchored/exported out of band, so operators
who need full tamper-proofing should periodically persist ``audit_head()``.
"""

from __future__ import annotations

import hashlib

from opentine.kernel import canonical_json

#: All-zero hash that seeds an empty chain.
GENESIS = "0" * 64

#: Column order used for both writing and verifying a row's committed body.
FIELDS = ("action", "actor", "details", "event_id", "outcome", "tenant", "timestamp")


def chain(prev_hash: str, row: dict[str, str]) -> str:
    """Return the hash committing ``row`` to ``prev_hash`` (a 64-char hex digest)."""
    body = canonical_json({field: row[field] for field in FIELDS})
    return hashlib.sha256(bytes.fromhex(prev_hash) + body).hexdigest()
