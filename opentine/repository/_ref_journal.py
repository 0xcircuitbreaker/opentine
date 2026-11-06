"""The on-disk ref-transaction journal format and its validation (:mod:`._ref_txn`)."""

from __future__ import annotations

import json
from pathlib import Path

from opentine.kernel import KernelError, parse_oid
from opentine.repository._refs import normalize_ref, validate_ref_oid, validate_ref_target

TXN_FORMAT = "opentine-ref-txn/1"
MAX_TXN_REFS = 4096
MAX_JOURNAL_BYTES = 4 * 1024 * 1024


def parse_journal(base: Path, raw: bytes, txn_id: str) -> dict:
    """A journal's record, or ``ValueError``: every field is checked before use."""
    from opentine.repository.store import Repo

    if len(raw) > MAX_JOURNAL_BYTES:
        raise ValueError("journal exceeds its size limit")
    record = json.loads(raw)
    if not isinstance(record, dict) or set(record) != {"actor", "format", "id", "updates"}:
        raise ValueError("journal has the wrong fields")
    if record["format"] != TXN_FORMAT or record["id"] != txn_id:
        raise ValueError("journal format or id mismatch")
    if not isinstance(record["actor"], str) or len(record["actor"]) > 4096:
        raise ValueError("journal actor is malformed")
    rows = record["updates"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TXN_REFS:
        raise ValueError("journal updates are malformed")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"new", "old", "ref"}:
            raise ValueError("journal row has the wrong fields")
        if not isinstance(row["ref"], str) or normalize_ref(row["ref"]) != row["ref"]:
            raise ValueError("journal names an illegal ref")
        if row["ref"] in seen:
            raise ValueError("journal names a ref twice")
        seen.add(row["ref"])
        if not isinstance(row["new"], str) or not isinstance(row["old"], (str, type(None))):
            raise ValueError("journal values are malformed")
        if row["old"] is not None:
            parse_oid(row["old"])
        validate_ref_oid(row["ref"], row["new"])
        try:  # the same target rules update_refs checked before writing it
            target = Repo(base).get(row["new"])
        except (KeyError, KernelError, OSError) as exc:
            raise ValueError("journal names an object the repository cannot read") from exc
        validate_ref_target(row["ref"], target.object_type, target.payload())
    return record
