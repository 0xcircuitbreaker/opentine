"""The remote audit chain, published over ``opentine-log/1`` (0.44, X33).

The keyed SQLite chain (:mod:`._audit`) can only be checked by the server,
which holds its HMAC key. Every committed row is therefore also appended to a
signed tlog-tiles log beside the database (``<db>.tlog``), whose checkpoints
anyone can verify: a client keeps the last one it saw per remote and refuses a
fetch whose new checkpoint is not provably an extension of it (fork, rollback),
and a push gets an inclusion receipt for its own ``update_ref`` row.

An entry is canonical JSON ``{action, event_id, format, outcome, row_hash,
tenant, timestamp[, name, new]}``: the row's keyed hash binds the full row
(actor and details included) without publishing them. The origin is
``opentine.remote/log/audit/<16 hex>``, random per server, so two servers never
share a witness state. Proof endpoints return hashes only; a receipt is given
only for the caller's own tenant.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from opentine.kernel import _parse_int, canonical_json
from opentine.repository import _tlog, _tlog_note, _tlog_proof, _tlog_receipt
from opentine.repository._paths import atomic_bytes, durable_directory

ENTRY_FORMAT = "opentine-audit/1"
ORIGIN_PREFIX = "opentine.remote/log/audit/"


def tlog_root(audit: Any) -> Path | None:
    path = getattr(audit, "path", None)
    return Path(str(path) + ".tlog") if path is not None else None


def origin(root: Path) -> str:
    marker = root / "origin"
    try:
        return marker.read_text("ascii").strip()
    except FileNotFoundError:
        durable_directory(root)
        atomic_bytes(marker, (ORIGIN_PREFIX + secrets.token_hex(8) + "\n").encode())
        return marker.read_text("ascii").strip()


def entry(row: dict[str, str], row_hash: str) -> bytes:
    body = {k: row[k] for k in ("action", "event_id", "outcome", "tenant", "timestamp")}
    if row["action"] == "update_ref":
        details = json.loads(row["details"], parse_int=_parse_int)
        body.update(name=details.get("name"), new=details.get("new"))
    return canonical_json({**body, "format": ENTRY_FORMAT, "row_hash": row_hash})


PUBLISH_ATTEMPTS = 3


class PublishError(RuntimeError):
    """The audit row committed but its transparency entry could not be appended."""


def publish(audit: Any, row: dict[str, str], row_hash: str) -> None:
    """Append a committed row to the transparency log, retrying; raise if it cannot.

    0.44 only warned, so a server could acknowledge a write its public log never
    showed. From 0.45 a failed append is retried (``PUBLISH_ATTEMPTS``, short
    backoff, which rides out a concurrent writer's lock) and then fails the
    request with :class:`PublishError`. The row itself stays committed: the audit
    chain is the record of truth, and the gap is visible to a monitor because
    every entry carries its ``row_hash`` (``docs/design/log-2.md``).
    """
    root = tlog_root(audit)
    if root is None:
        return
    for attempt in range(PUBLISH_ATTEMPTS):
        try:
            _tlog_note.append(root, origin(root), lambda _entries: entry(row, row_hash))
            return
        except (OSError, ValueError) as exc:
            failure = exc
            time.sleep(0.01 * (2**attempt))
    message = f"audit transparency append failed after {PUBLISH_ATTEMPTS} attempts: {failure}"
    print(f"opentine-remote: {message}", file=sys.stderr)
    raise PublishError(message) from failure


def _hashes(root: Path, size: int) -> _tlog_proof.Hashes:
    return _tlog_proof.Hashes(size, lambda rel: _tlog._read(root, rel))


def respond(audit: Any, tenant: str, what: str, query: dict[str, str]) -> dict[str, Any] | None:
    """Body of ``GET /v1/tenants/<t>/transparency/<what>``; None is a 404."""
    root = tlog_root(audit)
    if root is None or not (root / "checkpoint").exists():
        return None
    log_origin = origin(root)
    note = (root / "checkpoint").read_bytes()
    _, size, _ = _tlog_note.open_checkpoint(note, _tlog_note.stored_vkey(root))
    base = {"checkpoint": note.decode("utf-8"), "size": size, "vkey": _tlog_note.stored_vkey(root)}
    if what == "checkpoint":
        return base
    if what == "consistency":
        old, new = int(query.get("old", "0")), int(query.get("new", str(size)))
        proof = _tlog_proof.consistency_proof(_hashes(root, size), old, new) if old <= new else []
        return {**base, "new": new, "old": old, "proof": _tlog_proof.encode(proof)}
    if what == "receipt":
        entries = _tlog_note.verify_log(root, log_origin)
        for index in range(len(entries) - 1, -1, -1):
            item = json.loads(entries[index])
            if (item.get("tenant"), item.get("name"), item.get("new")) == (
                tenant, query.get("name"), query.get("new")
            ) and item.get("outcome") in ("ok", "forced"):  # fmt: skip
                return _tlog_receipt.make(root, log_origin, index)
        return None
    return None
