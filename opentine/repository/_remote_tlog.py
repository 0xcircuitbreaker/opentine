"""Client side of the remote audit log (0.44, X33): consistency on fetch, receipts on push.

Per remote (``base URL | tenant``) the repository keeps ``.tine/log/remotes/<id>/``:
``vkey`` (the log key, pinned on first contact) and ``checkpoint`` (the newest
checkpoint seen). Each fetch asks for a consistency proof from that size and
refuses -- before importing anything -- a checkpoint under another key, a
smaller tree (rollback) or one that does not extend the stored one (fork). A
push then fetches the inclusion receipt of its own ``update_ref`` row and
stores it under ``receipts/`` for bundles to embed. A server that publishes no
log (pre-0.44, or a custom audit sink) is reported ``unavailable`` -- unless it
published one before, which is refused like a rollback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from opentine.repository import _tlog, _tlog_note, _tlog_proof, _tlog_receipt
from opentine.repository._paths import atomic_bytes, durable_directory, internal_path


def state_root(base: Path | None, remote: str, tenant: str) -> Path | None:
    """None for a repository with no directory (nothing to pin or store)."""
    if base is None:
        return None
    key = hashlib.sha256(f"{remote}|{tenant}".encode()).hexdigest()[:32]
    return internal_path(Path(base), "log", "remotes", key)


def _get(client: Any, path: str, timeout: float, **query: Any) -> dict[str, Any] | None:
    url = path + ("?" + urlencode(query) if query else "")
    from opentine.repository import client as transport  # its _request_json, as patched

    status, body = transport._request_json(
        client, "GET", url, allowed=(200, 404), max_seconds=timeout
    )
    # A body with no checkpoint is no log at all: the same as a 404 (and refused alike
    # once a log was pinned), never a pass.
    return body if status == 200 and isinstance(body, dict) and "checkpoint" in body else None


def _stored(state: Path) -> tuple[str, int, bytes] | None:
    if not (state / "checkpoint").exists():
        return None
    vkey = (state / "vkey").read_text("ascii").strip()
    _, size, root = _tlog_note.open_checkpoint((state / "checkpoint").read_bytes(), vkey)
    return vkey, size, root


def advance(state: Path | None, client: Any, prefix: str, timeout: float) -> dict[str, Any] | None:
    """Check the remote's newest checkpoint against the stored one; store it."""
    if state is None:
        return None
    stored = _stored(state)
    old = stored[1] if stored else 0
    body = _get(client, prefix + "/transparency/consistency", timeout, old=old)
    if body is None:
        if stored:
            raise _tlog.LogError("remote stopped publishing its audit log (rollback?)")
        return {"status": "unavailable"}
    note, vkey = str(body.get("checkpoint", "")).encode(), str(body.get("vkey", ""))
    if stored and vkey != stored[0]:
        raise _tlog.LogError("remote audit log key changed since it was pinned")
    _, size, root = _tlog_note.open_checkpoint(note, vkey)
    if stored:
        proof = _tlog_proof.decode(body.get("proof"))
        _tlog_proof.verify_consistency(stored[1], size, stored[2], root, proof)
    durable_directory(state)
    if not stored:
        atomic_bytes(state / "vkey", (vkey + "\n").encode())
    atomic_bytes(state / "checkpoint", note)
    return {"previous_size": old, "size": size,
            "status": "consistent" if stored else "pinned"}  # fmt: skip


def receipt(
    state: Path | None, client: Any, prefix: str, ref: str, new: str, timeout: float
) -> dict[str, Any] | None:
    """Advance, then verify and store the inclusion receipt for ``ref -> new``."""
    report = advance(state, client, prefix, timeout)
    if report is None or report["status"] == "unavailable":
        return report
    body = _get(client, prefix + "/transparency/receipt", timeout, name=ref, new=new)
    if body is None:
        raise _tlog.LogError(f"remote logged no update of {ref} to {new}")
    vkey, size, root = _stored(state) or ("", 0, b"")
    checked = _tlog_receipt.verify(body, vkey=vkey)
    _, rsize, rroot = _tlog_note.open_checkpoint(str(body["checkpoint"]).encode(), vkey)
    if rsize > size:  # appended since the advance: prove the stored tree extends to it
        report = advance(state, client, prefix, timeout)
        vkey, size, root = _stored(state) or ("", 0, b"")
    if rsize > size:
        raise _tlog.LogError("push receipt checkpoint is ahead of the remote's own log")
    if rsize < size:
        body2 = _get(client, prefix + "/transparency/consistency", timeout, old=rsize, new=size)
        proof = _tlog_proof.decode((body2 or {}).get("proof"))
        _tlog_proof.verify_consistency(rsize, size, rroot, root, proof)
    elif rroot != root:
        raise _tlog.LogError("fork: push receipt checkpoint differs from the stored one")
    entry = json.loads(_tlog_receipt.entry_bytes(body))
    if (entry.get("name"), entry.get("new")) != (ref, new):
        raise _tlog.LogError("push receipt names another ref update")
    durable_directory(state / "receipts")
    name = hashlib.sha256(f"{ref}|{new}".encode()).hexdigest()[:32] + ".json"
    atomic_bytes(state / "receipts" / name, json.dumps(body, sort_keys=True).encode())
    return {**report, "receipt_index": checked["index"], "status": "included"}


def stored_receipts(base: Path) -> list[dict[str, Any]]:
    out = []
    for path in sorted(internal_path(Path(base), "log", "remotes").glob("*/receipts/*.json")):
        try:
            out.append(json.loads(path.read_text("utf-8")))
        except (OSError, ValueError):
            continue
    return out
