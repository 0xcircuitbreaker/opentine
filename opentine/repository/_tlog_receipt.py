"""Self-contained ``opentine-tlog-receipt/1`` objects: one entry, proven offline.

A receipt carries everything a verifier needs and nothing it must fetch: the
entry bytes, its index, the signed checkpoint (with any witness cosignatures)
and the RFC 9162 inclusion proof from the entry to that checkpoint's root.
Bundles embed receipts (``transparency.json``) and ``tine push`` stores the
one the remote returns, so "verifies from the bundle alone" is literal.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from opentine.repository import _tlog, _tlog_cosign, _tlog_note, _tlog_proof

RECEIPT_FORMAT = "opentine-tlog-receipt/1"
MAX_RECEIPTS = 1024


def make(root: Path, origin: str, index: int) -> dict[str, Any]:
    """A receipt for entry ``index`` of the verified log at ``root``."""
    note = (root / "checkpoint").read_bytes()  # one read: a concurrent append cannot skew it
    log_origin, size, tree_root = _tlog_note.open_checkpoint(note, _tlog_note.stored_vkey(root))
    entries = _tlog.read_entries(root, size)
    if (
        log_origin != origin
        or _tlog.merkle_root([_tlog.leaf_hash(e) for e in entries]) != tree_root
    ):
        raise _tlog.LogError("log entries do not match the signed checkpoint")
    if not 0 <= index < len(entries):
        raise _tlog.LogError(f"log has no entry {index}")
    hashes = _tlog_proof.Hashes(len(entries), lambda rel: _tlog._read(root, rel))
    return {
        "checkpoint": note.decode("utf-8"),
        "entry": base64.b64encode(entries[index]).decode("ascii"),
        "format": RECEIPT_FORMAT,
        "index": index,
        "inclusion": _tlog_proof.encode(_tlog_proof.inclusion_proof(hashes, index)),
        "vkey": _tlog_note.stored_vkey(root),
    }


def entry_bytes(receipt: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(receipt["entry"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise _tlog.LogError("receipt entry is not base64") from exc


def verify(
    receipt: Any,
    *,
    vkey: str | None = None,
    witnesses: list[str] | None = None,
    quorum: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Check one receipt offline; LogError on the first failure.

    ``vkey`` pins the log key (otherwise the embedded one: trust on first use);
    ``quorum`` ``(N, M)`` requires N of the M pinned ``witnesses`` to cosign.
    """
    if not isinstance(receipt, dict) or receipt.get("format") != RECEIPT_FORMAT:
        raise _tlog.LogError(f"not an {RECEIPT_FORMAT} object")
    try:
        note = str(receipt["checkpoint"]).encode("utf-8")
        entry = base64.b64decode(receipt["entry"], validate=True)
        index = receipt["index"]
        embedded = str(receipt["vkey"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _tlog.LogError("receipt is missing or mangles a member") from exc
    if not isinstance(index, int) or isinstance(index, bool):
        raise _tlog.LogError("receipt index is not an integer")
    key = vkey or embedded
    origin, size, root = _tlog_note.open_checkpoint(note, key)
    leaf = _tlog.leaf_hash(entry)
    _tlog_proof.verify_inclusion(leaf, index, size, _tlog_proof.decode(receipt["inclusion"]), root)
    cosigned: dict[str, int] = {}
    if quorum is not None:
        cosigned = _tlog_cosign.check_quorum(note, list(witnesses or ()), *quorum)
    return {
        "basis": "pinned log key" if vkey else "embedded log key (trust on first use)",
        "cosigned_by": sorted(cosigned),
        "index": index,
        "leaf": leaf.hex(),
        "ok": True,
        "origin": origin,
        "size": size,
    }


def verify_all(receipts: Any, **kwargs: Any) -> list[dict[str, Any]]:
    if not isinstance(receipts, list) or len(receipts) > MAX_RECEIPTS:
        raise _tlog.LogError("transparency receipts must be a bounded list")
    return [verify(item, **kwargs) for item in receipts]
