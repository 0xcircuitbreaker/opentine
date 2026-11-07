"""Transparency receipts for bundled refs (0.44, X33).

``tine bundle create --transparency`` embeds, in the manifest's ``transparency``
list, ``opentine-tlog-receipt/1`` objects (:mod:`.repository._tlog_receipt`)
proving each bundled ``ref -> oid`` was logged:

* by this repository's op log (``opentine-op/1``, whose rows carry each
  reflog row's digest -- the reflog published over ``opentine-log/1``), and
* by a remote's audit log, when ``tine push`` stored a receipt for it.

:func:`check` verifies them from the bundle bytes alone: no repository, no
network. Log keys are pinned by origin (``--log-vkey``, the vkey's name is the
origin) or else taken from the receipt (reported as trust on first use);
``quorum`` additionally requires witness cosignatures on every checkpoint.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine.repository import _oplog, _remote_tlog, _tlog, _tlog_note, _tlog_receipt


def covers(receipt: dict[str, Any]) -> set[tuple[str, str]]:
    """The ``(ref, oid)`` pairs a receipt's entry records."""
    try:
        return covers_entry(_tlog_receipt.entry_bytes(receipt))
    except ValueError:
        return set()


def covers_entry(raw: bytes) -> set[tuple[str, str]]:
    try:
        entry = json.loads(raw)
    except ValueError:
        return set()
    if not isinstance(entry, dict):
        return set()
    if entry.get("format") == _oplog.OP_FORMAT and isinstance(entry.get("refs"), list):
        return {
            (row["ref"], row["new"])
            for row in entry["refs"]
            if isinstance(row, dict) and isinstance(row.get("ref"), str)
            and isinstance(row.get("new"), str)
        }  # fmt: skip
    if entry.get("format") == "opentine-audit/1" and entry.get("outcome") in ("ok", "forced"):
        name, new = entry.get("name"), entry.get("new")
        return {(name, new)} if isinstance(name, str) and isinstance(new, str) else set()
    return set()


def receipts_for(base: Path, chosen: dict[str, str]) -> list[dict[str, Any]]:
    """The newest op-log receipt per bundled ref, plus stored push receipts."""
    wanted = set(chosen.items())
    out: list[dict[str, Any]] = []
    root = _oplog.log_root(base)
    entries = _tlog_note.verify_log(root, _oplog.ORIGIN)
    pending = set(wanted)
    for index in range(len(entries) - 1, -1, -1):
        if not pending:
            break
        hit = covers_entry(entries[index]) & pending
        if hit:
            out.append(_tlog_receipt.make(root, _oplog.ORIGIN, index))
            pending -= hit
    out.extend(r for r in _remote_tlog.stored_receipts(base) if covers(r) & wanted)
    if not out:
        raise _tlog.LogError("no bundled ref is in the op log or a push receipt")
    return out


def check(
    receipts: Any,
    refs: dict[str, str],
    *,
    vkeys: list[str] | None = None,
    witnesses: list[str] | None = None,
    quorum: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Verify every receipt and that each covers a bundled ref; LogError otherwise."""
    if not isinstance(receipts, list) or len(receipts) > _tlog_receipt.MAX_RECEIPTS:
        raise _tlog.LogError("transparency receipts must be a bounded list")
    pinned = {_tlog_note.parse_vkey(v)[0]: v for v in vkeys or ()}
    wanted, covered, results = set(refs.items()), set(), []
    for receipt in receipts:
        origin = str(receipt.get("checkpoint", "") if isinstance(receipt, dict) else "")
        origin = origin.split("\n", 1)[0]
        result = _tlog_receipt.verify(
            receipt, vkey=pinned.get(origin), witnesses=witnesses, quorum=quorum
        )
        hit = covers(receipt) & wanted
        if not hit:
            raise _tlog.LogError(f"receipt {result['origin']}#{result['index']} covers no ref")
        covered |= hit
        results.append(result)
    return {
        "covered": sorted(ref for ref, _ in covered),
        "ok": True,
        "receipts": results,
        "uncovered": sorted(ref for ref, oid in wanted - covered),
    }
