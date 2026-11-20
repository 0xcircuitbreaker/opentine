"""``tine hold``: keep named objects, and everything they reach, from deletion.

A hold is a row in ``.tine/holds`` (canonical JSON, ``tine-holds/1``) naming an
object id and what the user asked for (the id itself, or the ref it resolved
to when the hold was added). ``tine gc --prune=now``, ``tine prune --delete``,
``tine rewind --apply`` and the remote's object deletes refuse held objects.
The file names its ids in plain text, so a release that predates holds still
keeps them: ``tine prune`` treats every id named outside the object store as
a root. An unreadable holds file refuses every delete (fail closed).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from opentine.kernel import OID_RE, KernelError, canonical_json
from opentine.repository import _winretry
from opentine.repository._lockfile import acquire
from opentine.repository._paths import atomic_bytes, internal_path

FORMAT = "tine-holds/1"
#: Rows whose target starts with this keep a loop stop (opentine.coord._loop_hold):
#: ``tine hold release`` refuses them, so deleting coord/loops/LOOP cannot un-stop.
LOOP_STOP = "loop-stop:"
#: 0.59: rows whose target starts with this keep an integrity taint
#: (opentine._integrity_hold): released never, so deleting the taint file cannot un-taint.
TAINT = "integrity-taint:"
#: 0.60: rows that keep a sealed holdout's access record or a canary registration
#: (opentine._holdout_hold): released never, so deleting the file lowers nothing.
HOLDOUT_ACCESS = "holdout-access:"
CANARY_HOLD = "holdout-canary:"
#: 0.61: rows that keep a memory quarantine (opentine._memory_quarantine): released
#: never, so deleting the quarantine's ref cannot serve the note again.
MEMORY_QUARANTINE = "memory-quarantine:"
#: 0.63: rows that keep a monitor verdict that was not ``allow`` and a monitor stop
#: token (opentine._monitor_verdict, opentine._monitor_stop): released never.
MONITOR_VERDICT = "monitor-verdict:"
MONITOR_STOP = "monitor-stop:"
#: 0.64: rows that keep an oversight decision (opentine._oversight): released never,
#: so a loop cannot delete an approval, a rejection or a review request.
OVERSIGHT_DECISION = "oversight-decision:"
#: 0.65: rows that keep a blind audit game's seal, findings and reveal
#: (opentine._audit_game): released never, so a reveal stays on record.
AUDIT_GAME = "audit-game:"
#: 0.68: rows that keep a sabotage task record (opentine._sabotage): released never,
#: so a loop cannot delete the record of an attempted or achieved side task.
SABOTAGE_TASK = "sabotage-task:"
#: 0.69: rows that keep a signed history-merge record (opentine._history_merge_repo):
#: released never, so a loop cannot delete the record of what a merge kept or weakened.
HISTORY_MERGE = "history-merge:"
#: 0.69: rows that keep budget-ledger entries and the flags routed to oversight
#: (opentine._budget_ledger): released never, so a loop cannot delete its own spend.
BUDGET_LEDGER = "budget-ledger:"
BUDGET_FLAG = "budget-flag:"
#: 0.69: rows that keep a signed sandbox policy or containment finding
#: (opentine._containment): released never, so a loop cannot delete what it tried.
CONTAINMENT = "containment:"
#: 0.71: rows that keep a signed checkpoint/weight custody event
#: (opentine._weight_custody): released never, so a loop cannot delete a copy or a load.
WEIGHT_CUSTODY = "custody:weights:"
#: 0.72: rows that keep a model-organism tag, untag, load approval or access-log entry
#: (opentine._organism): released never, so a loop cannot untag or erase an access.
ORGANISM = "organism:"
MAX_HOLDS_BYTES = 4 * 1024 * 1024


class HoldError(KernelError):
    """The holds file is unreadable, or a delete would touch a held object."""


def read_holds(path: Path) -> list[dict[str, str]]:
    """The hold rows in *path* (none when it does not exist)."""
    try:
        data = _winretry.read_bytes(path, MAX_HOLDS_BYTES + 1)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise HoldError(f"cannot read holds file {path}: {exc}") from exc
    try:
        record = json.loads(data) if len(data) <= MAX_HOLDS_BYTES else None
        rows = record["holds"] if record and record.get("format") == FORMAT else None
        if not isinstance(rows, list) or not all(_valid(row) for row in rows):
            raise ValueError("not a tine-holds/1 file")
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HoldError(f"unreadable holds file {path}: {exc}") from exc
    return rows


def _valid(row) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("oid"), str)
        and OID_RE.fullmatch(row["oid"]) is not None
        and isinstance(row.get("target"), str)
    )


def held_oids(path: Path) -> set[str]:
    return {row["oid"] for row in read_holds(path)}


def edit_holds(path: Path, change: Callable[[list[dict[str, str]]], list[dict[str, str]]]):
    """Apply *change* to the rows under ``<path>.lock``; return the new rows."""
    lock = path.with_name(path.name + ".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(100):
        try:
            fd = acquire(lock, 0o600)
            break
        except FileExistsError:
            if attempt == 99:
                raise HoldError(f"holds file is locked by another writer ({lock})") from None
            time.sleep(0.05)
    try:
        os.close(fd)
        rows = change(read_holds(path))
        rows = sorted(rows, key=lambda row: (row["oid"], row["target"]))
        atomic_bytes(path, canonical_json({"format": FORMAT, "holds": rows}) + b"\n")
        return rows
    finally:
        _winretry.unlink(lock)


def holds_path(repo) -> Path:
    return internal_path(repo.path, "holds")


def resolve(repo, target: str) -> str:
    """The object id *target* names: an id stored here, or a ref."""
    if OID_RE.fullmatch(target):
        if not repo.has(target):
            raise HoldError(f"not stored in this repository: {target}")
        return target
    oid = repo.read_ref(target)
    if oid is None:
        raise HoldError(f"no such object id or ref: {target}")
    return oid


def add(repo, target: str) -> dict[str, str]:
    from opentine.repository._link_touch import touch_links

    oid = resolve(repo, target)
    touch_links(repo, [oid])  # a concurrent prune keeps it, or this hold fails
    row = {"oid": oid, "target": target}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    return row


def release(repo, target: str) -> list[dict[str, str]]:
    """Drop every hold added as *target* or on the object id *target*."""
    gone: list[dict[str, str]] = []

    def change(rows):
        gone.extend(r for r in rows if target in (r["oid"], r["target"]))
        if any(r["target"].startswith(LOOP_STOP) for r in gone):
            raise HoldError(f"{target} keeps a loop stop: a stopped loop is never released")
        if any(r["target"].startswith(TAINT) for r in gone):
            raise HoldError(f"{target} keeps an integrity taint: a taint is never released")
        if any(r["target"].startswith((HOLDOUT_ACCESS, CANARY_HOLD)) for r in gone):
            raise HoldError(f"{target} keeps a holdout access record or canary registration: "
                            "it is never released")  # fmt: skip
        if any(r["target"].startswith(MEMORY_QUARANTINE) for r in gone):
            raise HoldError(f"{target} keeps a memory quarantine: it is never released")
        if any(r["target"].startswith((MONITOR_VERDICT, MONITOR_STOP)) for r in gone):
            raise HoldError(f"{target} keeps a monitor verdict or stop token: it is never released")
        if any(r["target"].startswith(OVERSIGHT_DECISION) for r in gone):
            raise HoldError(f"{target} keeps an oversight decision: it is never released")
        if any(r["target"].startswith(AUDIT_GAME) for r in gone):
            raise HoldError(f"{target} keeps an audit-game record: it is never released")
        if any(r["target"].startswith(SABOTAGE_TASK) for r in gone):
            raise HoldError(f"{target} keeps a sabotage task record: it is never released")
        if any(r["target"].startswith(HISTORY_MERGE) for r in gone):
            raise HoldError(f"{target} keeps a history-merge record: it is never released")
        if any(r["target"].startswith((BUDGET_LEDGER, BUDGET_FLAG)) for r in gone):
            raise HoldError(f"{target} keeps a budget-ledger entry: it is never released")
        if any(r["target"].startswith(CONTAINMENT) for r in gone):
            raise HoldError(f"{target} keeps a containment record: it is never released")
        if any(r["target"].startswith(WEIGHT_CUSTODY) for r in gone):
            raise HoldError(f"{target} keeps a weight custody event: it is never released")
        if any(r["target"].startswith(ORGANISM) for r in gone):
            raise HoldError(f"{target} keeps a model-organism record: it is never released")
        return [r for r in rows if r not in gone]

    edit_holds(holds_path(repo), change)
    if not gone:
        raise HoldError(f"no hold on {target}")
    return gone


def held(repo) -> set[str]:
    """Every held object and everything it reaches (fails closed)."""
    from opentine.repository._prune_roots import reachable

    roots = held_oids(holds_path(repo))
    return reachable(repo, roots) | roots if roots else set()


def refuse_held(repo, oids, what: str) -> None:
    """Raise :class:`HoldError` if any of *oids* is held (directly or by reach)."""
    hit = sorted(set(oids) & held(repo))
    if hit:
        raise HoldError(f"{what} refused: {hit[0]} is held (tine hold release to allow it)")


def refuse_held_names(path, names, what: str) -> None:
    """Refuse *what* when the repository at *path* holds any of *names* (ids or refs).

    No repository there: nothing can be held. An unreadable holds file refuses.
    """
    from opentine.repository import Repo

    try:
        repo = Repo.open(path)
    except (OSError, ValueError):
        return
    rows = read_holds(holds_path(repo))
    if not rows:
        return
    hit = sorted({name for name in names if name} & (held(repo) | {r["target"] for r in rows}))
    if hit:
        raise HoldError(f"{what} refused: {hit[0]} is held (tine hold release to allow it)")
