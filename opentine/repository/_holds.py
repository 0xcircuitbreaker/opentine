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

import os
import time
from collections.abc import Callable
from pathlib import Path

from opentine import _json_shallow
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
#: 0.60: a holdout access record or canary registration (opentine._holdout_hold): never released.
HOLDOUT_ACCESS, CANARY_HOLD = "holdout-access:", "holdout-canary:"
HOLDOUT_QUERY = "holdout-query:"  # 0.86: a holdout query record (opentine._holdout_query)
#: 0.61: a memory quarantine (opentine._memory_quarantine): never released.
MEMORY_QUARANTINE = "memory-quarantine:"
#: 0.63: rows that keep a monitor verdict that was not ``allow`` and a monitor stop
#: token (opentine._monitor_verdict, opentine._monitor_stop): released never.
MONITOR_VERDICT, MONITOR_STOP = "monitor-verdict:", "monitor-stop:"
#: 0.64: an oversight decision or review request (opentine._oversight): never released.
OVERSIGHT_DECISION = "oversight-decision:"
#: 0.65: a blind audit game's seal, findings and reveal (opentine._audit_game): never released.
AUDIT_GAME = "audit-game:"
#: 0.68: a sabotage task record (opentine._sabotage): never released.
SABOTAGE_TASK = "sabotage-task:"
#: 0.69: a signed history-merge record (opentine._history_merge_repo): never released.
HISTORY_MERGE = "history-merge:"
#: 0.69: rows that keep budget-ledger entries and the flags routed to oversight
#: (opentine._budget_ledger): released never, so a loop cannot delete its own spend.
BUDGET_LEDGER, BUDGET_FLAG = "budget-ledger:", "budget-flag:"
#: 0.69: rows that keep a signed sandbox policy or containment finding
#: (opentine._containment): released never, so a loop cannot delete what it tried.
CONTAINMENT = "containment:"
#: 0.71: rows that keep a signed checkpoint/weight custody event
#: (opentine._weight_custody): released never, so a loop cannot delete a copy or a load.
WEIGHT_CUSTODY = "custody:weights:"
#: 0.72: a refused load of a model-organism artifact (opentine._weight_custody_review).
WEIGHT_CUSTODY_REFUSED = "custody:weights-refused:"
#: 0.72: a model-organism tag, untag, approval or access entry (opentine._organism).
ORGANISM = "organism:"
#: 0.74: a signed behaviour flag on transcripts (opentine._transcript_flags): never released.
TRANSCRIPT_FLAG = "transcript-flag:"
#: 0.73: rows that keep an uplift suite or record (opentine._uplift): released never.
UPLIFT = "uplift:"
#: 0.75: a dataset record or signed withdrawal (opentine._dataset_version, _dataset_withdraw).
DATASET_RECORD, DATASET_WITHDRAW = "dataset-record:", "dataset-withdraw:"
#: 0.74: rows that keep a signed policy admission record (opentine._policy_record): never released.
POLICY_ADMISSION = "policy-admission:"
#: 0.77/0.84: ingest policies, newest batch and segment, audits (_ingest_holds, _rl_audit).
INGEST_POLICY, INGEST_HEAD = "ingest-policy:", "ingest-head:"
INGEST_SEGMENT, INGEST_AUDIT = "ingest-segment:", "ingest-audit:"
#: 0.83: interpretability records and probe calibrations (opentine._interp_custody): never released.
INTERP_CUSTODY = "custody:interp"
#: 0.83: a signed collusion-protocol verdict (opentine._collusion_record): never released.
COLLUSION_VERDICT = "collusion-verdict:"
#: 0.84/0.88: an artifact provenance record and its run; a run's scaffold manifest.
PROVENANCE, SCAFFOLD = "custody:provenance:", "scaffold-manifest:"
JUDGE_VALIDATION = "judge-validation:"  # 0.89: opentine._judge_validation
#: 0.90: monitor ledger and heartbeat chain heads, operating points (opentine._monitor_*).
MONITOR_LEDGER, MONITOR_HEARTBEAT = "monitor-ledger:", "monitor-heartbeat:"
MONITOR_VALIDATION = "monitor-validation:"
#: 0.91: an installed stop policy, a fleet stop issued here, a stop-compliance record.
STOP_POLICY, FLEET_STOP, STOP_COMPLIANCE = "stop-policy:", "fleet-stop:", "stop-compliance:"
TRIPWIRE, CUSTODY_QUORUM = "tripwire:", "custody:quorum:"  # 0.91: _tripwire_*, _custody_quorum
_NEVER_RELEASED = (
    ((MEMORY_QUARANTINE,), "a memory quarantine"),
    ((MONITOR_VERDICT, MONITOR_STOP), "a monitor verdict or stop token"),
    ((OVERSIGHT_DECISION,), "an oversight decision"),
    ((AUDIT_GAME,), "an audit-game record"),
    ((SABOTAGE_TASK,), "a sabotage task record"),
    ((HISTORY_MERGE,), "a history-merge record"),
    ((BUDGET_LEDGER, BUDGET_FLAG), "a budget-ledger entry"),
    ((CONTAINMENT,), "a containment record"),
    ((WEIGHT_CUSTODY, WEIGHT_CUSTODY_REFUSED), "a weight custody record"),
    ((ORGANISM,), "a model-organism record"),
    ((TRANSCRIPT_FLAG,), "a transcript behaviour flag"),
    ((UPLIFT,), "an uplift record"),
    ((HOLDOUT_QUERY,), "a holdout query record"),
    ((DATASET_RECORD,), "a dataset record"),
    ((DATASET_WITHDRAW,), "a dataset withdrawal"),
    ((POLICY_ADMISSION,), "a policy admission record"),
    ((INGEST_POLICY, INGEST_HEAD, INGEST_SEGMENT, INGEST_AUDIT), "an ingest record"),
    ((INTERP_CUSTODY,), "an interpretability custody record"),
    ((COLLUSION_VERDICT,), "a collusion-protocol verdict"),
    ((PROVENANCE,), "an artifact provenance record"),
    ((SCAFFOLD,), "a scaffold manifest record"),
    ((JUDGE_VALIDATION,), "a judge validation record"),
    ((MONITOR_LEDGER, MONITOR_HEARTBEAT, MONITOR_VALIDATION), "a monitor coverage record"),
    ((STOP_POLICY, FLEET_STOP, STOP_COMPLIANCE), "a stop policy, fleet stop or compliance record"),
    ((TRIPWIRE, CUSTODY_QUORUM), "a tripwire or custody quorum record"),
)
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
        record = _json_shallow.loads(data) if len(data) <= MAX_HOLDS_BYTES else None
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


def hold_row(repo, oid: str, target: str) -> dict[str, str]:
    """Hold the stored *oid* as *target*; re-adding the same row keeps one copy."""
    from opentine.repository._link_touch import touch_links

    touch_links(repo, [oid])  # a concurrent prune keeps it, or this hold fails
    row = {"oid": oid, "target": target}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    return row


def add(repo, target: str) -> dict[str, str]:
    return hold_row(repo, resolve(repo, target), target)


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
        for prefixes, what in _NEVER_RELEASED:
            if any(r["target"].startswith(prefixes) for r in gone):
                raise HoldError(f"{target} keeps {what}: it is never released")
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
