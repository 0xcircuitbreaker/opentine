"""``tine undo [OP]``: a forward transaction putting an op's refs back (0.36).

Undo never rewrites history: it appends a new op (``undoes`` names the one it
reverts) that moves each ref from the value the undone op left back to the value
it found, by compare-and-swap through the ref transaction (``Repo.update_refs``),
with deletions through ``delete_ref`` under the same lock discipline.

Before moving anything it looks for *gaps* (ROADMAP §6): a ref whose current
value is not the last value the op log recorded for it, or whose reflog has rows
newer than that op, was moved by a writer that did not log (opentine 0.34, a
library caller). An op whose refs a later op moved again is *superseded*. Both
refuse unless ``force``: the log cannot say what undoing across them means.
"""

from __future__ import annotations

from pathlib import Path

from opentine._ref_delete import delete_ref
from opentine.repository._oplog import read_ops, set_undoes
from opentine.repository._ref_store import read_ref_oid
from opentine.repository._reflog import read_reflog


class UndoRefused(ValueError):
    def __init__(self, message: str, problems: list[dict]) -> None:
        super().__init__(message)
        self.problems = problems


def find_op(ops: list[dict], selector: str | None) -> dict:
    if not ops:
        raise KeyError("the op log is empty: nothing to undo")
    if selector is None:
        return ops[-1]
    matches = [op for op in ops if op["id"].startswith(selector) or str(op["index"]) == selector]
    if len(matches) != 1:
        raise KeyError(f"{'no' if not matches else 'ambiguous'} op matches {selector!r}")
    return matches[0]


def problems(base: Path, ops: list[dict], target: dict) -> list[dict]:
    """Every reason undoing *target* would cross a gap or a later op."""
    found = []
    for row in target["refs"]:
        ref = row["ref"]
        last = next(op for op in reversed(ops) if any(r["ref"] == ref for r in op["refs"]))
        logged = next(r["new"] for r in last["refs"] if r["ref"] == ref)
        current = read_ref_oid(base, ref)
        newer = [
            r for r in read_reflog(base, ref) if int(r.get("time_ns", "0")) > int(last["time_ns"])
        ]
        if current != logged or newer:
            found.append({"kind": "gap", "ref": ref, "logged": logged, "current": current})
        elif last["id"] != target["id"]:
            found.append({"kind": "superseded", "ref": ref, "by": last["id"]})
    return found


def undo(repo, selector: str | None = None, *, force: bool = False) -> dict:
    """Revert one op's ref moves; return ``{"undone", "refs", "problems"}``."""
    base = Path(repo.path)
    ops = read_ops(base)
    target = find_op(ops, selector)
    found = problems(base, ops, target)
    if found and not force:
        kinds = ", ".join(sorted({p["kind"] for p in found}))
        raise UndoRefused(f"undo would cross a {kinds} (pass --force to undo anyway)", found)
    set_undoes(target["id"])
    moves, deletes, rows = [], [], []
    for row in target["refs"]:
        current = read_ref_oid(base, row["ref"])
        if current == row["old"]:
            continue
        rows.append({"ref": row["ref"], "old": current, "new": row["old"]})
        if row["old"] is None:
            deletes.append((row["ref"], current))
        else:
            moves.append((row["ref"], row["old"], current))
    if moves:
        repo.update_refs(moves, actor=f"undo {target['id']}")
    for ref, current in deletes:
        delete_ref(base, ref, current, actor=f"undo {target['id']}")
    return {"undone": target["id"], "refs": rows, "problems": found}
