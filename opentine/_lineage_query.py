"""``why`` and ``archive`` over the derived lineage index (0.58).

``why VARIANT`` walks from a variant to every ancestor and collects each one's
evidence (evals, judges, dataset commitments, approvers, policies,
the promotion decision, the loop). It touches only the rows on that path:
one ``variants`` lookup, one ``edges`` and one ``evidence`` query per ancestor,
each served by a primary-key prefix. ``visited`` reports the queries and rows
read, which is what the scale tests count (never wall time).

The index is derived, so ``why`` does not take it on trust: given *load* (an
oid -> claim rows reader over the lineage folder) it re-derives every ancestor
it reports from its signed record and raises :class:`IndexMismatch` when the index
disagrees (a hand-edited or poisoned file). That is one object read per
ancestor, so the bound stays O(ancestors + evidence). *max_nodes* caps the walk
on a huge archive and sets ``truncated``.
"""

from __future__ import annotations

import sqlite3
from collections import deque
from typing import Any

_NODE = "SELECT oid, signer, signed, loop FROM variants WHERE variant = ?"
WHY_KINDS = ("conflict", "eval", "judge", "dataset", "signer", "approver", "policy", "decision",
             "selector", "mutation", "artifact", "compare", "loop", "input")  # fmt: skip


class IndexMismatch(ValueError):
    """The derived index disagrees with the attestation it claims to come from."""


def _check(load: Any, name: str, oid: str, signed: int, parents: list[str],
           evidence: list[tuple[str, str, str]]) -> None:  # fmt: skip
    truth = load(oid)
    mine = [e for e in evidence if e[0] != "conflict"]
    if (truth is None or truth["variant"] != name or int(truth["signed"]) != int(signed)
            or sorted(truth["parents"]) != sorted(parents)
            or sorted(truth["evidence"]) != sorted(mine)):  # fmt: skip
        raise IndexMismatch(f"index row for {name!r} does not match {oid}; rebuild the index")


class _Reader:
    """Counts the queries issued and the rows they return."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db, self.queries, self.rows = db, 0, 0

    def all(self, sql: str, args: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        self.queries += 1
        found = self.db.execute(sql, args).fetchall()
        self.rows += len(found)
        return found


def why(db: sqlite3.Connection, variant: str, *, max_depth: int | None = None,
        max_nodes: int | None = None, load: Any = None) -> dict[str, Any]:  # fmt: skip
    read = _Reader(db)
    truncated = False
    first = read.all(_NODE, (variant,))
    if not first:
        raise KeyError(f"no lineage record for variant {variant!r}")
    depth_of = {variant: 0}
    queue, ancestors, evidence, missing = deque([variant]), [], [], set()
    while queue:
        name = queue.popleft()
        depth = depth_of[name]
        if max_nodes is not None and len(ancestors) >= max_nodes:
            truncated = True
            break
        node = first if name == variant else read.all(_NODE, (name,))
        if node == []:
            missing.add(name)
            continue
        oid, signer, signed, loop = node[0]
        ancestors.append({"variant": name, "depth": depth, "oid": oid, "signer": signer,
                          "signed": bool(signed), "loop": loop})  # fmt: skip
        found = read.all("SELECT kind, ref, detail FROM evidence WHERE variant = ?", (name,))
        for kind, ref, detail in found:
            evidence.append({"variant": name, "kind": kind, "ref": ref, "detail": detail})
        parents = [p for (p,) in read.all("SELECT parent FROM edges WHERE child = ?", (name,))]
        if load is not None:
            _check(load, name, oid, signed, parents, [tuple(r) for r in found])
        if max_depth is not None and depth >= max_depth:
            continue
        for parent in parents:
            if parent not in depth_of:
                depth_of[parent] = depth + 1
                queue.append(parent)
    summary = {k: sorted({e["ref"] for e in evidence if e["kind"] == k}) for k in WHY_KINDS}
    return {"variant": variant, "depth": max(depth_of.values()),
            "ancestors": sorted(ancestors, key=lambda a: (a["depth"], a["variant"])),
            "evidence": sorted(evidence, key=lambda e: (e["variant"], e["kind"], e["ref"])),
            "summary": {k: v for k, v in summary.items() if v},
            "missing_parents": sorted(missing), "truncated": truncated,
            "store_checked": load is not None,
            "visited": {"queries": read.queries, "rows": read.rows}}  # fmt: skip


def archive(db: sqlite3.Connection, *, loop: str | None = None,
            signed_only: bool = False) -> dict[str, Any]:  # fmt: skip
    """The population of an archive loop: every variant with its fan-in and fan-out."""
    clauses, args = [], []
    if loop:
        clauses.append("v.loop = ?")
        args.append(loop)
    if signed_only:
        clauses.append("v.signed = 1")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""SELECT v.variant, v.signed, v.loop,
        (SELECT COUNT(*) FROM edges e WHERE e.child = v.variant),
        (SELECT COUNT(*) FROM edges e WHERE e.parent = v.variant)
        FROM variants v {where} ORDER BY v.variant"""
    members = [{"variant": n, "signed": bool(s), "loop": lp, "parents": p, "children": c}
               for n, s, lp, p, c in db.execute(sql, args)]  # fmt: skip
    totals = {
        "variants": len(members),
        "signed": sum(m["signed"] for m in members),
        "roots": sum(m["parents"] == 0 for m in members),
        "leaves": sum(m["children"] == 0 for m in members),
        "multi_parent": sum(m["parents"] > 1 for m in members),
        "max_parents": max((m["parents"] for m in members), default=0),
    }
    return {"loop": loop, "signed_only": signed_only, "totals": totals, "members": members}


__all__ = ["WHY_KINDS", "IndexMismatch", "archive", "why"]
