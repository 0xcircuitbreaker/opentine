"""Write merges and picks into a repository (0.47, F2; the rules are :mod:`opentine._merge`).

:func:`merge_runs` loads both runs, finds each side's workspace tree (the
``tree`` of the last event carrying one; the base's is the last shared event
carrying one), computes the merge with :func:`opentine._merge.merge_payloads`
and writes exactly the objects it names, checking every oid it gets back is
the one it computed. With ``ref``, the ref moves by compare-and-swap from the
oid it named when ours was read, so a racing writer is refused, never
overwritten. :func:`pick_events` does the same for a pick.
"""

from __future__ import annotations

from typing import Any

from opentine._merge import MergeError, merge_payloads, pick_payloads
from opentine._merge_tree import flatten


def _run(repo: Any, value: str) -> tuple[str, dict[str, Any]]:
    from opentine.repository.ops import resolve_target

    try:
        oid = resolve_target(repo, value)
    except KeyError:
        raise MergeError("merge.missing", f"cannot resolve {value}: no such run") from None
    envelope = repo.get(oid)
    if envelope.object_type != "run":
        raise MergeError("merge.missing", f"{value} is not a run")
    return oid, envelope.payload()


def _last_tree(repo: Any, events: list[str]) -> str | None:
    for event in reversed(events):
        tree = repo.get(event).payload().get("tree")
        if tree:
            return tree
    return None


def _write(repo: Any, kind: str, payload: Any, expected: str, schema: int = 1) -> None:
    got = repo.put(kind, payload, schema, redact=False)
    if got != expected:  # pragma: no cover - a writer that re-spells the payload
        raise MergeError("merge.malformed", f"{kind} wrote {got}, computed {expected}")


def _move(repo: Any, ref: str | None, oid: str, expected_old: str | None) -> None:
    if ref:
        repo.update_ref(ref, oid, expected_old=expected_old, actor="merge")


def merge_runs(repo: Any, ours: str, theirs: str, *, ref: str | None = None) -> dict[str, Any]:
    """Merge *theirs* into *ours*; ``{run, event, parents, conflicts, status, tree}``."""
    old = repo.read_ref(ref) if ref else None
    ours_oid, ours_payload = _run(repo, ours)
    theirs_oid, theirs_payload = _run(repo, theirs)
    common = [e for e in ours_payload["events"] if e in set(theirs_payload["events"])]
    trees = {
        "base": flatten(repo, _last_tree(repo, common)),
        "ours": flatten(repo, _last_tree(repo, ours_payload["events"])),
        "theirs": flatten(repo, _last_tree(repo, theirs_payload["events"])),
    }
    plan = merge_payloads(ours_payload, theirs_payload, trees)
    for oid, (schema, body) in plan["blobs"].items():
        _write(repo, "blob", body, oid, schema)
    _write(repo, "event", plan["event"], plan["event_oid"])
    _write(repo, "run", plan["run"], plan["run_oid"])
    _move(repo, ref, plan["run_oid"], old)
    return {"run": plan["run_oid"], "event": plan["event_oid"], "parents": [ours_oid, theirs_oid],
            "base_events": len(common), "conflicts": plan["conflicts"],
            "status": plan["status"], "tree": plan["tree"], "ref": ref}  # fmt: skip


def pick_events(
    repo: Any, ours: str, events: list[str], *, ref: str | None = None
) -> dict[str, Any]:
    """Copy *events* (event oids, any run's) onto *ours*; ``{run, picked, forked_from}``."""
    old = repo.read_ref(ref) if ref else None
    ours_oid, ours_payload = _run(repo, ours)
    picks = []
    for event in events:
        if not repo.has(event) or repo.get(event).object_type != "event":
            raise MergeError("merge.missing", f"no such event: {event}")
        picks.append((event, repo.get(event).payload()))
    plan = pick_payloads(ours_payload, picks)
    for oid, payload in plan["events"]:
        _write(repo, "event", payload, oid)
    _write(repo, "run", plan["run"], plan["run_oid"])
    _move(repo, ref, plan["run_oid"], old)
    picked = [{"from": source, "event": copy} for source, copy in plan["map"].items()]
    return {"run": plan["run_oid"], "forked_from": ours_oid, "ref": ref, "picked": picked}


__all__ = ["merge_runs", "pick_events"]
