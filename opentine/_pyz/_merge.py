"""SPEC 4.19 run merge and pick, standard library only (0.47).

An independent port of :func:`opentine._merge.merge_payloads` and
:func:`opentine._merge.pick_payloads` (with :mod:`opentine._merge_tree`) for
``tine-verify.pyz``, so the pyz recomputes a merge run's oid from its two
parents without importing opentine. :func:`compute_case` and
:func:`pick_case` answer the ``merge.compute`` and ``merge.pick`` conformance
ops; refusals raise :class:`Refused` with the suite's ``merge.*`` codes.
"""

from __future__ import annotations

from typing import Any

from .. import kernel

_LEAF_MODES = ("100644", "100755", "120000")
_EMPTY = {"billing": {}, "causal_ids": [], "cost": 0, "duration": 0, "error": {}, "model": "",
          "tool": {}, "usage": {}}  # fmt: skip


class Refused(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _bad(message: str) -> Refused:
    return Refused("merge.malformed", f"merge input is malformed: {message}")


def run_oid(payload: Any) -> str:
    return kernel.ObjectEnvelope.create("run", payload).oid


def _events(payload: Any, side: str) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise _bad(f"{side} is not a run")
    rows = payload["events"]
    if not rows or not all(isinstance(e, str) for e in rows) or len(set(rows)) != len(rows):
        raise _bad(f"{side} events")
    for field in ("tips", "roots"):
        if not isinstance(payload.get(field), list) or not set(payload[field]) <= set(rows):
            raise _bad(f"{side} {field}")
    return rows


def _uniq(rows: list[str]) -> list[str]:
    return list(dict.fromkeys(rows))


def _flat(flat: Any) -> dict[str, dict[str, Any]]:
    if flat is None:
        return {}
    if not isinstance(flat, dict):
        raise _bad("a flat tree is an object of path -> leaf")
    for path, leaf in flat.items():
        if (
            not isinstance(leaf, dict)
            or set(leaf) - {"mode", "oid", "redacted"}
            or leaf.get("mode") not in _LEAF_MODES
            or leaf.get("redacted", True) is not True
        ):
            raise _bad(f"malformed tree leaf: {path}")
        try:
            kernel.parse_oid(leaf.get("oid"))
        except kernel.KernelError as exc:
            raise _bad(f"malformed tree leaf: {path}") from exc
        parts = path.split("/")
        if not path or any(p in ("", ".", "..") or "\\" in p or "\0" in p for p in parts):
            raise _bad(f"invalid tree path: {path!r}")
    return flat


def _merge_flat(base: Any, ours: Any, theirs: Any) -> tuple[dict, list]:
    base, ours, theirs = _flat(base), _flat(ours), _flat(theirs)
    merged: dict[str, Any] = {}
    conflicts: list[dict[str, Any]] = []
    for path in sorted({*base, *ours, *theirs}, key=lambda p: p.encode("utf-8")):
        b, o, t = base.get(path), ours.get(path), theirs.get(path)
        take = o if (o == t or t == b) else t if o == b else o
        if not (o == t or t == b or o == b):
            conflicts.append({"kind": "tree", "path": path, "base": b and b["oid"],
                              "ours": o and o["oid"], "theirs": t and t["oid"]})  # fmt: skip
        if take is not None:
            merged[path] = take
    for path in merged:
        if any(other.startswith(path + "/") for other in merged):
            raise _bad(f"tree merge puts a file and a directory at {path}")
    return merged, conflicts


def _tree(rows: dict[str, Any]) -> str:
    files: list[dict[str, Any]] = []
    dirs: dict[str, dict[str, Any]] = {}
    for path, leaf in rows.items():
        head, _, rest = path.partition("/")
        if rest:
            dirs.setdefault(head, {})[rest] = leaf
        else:
            files.append({**leaf, "name": head})
    for name, sub in dirs.items():
        files.append({"mode": "40000", "name": name, "oid": _tree(sub)})
    files.sort(key=lambda row: row["name"].encode("utf-8"))
    body = kernel.canonical_json({"entries": files, "type": "opentine.tree"})
    return kernel.object_id("blob", 2, body)


def compute_case(value: dict[str, Any]) -> dict[str, Any]:
    """A ``merge.compute`` input -> ``{run, event, tree, status, conflicts}``."""
    ours, theirs = value.get("ours"), value.get("theirs")
    mine, other = _events(ours, "ours"), _events(theirs, "theirs")
    ours_oid, theirs_oid = run_oid(ours), run_oid(theirs)
    if ours_oid == theirs_oid:
        raise Refused("merge.same-run", "cannot merge a run with itself")
    if set(other) <= set(mine):
        raise Refused("merge.up-to-date", "theirs is already contained in ours: up to date")
    union = [e for e in mine if e in set(other)]
    union += [e for e in mine if e not in set(other)] + [e for e in other if e not in set(mine)]
    trees = value.get("trees") if isinstance(value.get("trees"), dict) else {}
    conflicts: list[dict[str, Any]] = []
    tree = None
    if trees.get("ours") is not None and trees.get("theirs") is not None:
        flat, conflicts = _merge_flat(trees.get("base"), trees["ours"], trees["theirs"])
        tree = _tree(flat)
    policy = [(side.get("manifests") or {}).get("policy") for side in (ours, theirs)]
    if policy[0] != policy[1]:
        conflicts.append({"kind": "manifest", "name": "policy", "base": None,
                          "ours": policy[0], "theirs": policy[1]})  # fmt: skip
    output = kernel.object_id(
        "blob",
        1,
        kernel.canonical_json(
            {"conflicts": conflicts, "merged": [ours_oid, theirs_oid], "type": "opentine.merge"}
        ),
    )
    numbers = [s.get("created_at") for s in (ours, theirs)]
    numbers = [n for n in numbers if isinstance(n, int | float) and not isinstance(n, bool)]
    at = max(numbers) if numbers else 0
    inner = {e for s in (ours, theirs) for e in s["events"] if e not in s["tips"]}
    parents = [e for e in _uniq([*ours["tips"], *theirs["tips"]]) if e not in inner]
    event = {**_EMPTY, "kind": "merge", "output_blob": output, "parent_ids": parents,
             "time_unix": at, **({"tree": tree} if tree else {})}  # fmt: skip
    event_oid = kernel.ObjectEnvelope.create("event", event).oid
    status = "paused" if conflicts else "completed"
    run = {k: v for k, v in ours.items() if k not in ("forked_from", "parents")}
    run.update(
        events=[*union, event_oid],
        roots=_uniq([*ours["roots"], *theirs["roots"]]),
        tips=[event_oid],
        parents=[ours_oid, theirs_oid],
        created_at=at,
        status=status,
    )
    return {"run": run_oid(run), "event": event_oid, "tree": tree, "status": status,
            "conflicts": conflicts}  # fmt: skip


def pick_case(value: dict[str, Any]) -> dict[str, Any]:
    """A ``merge.pick`` input -> ``{run, events}``."""
    ours = value.get("ours")
    rows = list(_events(ours, "ours"))
    picks = value.get("picks")
    if not isinstance(picks, list) or not picks:
        raise _bad("pick needs at least one event")
    held, mapping, tips, written = set(rows), {}, list(ours["tips"]), []
    for source, payload in picks:
        if not isinstance(payload, dict) or source in held:
            raise _bad(f"cannot pick {source}: already in the run")
        if kernel.ObjectEnvelope.create("event", payload).oid != source or source in mapping:
            raise _bad(f"cannot pick {source}: another event, or twice")
        links = payload.get("causal_ids") or []
        if not isinstance(links, list) or not all(isinstance(c, str) for c in links):
            raise _bad(f"cannot pick {source}: malformed causal_ids")
        causal = _uniq([mapping.get(c, c) for c in links if mapping.get(c, c) in held])
        copy = {**payload, "parent_ids": tips, "picked_from": source, "causal_ids": causal}
        oid = kernel.ObjectEnvelope.create("event", copy).oid
        if oid in held:
            raise _bad(f"picking {source} adds nothing")
        mapping[source] = oid
        held.add(oid)
        rows.append(oid)
        tips = [oid]
        written.append(oid)
    run = {k: v for k, v in ours.items() if k not in ("forked_from", "parents")}
    run.update(events=rows, tips=tips, forked_from=run_oid(ours))
    return {"run": run_oid(run), "events": written}


__all__ = ["Refused", "compute_case", "pick_case", "run_oid"]
