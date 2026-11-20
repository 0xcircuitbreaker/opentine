"""Three-way merge of run histories: refs, labels, lineage and holds (0.69, F2).

A *history snapshot* (``opentine-history-snapshot/1``) is what one branch or
remote of a self-improving loop holds::

    {"format": "opentine-history-snapshot/1",
     "refs":    {"heads/main": "run:sha256:HEX", ...},
     "labels":  {"prod": {"current": "run:sha256:HEX" | null,
                          "history": ["HEX", ...]}},     # sha256 per decision row
     "lineage": {"sha256:VARIANT": "HEX", ...},          # sha256 of the record file
     "holds":   [["TARGET", "OID"], ...]}                # sorted, unique

:func:`merge` takes a base and two sides and returns the merged snapshot and
its conflicts. It is symmetric: ``merge(b, o, t) == merge(b, t, o)``, conflicts
included, because a conflict names its two side values sorted, never "ours" and
"theirs", and a conflicting key keeps the base value. Conflict kinds:

``ref-diverged``       both sides moved a ref to different objects
``label-moved``        both sides moved a label to different runs
``promotion-diverged`` the label's decision histories do not extend each other
``lineage-id``         one variant id names two different records
``hold-weakened``      a hold of the base is gone on one side (it is kept)
``held-target``        a ref or label moved onto an object that a loop-stop,
                       taint or quarantine hold in the base or on either side
                       names (it stays at the base value)

Nothing is resolved in favour of the side that weakens a hold: holds are the
union of all three, and refs and lineage records are append-only (one missing
on one side is not a deletion: a merge never deletes a ref or a record).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine.kernel import OID_RE, canonical_json

FORMAT = "opentine-history-snapshot/1"
DOMAIN = b"opentine.history-snapshot.v1:"
#: Hold targets that stop a name from moving onto what they name, when one side adds them.
GUARDS = ("loop-stop:", "integrity-taint:", "memory-quarantine:")
KINDS = ("ref-diverged", "label-moved", "promotion-diverged", "lineage-id", "hold-weakened",
         "held-target")  # fmt: skip
_EMPTY_LABEL = {"current": None, "history": []}
#: Label names and lineage ids become file names on apply: only these shapes.
LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
LINEAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")


def empty() -> dict[str, Any]:
    return {"format": FORMAT, "refs": {}, "labels": {}, "lineage": {}, "holds": []}


def normalize(snapshot: Any) -> dict[str, Any]:
    """A checked copy of *snapshot*; ``ValueError`` names what is malformed."""
    if not isinstance(snapshot, dict) or snapshot.get("format") != FORMAT:
        raise ValueError(f"a history snapshot has format {FORMAT}")
    if set(snapshot) != {"format", "refs", "labels", "lineage", "holds"}:
        raise ValueError("a history snapshot has exactly format, refs, labels, lineage, holds")
    for name in ("refs", "lineage"):
        table = snapshot[name]
        if not isinstance(table, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and k and v for k, v in table.items()
        ):
            raise ValueError(f"{name} maps names to strings")
    if not all(LINEAGE_RE.fullmatch(k) for k in snapshot["lineage"]):
        raise ValueError("lineage ids are sha256:HEX")
    labels = snapshot["labels"]
    if not isinstance(labels, dict):
        raise ValueError("labels is an object")
    if not all(isinstance(k, str) and LABEL_RE.fullmatch(k) for k in labels):
        raise ValueError("label names are [a-z0-9][a-z0-9._-]{0,63}")
    for label, state in labels.items():
        if not isinstance(state, dict) or set(state) != {"current", "history"}:
            raise ValueError(f"label {label!r} is {{current, history}}")
        if state["current"] is not None and not isinstance(state["current"], str):
            raise ValueError(f"label {label!r} current is a run oid or null")
        if not isinstance(state["history"], list) or not all(
            isinstance(h, str) for h in state["history"]
        ):
            raise ValueError(f"label {label!r} history is a list of digests")
    holds = snapshot["holds"]
    if not isinstance(holds, list) or not all(
        isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in holds
    ):
        raise ValueError("holds is a list of [target, oid] pairs")
    if not all(0 < len(t) <= 1024 and OID_RE.fullmatch(o) for t, o in holds):
        raise ValueError("holds name a 1..1024 character target and a run oid")
    pairs = sorted({(t, o) for t, o in holds})
    if len(pairs) != len(holds):
        raise ValueError("holds are unique")
    return {"format": FORMAT, "refs": dict(snapshot["refs"]),
            "labels": {k: {"current": v["current"], "history": list(v["history"])}
                       for k, v in labels.items()},
            "lineage": dict(snapshot["lineage"]),
            "holds": [list(p) for p in pairs]}  # fmt: skip


def digest(snapshot: Any) -> str:
    """``sha256:`` over the domain and JCS of the normalized snapshot."""
    return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(normalize(snapshot))).hexdigest()


def _sides(a: Any, b: Any) -> list[Any]:
    return sorted([a, b], key=canonical_json)


def _conflict(kind: str, key: str, base: Any, a: Any, b: Any) -> dict[str, Any]:
    return {"kind": kind, "key": key, "base": base, "sides": _sides(a, b)}


def _three(base: Any, ours: Any, theirs: Any) -> tuple[Any, bool]:
    """The three-way value and whether it conflicts (then the base value)."""
    if ours == theirs:
        return ours, False
    if ours == base:
        return theirs, False
    if theirs == base:
        return ours, False
    return base, True


def _extends(longer: list[str], shorter: list[str]) -> bool:
    return longer[: len(shorter)] == shorter


def _label(base: dict, ours: dict, theirs: dict) -> tuple[dict, str | None]:
    hb, ho, ht = base["history"], ours["history"], theirs["history"]
    if not (_extends(ho, hb) and _extends(ht, hb)) or not (_extends(ho, ht) or _extends(ht, ho)):
        return base, "promotion-diverged"
    history = ho if len(ho) >= len(ht) else ht
    current, clash = _three(base["current"], ours["current"], theirs["current"])
    if clash:
        return base, "label-moved"
    return {"current": current, "history": list(history)}, None


def _guarded(base: set, ours: set, theirs: set) -> set[str]:
    """Names (oids and target suffixes) a guard hold in base or on either side protects."""
    out: set[str] = set()
    for target, oid in base | ours | theirs:
        if target.startswith(GUARDS):
            out.add(oid)
            out.add(target.split(":", 1)[1])
    return out


def merge(base: Any, ours: Any, theirs: Any) -> dict[str, Any]:
    """``{"merged": snapshot, "conflicts": [...], "digests": {...}}`` (deterministic)."""
    b, o, t = normalize(base), normalize(ours), normalize(theirs)
    conflicts: list[dict[str, Any]] = []
    hb, ho, ht = ({tuple(h) for h in s["holds"]} for s in (b, o, t))
    guarded = _guarded(hb, ho, ht)
    refs: dict[str, str] = {}
    for name in sorted(set(b["refs"]) | set(o["refs"]) | set(t["refs"])):
        vb = b["refs"].get(name)
        vo, vt = (s["refs"].get(name, vb) for s in (o, t))  # a merge never deletes a ref
        value, clash = _three(vb, vo, vt)
        if clash:
            conflicts.append(_conflict("ref-diverged", name, vb, vo, vt))
        elif value != vb and value in guarded:
            conflicts.append(_conflict("held-target", f"refs/{name}", vb, vo, vt))
            value = vb
        if value is not None:
            refs[name] = value
    labels: dict[str, dict] = {}
    for name in sorted(set(b["labels"]) | set(o["labels"]) | set(t["labels"])):
        sb, so, st = (s["labels"].get(name, _EMPTY_LABEL) for s in (b, o, t))
        state, kind = _label(sb, so, st)
        if kind is not None:
            conflicts.append(_conflict(kind, name, sb, so, st))
        elif state["current"] != sb["current"] and state["current"] in guarded:
            conflicts.append(_conflict("held-target", f"labels/{name}", sb, so, st))
            state = sb
        if state != _EMPTY_LABEL:
            labels[name] = {"current": state["current"], "history": list(state["history"])}
    lineage: dict[str, str] = {}
    for ident in sorted(set(b["lineage"]) | set(o["lineage"]) | set(t["lineage"])):
        found = {s["lineage"][ident] for s in (b, o, t) if ident in s["lineage"]}
        if len(found) > 1:
            vb, vo, vt = (s["lineage"].get(ident) for s in (b, o, t))
            conflicts.append(_conflict("lineage-id", ident, vb, vo, vt))
            if vb is not None:
                lineage[ident] = vb
        else:
            lineage[ident] = found.pop()
    for target, oid in sorted(hb - (ho & ht)):
        conflicts.append(_conflict("hold-weakened", target, oid, (target, oid) in ho,
                                   (target, oid) in ht))  # fmt: skip
    merged = {"format": FORMAT, "refs": refs, "labels": labels, "lineage": lineage,
              "holds": [list(h) for h in sorted(hb | ho | ht)]}  # fmt: skip
    conflicts.sort(key=lambda c: (KINDS.index(c["kind"]), c["key"], canonical_json(c)))
    return {"merged": merged, "conflicts": conflicts,
            "digests": {"base": digest(b), "sides": _sides(digest(o), digest(t)),
                        "merged": digest(merged)}}  # fmt: skip


__all__ = ["DOMAIN", "FORMAT", "GUARDS", "KINDS", "digest", "empty", "merge", "normalize"]
