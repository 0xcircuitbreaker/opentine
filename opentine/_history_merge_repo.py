"""A repository's history snapshot, and applying a history merge to it (0.69).

:func:`snapshot` reads what :mod:`opentine._history_merge` merges: the
``heads/`` and ``tags/`` refs, the label states of ``.tine/promotion`` (each
decision row by its sha256), the lineage folder's variant records (each by the
sha256 of its file) and the hold rows.

:func:`apply` lands a conflict-free merge as ref updates plus one signed
attestation, no new kind:

* refs move by one compare-and-swap transaction from this repository's own
  values; a ref a merge queue owns (``coord/merge-queue/*`` with that target)
  is not moved but its new run is enqueued, so the queue lands it;
* label states and lineage records come from the other side's folders, and
  each file must hash to what the merged snapshot names (lineage records must
  also verify as signed);
* holds are only ever added;
* the ``opentine.history-merge/1`` attestation is stored and held
  (``history-merge:`` rows are never released).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._history_merge import FORMAT, merge
from opentine.kernel import canonical_json

PREFIXES = ("heads/", "tags/")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _label_rows(state: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(state.glob("*.json")) if state.is_dir() else []:
        record = json.loads(path.read_bytes().decode("utf-8"))
        out[path.stem] = record
    return out


def _label(record: dict[str, Any]) -> dict[str, Any]:
    rows = record.get("history") or []
    return {"current": record.get("current"), "history": [_sha(canonical_json(r)) for r in rows]}


def snapshot(repo: Any, *, state: Path, lineage: Path) -> dict[str, Any]:
    """This repository's ``opentine-history-snapshot/1``."""
    from opentine.repository._holds import holds_path, read_holds

    refs = {name: oid for name, oid in repo.list_refs().items() if name.startswith(PREFIXES)}
    labels = {name: _label(rec) for name, rec in _label_rows(Path(state)).items()}
    variants = Path(lineage) / "variants"
    records = {f"sha256:{p.stem}": _sha(p.read_bytes())
               for p in (sorted(variants.glob("*.json")) if variants.is_dir() else [])}  # fmt: skip
    holds = sorted({(r["target"], r["oid"]) for r in read_holds(holds_path(repo))})
    return {"format": FORMAT, "refs": refs, "labels": labels, "lineage": records,
            "holds": [list(h) for h in holds]}  # fmt: skip


def _queues(repo: Any) -> dict[str, str]:
    """``{target ref: queue id}`` for the merge queues of this repository."""
    from opentine.coord._merge_queue import PREFIX, get

    out: dict[str, str] = {}
    for name in repo.list_refs():
        if name.startswith(PREFIX):
            queue = name[len(PREFIX) :]
            out.setdefault(get(repo, queue)["target"], queue)
    return out


def _lineage_files(merged: dict, ours: dict, theirs_lineage: Path | None, lineage: Path) -> list:
    from opentine._lineage import loads, signed

    added = []
    for ident, digest in sorted(merged["lineage"].items()):
        if ours["lineage"].get(ident) == digest:
            continue
        source = (theirs_lineage or Path("\0")) / "variants" / f"{ident[7:]}.json"
        raw = source.read_bytes() if theirs_lineage is not None and source.is_file() else None
        if raw is None or _sha(raw) != digest or not signed(loads(raw)):
            raise ValueError(f"history-merge.lineage-missing: no signed record {ident} hashing "
                             f"to {digest} under --theirs-lineage")  # fmt: skip
        added.append((ident, lineage / "variants" / f"{ident[7:]}.json", raw))
    return added


def _label_files(merged: dict, ours: dict, theirs_state: Path | None, state: Path) -> list:
    rows = _label_rows(theirs_state) if theirs_state is not None else {}
    moved = []
    for label, want in sorted(merged["labels"].items()):
        if ours["labels"].get(label) == want:
            continue
        record = rows.get(label)
        if record is None or _label(record) != want:
            raise ValueError(f"history-merge.label-missing: no label state {label} matching the "
                             "merge under --theirs-state")  # fmt: skip
        text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        moved.append((label, state / f"{label}.json", text.encode("utf-8")))
    return moved


def plan(repo: Any, base: Any, theirs: Any, *, state: Path, lineage: Path) -> dict[str, Any]:
    ours = snapshot(repo, state=state, lineage=lineage)
    return {"ours": ours, **merge(base, ours, theirs)}


def apply(repo: Any, key: Any, base: Any, theirs: Any, *, state: Path, lineage: Path,
          subject: str | None, target: str | None, at: str, actor: str = "history-merge",
          theirs_state: Path | None = None,
          theirs_lineage: Path | None = None) -> dict[str, Any]:  # fmt: skip
    """Land the merge (refusing on any conflict); the applied changes and the record oid."""
    from opentine._history_merge_record import sign
    from opentine.coord._merge_queue import enqueue
    from opentine.repository._holds import HISTORY_MERGE, edit_holds, holds_path

    found = plan(repo, base, theirs, state=Path(state), lineage=Path(lineage))
    ours, merged = found["ours"], found["merged"]
    if found["conflicts"]:
        return {"applied": False, **found}
    subject = subject or (merged["refs"].get(target) if target else None)
    if not subject or not str(subject).startswith("run:"):
        raise ValueError("history-merge.subject: name --subject RUN, or a --target ref on a run")
    missing = sorted(o for o in merged["refs"].values() if not repo.has(o))
    if missing:
        raise ValueError(f"history-merge.objects-missing: fetch {missing[0]} first")
    queues = _queues(repo)
    moves = [(n, o, ours["refs"].get(n)) for n, o in sorted(merged["refs"].items())
             if ours["refs"].get(n) != o]  # fmt: skip
    queued = [{"ref": n, "run": o, "queue": queues[n]} for n, o, _ in moves if n in queues]
    direct = [m for m in moves if m[0] not in queues]
    files = [
        *_lineage_files(merged, ours, theirs_lineage, Path(lineage)),
        *_label_files(merged, ours, theirs_state, Path(state)),
    ]  # all checked first
    for _, path, raw in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record = sign(key, found, subject=subject, target=target, at=at)
    oid = repo.put("attestation", record)
    have = {tuple(h) for h in ours["holds"]}
    new_rows = [{"target": t, "oid": o} for t, o in merged["holds"] if (t, o) not in have]
    new_rows.append({"target": HISTORY_MERGE + found["digests"]["merged"], "oid": oid})
    edit_holds(holds_path(repo), lambda rows: [*rows, *(r for r in new_rows if r not in rows)])
    if direct:
        repo.update_refs(direct, actor=actor)
    for row in queued:
        enqueue(repo, row["queue"], row["run"], actor)
    return {"applied": True, **found, "record": oid,
            "refs_moved": [m[0] for m in direct], "queued": queued,
            "labels_moved": [n for n, p, _ in files if p.parent == Path(state)],
            "lineage_added": [n for n, p, _ in files if p.parent != Path(state)],
            "holds_added": len(new_rows)}  # fmt: skip


__all__ = ["PREFIXES", "apply", "plan", "snapshot"]
