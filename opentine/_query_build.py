"""Building the query index from a repository, and telling when it is stale (0.65).

Sources: every ``run``, ``attestation`` and ``annotation`` object of the store
(runs and their steps, monitor verdicts, oversight decisions), the lineage
folder ``.tine/lineage`` (variants, edges and the eval verdicts filed under
``evals/``) and any eval folder given with ``--evals DIR`` (its
``verdicts.jsonl``), and the experiment manifests and reproduce reports of
``.tine/experiments`` and each ``--experiments DIR``
(:mod:`opentine._query_experiments`), and the elicitation links of
``.tine/elicit/links`` (:mod:`opentine._query_research`). Both kinds of folder are remembered in
``meta``, so the staleness check and the next rebuild read the same ones.
"""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
from typing import Any

from opentine import _query_experiments as qx
from opentine import _query_index as qi
from opentine import _query_research as qe
from opentine import _query_rows as qr


def _lineage_files(store: Path) -> dict[str, bytes]:
    from opentine._lineage import read_folder

    folder = store / "lineage"
    return read_folder(folder) if folder.is_dir() else {}


def eval_files(store: Path, dirs: list[str]) -> dict[str, bytes]:
    """``{source: bytes}``: lineage ``evals/*.jsonl`` and each DIR's ``verdicts.jsonl``."""
    out = {f"lineage/{name}": raw for name, raw in _lineage_files(store).items()
           if name.startswith("evals/") and name.endswith(".jsonl")}  # fmt: skip
    for folder in dirs:
        path = Path(folder) / "verdicts.jsonl"
        if path.is_file():
            out[path.as_posix()] = path.read_bytes()
    return out


def eval_source(store: Path, source: str) -> Path:
    return store / source if source.startswith("lineage/") else Path(source)


def sources(store: Path, dirs: list[str], exps: list[str]) -> dict[str, str]:
    lineage = _lineage_files(store)
    return {"lineage": qi.files_digest(lineage),
            "evals": json.dumps({"dirs": dirs, "digest": qi.files_digest(eval_files(store, dirs))},
                                sort_keys=True),
            "experiments": json.dumps({"dirs": exps, "digest": qi.files_digest(
                qx.experiment_files(store, exps))}, sort_keys=True),
            "elicit": qi.files_digest(qe.elicit_files(store))}  # fmt: skip


#: Below this many objects the build reads in-process; above, in worker processes.
PARALLEL_FROM = 20_000
_CHUNK = 5_000
_KINDS = ("run", "attestation", "annotation")


def _read_chunk(project: str, oids: list[str]) -> dict[str, list[tuple]]:
    """Rows of *oids* as tuples (a worker's job; opens its own repository)."""
    from opentine.repository import Repo

    repo = Repo.open(project)
    read = qr.fast_reader(repo)
    out: dict[str, list[tuple]] = {}
    for oid in oids:
        for name, rows in qr.object_rows(repo, oid, read).items():
            columns = qr.COLUMNS[name]
            out.setdefault(name, []).extend(tuple(r[c] for c in columns) for r in rows)
    return out


def _object_chunks(repo: Any, oids: list[str], workers: int | None):
    wanted = [o for o in oids if o.partition(":")[0] in _KINDS]
    pieces = [wanted[i : i + _CHUNK] for i in range(0, len(wanted), _CHUNK)]
    project = Path(repo.path).parent.as_posix()
    if workers is None:
        workers = min(os.cpu_count() or 1, 8) if len(wanted) >= PARALLEL_FROM else 1
    if workers <= 1:
        yield from (_read_chunk(project, piece) for piece in pieces)
        return
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(max_workers=workers) as pool:
        yield from pool.map(_read_chunk, [project] * len(pieces), pieces)


def build(repo: Any, dirs: list[str] | None = None, *, workers: int | None = None,
          experiments: list[str] | None = None) -> dict:  # fmt: skip
    """Rebuild the index; ``{"path", "counts"}``. Objects are read in chunks, in order.

    *experiments* ``None`` keeps the remembered experiment folders.
    """
    store = Path(repo.path)
    dirs = sorted({Path(d).resolve().as_posix() for d in dirs or []})
    exps = remembered_dirs(store, "experiments") if experiments is None else experiments
    exps = sorted({Path(d).resolve().as_posix() for d in exps})
    fingerprint = qi.fingerprint(store)
    oids = list(repo.iter_oids())
    files = {"evals": [r for source, raw in sorted(eval_files(store, dirs).items())
                       for r in qr.verdict_lines(source, raw)],
             **qr.lineage_rows(_lineage_files(store)),
             **qx.rows(qx.experiment_files(store, exps)),
             **qe.rows(qe.elicit_files(store))}  # fmt: skip
    meta = {"fingerprint": fingerprint, "objects": qi.objects_digest(oids),
            **sources(store, dirs, exps)}  # fmt: skip
    path = qi.index_path(store)
    chunks = itertools.chain(_object_chunks(repo, oids, workers), [files])
    return {"path": path.as_posix(), "counts": qi.write(path, chunks, meta)}


def remembered_dirs(store: Path, key: str = "evals") -> list[str]:
    path = qi.index_path(store)
    if not path.is_file():
        return []
    try:
        return list(json.loads(qi.read_meta(path).get(key, "{}")).get("dirs", []))
    except (ValueError, AttributeError):
        return []


def staleness(repo: Any, *, exact: bool = False) -> dict[str, Any]:
    """``{"exists", "stale", "reasons"}``; *exact* compares object ids even on a stat match."""
    store = Path(repo.path)
    path = qi.index_path(store)
    if not path.is_file():
        return {"exists": False, "stale": True, "reasons": ["the index has not been built"]}
    meta = qi.read_meta(path)
    reasons = []
    if meta.get("format") != qi.FORMAT:
        reasons.append("the index was written in another format")
    dirs = remembered_dirs(store)
    now = sources(store, dirs, remembered_dirs(store, "experiments"))
    for key, why in (("lineage", "the lineage folder changed"),
                     ("evals", "an eval folder changed"),
                     ("experiments", "an experiment folder changed"),
                     ("elicit", "the elicitation folder changed")):  # fmt: skip
        if meta.get(key) != now[key]:
            reasons.append(why)
    fingerprint = qi.fingerprint(store)
    if exact or meta.get("fingerprint") != fingerprint:
        if meta.get("objects") != qi.objects_digest(repo.iter_oids()):
            reasons.append("objects were added or removed since the build")
        elif meta.get("fingerprint") != fingerprint and not reasons:
            qi.set_meta(path, "fingerprint", fingerprint)  # repacked, same objects
    return {"exists": True, "stale": bool(reasons), "reasons": reasons}


__all__ = [
    "PARALLEL_FROM",
    "build",
    "eval_files",
    "eval_source",
    "remembered_dirs",
    "sources",
    "staleness",
]
