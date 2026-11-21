"""Selection expressions and content-defined dedup for ``tine dataset curate`` (0.75).

An expression is terms joined by ``and``; a term may start with ``not``::

    all                     every run (record anchors excluded)
    failures:EVAL           runs with a signed eval verdict of EVAL that did not pass
    passes:EVAL             runs with a signed eval verdict of EVAL that passed
    eval:EVAL               runs with any signed eval verdict of EVAL
    model:GLOB              runs whose model_info matches GLOB (fnmatch)
    run:RUN                 one run id

``failures of eval E`` is read as ``failures:E``. Eval verdicts come from the
lineage ``evals/*.jsonl`` files and each ``--evals DIR``'s ``verdicts.jsonl``
(as ``tine query`` indexes them); a verdict whose signature does not verify is
ignored. Runs whose ``model_info`` starts ``opentine/`` are record anchors,
never candidates.

Dedup cuts each candidate's redacted transcript text (the text ``tine
transcripts`` analyses, the run's own id removed) into FastCDC chunks with
the fixed :data:`opentine._dataset_claims.CHUNKING` parameters; the content
digest is SHA-256 over the chunk digests. Candidates with the same content
keep the smallest run id; the rest are recorded as dropped.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import Path
from typing import Any

from opentine._dataset_claims import CHUNKING

_ALIAS = re.compile(r"^failures of eval (\S+)$")
_ATOMS = ("failures", "passes", "eval", "model", "run")


def parse(expr: str) -> list[tuple[bool, str, str]]:
    """``[(negated, atom, argument)]``; raises ``ValueError`` for anything else."""
    text = expr.strip()
    alias = _ALIAS.match(text)
    if alias:
        text = f"failures:{alias.group(1)}"
    if not text:
        raise ValueError("the selection is empty")
    terms = []
    for part in re.split(r"\s+and\s+", text):
        words = part.split()
        negated = bool(words) and words[0] == "not"
        words = words[1:] if negated else words
        if len(words) != 1:
            raise ValueError(f"cannot read the term {part!r}")
        atom, _, arg = words[0].partition(":")
        if atom == "all" and not arg:
            terms.append((negated, "all", ""))
        elif atom in _ATOMS and arg:
            terms.append((negated, atom, arg))
        else:
            raise ValueError(f"unknown term {words[0]!r}: use all, {', '.join(_ATOMS)}")
    return terms


def _verdicts(repo: Any, dirs: list[str]) -> list[dict[str, Any]]:
    from opentine._query_build import eval_files, remembered_dirs
    from opentine._query_rows import verdict_lines

    store = Path(repo.path)
    folders = sorted({*remembered_dirs(store), *(Path(d).resolve().as_posix() for d in dirs)})
    rows = []
    for source, raw in sorted(eval_files(store, folders).items()):
        rows += [r for r in verdict_lines(source, raw) if r["signed"]]
    return rows


def candidates(repo: Any, expr: str, eval_dirs: list[str] | None = None) -> list[str]:
    """The run ids *expr* selects, sorted."""
    terms = parse(expr)
    runs: dict[str, str] = {}
    for oid in repo.iter_oids():
        if oid.startswith("run:"):
            payload = repo.get(oid).payload()
            model = payload.get("model_info") if isinstance(payload, dict) else None
            model = model if isinstance(model, str) else ""
            if not model.startswith("opentine/"):
                runs[oid] = model
    verdicts = _verdicts(repo, eval_dirs or []) if any(t[1] in _ATOMS[:3] for t in terms) else []

    def by_eval(name: str, passed: int | None) -> set[str]:
        return {v["run"] for v in verdicts
                if v["eval"] == name and (passed is None or v["passed"] == passed)}  # fmt: skip

    chosen = set(runs)
    for negated, atom, arg in terms:
        if atom == "all":
            hit = set(runs)
        elif atom == "model":
            hit = {r for r, m in runs.items() if fnmatch.fnmatchcase(m, arg)}
        elif atom == "run":
            hit = {arg}
        else:
            hit = by_eval(arg, {"failures": 0, "passes": 1, "eval": None}[atom])
        chosen = chosen - hit if negated else chosen & hit
    return sorted(chosen & set(runs))


def content_digest(text: str) -> str:
    from opentine.remote._fastcdc import ChunkParams, chunks

    params = ChunkParams(CHUNKING["min"], CHUNKING["avg"], CHUNKING["max"])
    outer = hashlib.sha256()
    for chunk in chunks(text.encode("utf-8"), params):
        outer.update(hashlib.sha256(chunk).digest())
    return "sha256:" + outer.hexdigest()


def dedup(repo: Any, runs: list[str]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """``(members, dropped)``: one member per content digest, the smallest run id kept."""
    from opentine._pii_classify import load as load_classifier
    from opentine.repository._embed_index import redacted_text

    classifier = load_classifier()
    kept: dict[str, str] = {}
    members, dropped = [], []
    for run in sorted(runs):
        text = (redacted_text(repo, run, classifier) or "").replace(run, "")
        digest = content_digest(text)
        if digest in kept:
            dropped.append({"run": run, "same_as": kept[digest]})
            continue
        kept[digest] = run
        members.append({"run": run, "content": digest})
    return members, dropped


__all__ = ["candidates", "content_digest", "dedup", "parse"]
