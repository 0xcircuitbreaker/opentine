"""What ``tine transcripts`` analyses (0.74): repository runs or a JSONL corpus.

From a repository, every ``run:`` object's indexed text (the same text the
search index holds) after credential and PII redaction
(:func:`opentine.repository._embed_index.redacted_text`), so no analysis or
annotation can recover a secret. The run's own object id is removed from its
text: it is a content hash that covers the run's wall-clock ``created_at``, so
as a feature it is a unique random token that says nothing about behaviour yet
moves clusters and scores between otherwise identical corpora.

From ``--corpus FILE.jsonl``, one object per line with ``id`` and ``text``
(and optionally ``behaviour``, used only by the recall evaluation), as the
committed synthetic corpus has.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_RUNS = 1_000_000


def from_repo(repo: Any, *, limit: int = MAX_RUNS) -> dict[str, str]:
    """``{run id: redacted text}`` for every run in *repo*."""
    from opentine._pii_classify import load as load_classifier
    from opentine.repository._embed_index import redacted_text

    classifier = load_classifier()
    out: dict[str, str] = {}
    for oid in sorted(o for o in repo.iter_oids(limit=limit) if o.startswith("run:")):
        text = redacted_text(repo, oid, classifier)
        if text is not None:
            out[oid] = text.replace(oid, "")
    return out


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise ValueError(f"{name} is not a finite number")


def _loads(line: str, where: str) -> Any:
    """Strict JSON: no duplicate keys, no NaN or Infinity (a later key cannot hide text)."""
    try:
        return json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}") from None


def from_files(paths: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """``({id: text}, {id: behaviour})`` from JSONL corpus files; ids must be unique."""
    texts: dict[str, str] = {}
    behaviours: dict[str, str] = {}
    for path in paths:
        for number, line in enumerate(Path(path).read_bytes().decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            where = f"{Path(path).as_posix()}:{number}"
            row = _loads(line, where)
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ValueError(f"{where}: a corpus line is an object with a string id")
            if not isinstance(row.get("text"), str):
                raise ValueError(f"{where}: text is a string")
            if row["id"] in texts:
                raise ValueError(f"{where}: duplicate id {row['id']}")
            texts[row["id"]] = row["text"]
            behaviours[row["id"]] = str(row.get("behaviour") or "none")
    return texts, behaviours


__all__ = ["MAX_RUNS", "from_files", "from_repo"]
