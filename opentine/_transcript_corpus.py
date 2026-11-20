"""What ``tine transcripts`` analyses (0.74): repository runs or a JSONL corpus.

From a repository, every ``run:`` object's indexed text (the same text the
search index holds) after credential and PII redaction
(:func:`opentine.repository._embed_index.redacted_text`), so no analysis or
annotation can recover a secret. From ``--corpus FILE.jsonl``, one object per
line with ``id`` and ``text`` (and optionally ``behaviour``, used only by the
recall evaluation), as the committed synthetic corpus has.
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
            out[oid] = text
    return out


def from_files(paths: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """``({id: text}, {id: behaviour})`` from JSONL corpus files; ids must be unique."""
    texts: dict[str, str] = {}
    behaviours: dict[str, str] = {}
    for path in paths:
        for number, line in enumerate(Path(path).read_bytes().decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            where = f"{Path(path).as_posix()}:{number}"
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
