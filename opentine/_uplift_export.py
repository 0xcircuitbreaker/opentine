"""The uplift export (0.73): every counted record of one suite, in a fixed order.

``tine uplift horizon|compare`` compute from this export and nothing else, both
when reading a repository and when given ``--from FILE``, so the numbers a
report prints can be recomputed from the export byte for byte::

    {"format": "opentine-uplift-export/1", "suite": "sha256:..",
     "definition": {name, version, scoring, tasks}, "records": [ROW, ...],
     "findings": [{level, code, oid, message}]}

A ROW is the record claim without ``convention`` and ``at``, plus its ``oid``;
rows are sorted by ``oid``. Records that do not count stay out of ``records``
and are named in ``findings``: ``fail:uplift.malformed`` (signed by a pinned
key, ill formed), ``fail:uplift.key-separation`` (signed by a pinned optimizer
key), ``advisory:uplift.signer-unpinned`` and ``advisory:uplift.unknown-task``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json

FORMAT = "opentine-uplift-export/1"
_ROW = ("record", "task", "subject", "condition", "success", "minutes", "perceived_minutes",
        "generation")  # fmt: skip


def _finding(level: str, code: str, oid: str, message: str) -> dict[str, str]:
    return {"level": level, "code": f"{level}:uplift.{code}", "oid": oid, "message": message}


def suite_of(repo: Any, digest: str) -> dict[str, Any] | None:
    """The suite body of a counted ``opentine.uplift-suite/1`` record for *digest*."""
    from opentine import _uplift

    keys, _opt, _why = _uplift.scorers(repo)
    for row in _uplift.rows(repo, digest):
        claim = row["claim"]
        if (row["signed"] and row["signer"] in keys and claim
                and claim.get("convention") == _uplift.SUITE
                and not _uplift.check_claim(claim) and claim["digest"] == digest):  # fmt: skip
            return claim["suite"]
    return None


def build(repo: Any, digest: str) -> dict[str, Any]:
    """The export of suite *digest* from *repo* (refuses an unknown suite)."""
    from opentine import _uplift

    definition = suite_of(repo, digest)
    if definition is None:
        raise ValueError(f"uplift.unknown-suite: no counted suite {digest}")
    tasks = {t["id"] for t in definition["tasks"]}
    keys, optimizers, why = _uplift.scorers(repo)
    records: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    for row in _uplift.rows(repo, digest):
        claim, oid = row["claim"] or {}, row["oid"]
        if claim.get("convention") == _uplift.SUITE:
            continue
        if not row["signed"] or row["signer"] not in keys | optimizers:
            findings.append(_finding("advisory", "signer-unpinned", oid, why))
        elif row["signer"] in optimizers:
            findings.append(_finding("fail", "key-separation", oid,
                                     "signed by a pinned optimizer key"))  # fmt: skip
        elif _uplift.check_claim(claim):
            findings.append(_finding("fail", "malformed", oid, _uplift.check_claim(claim)[0]))
        elif claim["suite"] != digest or claim["task"] not in tasks:
            findings.append(_finding("advisory", "unknown-task", oid,
                                     f"{claim['task']} is not a task of the suite"))  # fmt: skip
        else:
            records.append({"oid": oid, **{k: claim[k] for k in _ROW}})
    records.sort(key=lambda r: r["oid"])
    findings.sort(key=lambda f: (f["oid"], f["code"]))
    return {"format": FORMAT, "suite": digest, "definition": definition, "records": records,
            "findings": findings}  # fmt: skip


def digest_of(export: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(FORMAT.encode() + b"\0" + canonical_json(export)).hexdigest()


def dump(export: dict[str, Any]) -> bytes:
    """Canonical JSON plus a newline: the bytes ``--export`` writes."""
    return canonical_json(export) + b"\n"


def load(path: str | Path) -> dict[str, Any]:
    """Read and check an export file (refuses a definition that does not match)."""
    from opentine import _uplift

    export = json.loads(Path(path).read_bytes())
    if not isinstance(export, dict) or export.get("format") != FORMAT:
        raise ValueError(f"{path}: not an {FORMAT} file")
    if set(export) != {"format", "suite", "definition", "records", "findings"}:
        raise ValueError(f"{path}: an export has format, suite, definition, records, findings")
    if _uplift.check_suite(export["definition"]) or (
        _uplift.suite_digest(export["definition"]) != export["suite"]
    ):
        raise ValueError(f"{path}: the definition does not match the suite digest")
    for row in export["records"]:
        claim = {"convention": _uplift.RECORD, "suite": export["suite"], "at": "",
                 **{k: row.get(k) for k in _ROW}}  # fmt: skip
        if not isinstance(row, dict) or set(row) != {"oid", *_ROW} or _uplift.check_claim(claim):
            raise ValueError(f"{path}: a record row is malformed")
    return export


__all__ = ["FORMAT", "build", "digest_of", "dump", "load", "suite_of"]
