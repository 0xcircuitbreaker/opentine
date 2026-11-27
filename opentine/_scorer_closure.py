"""The scorer closure pin (0.85): the ``opentine.scorer-closure/1`` claim convention.

An isolated ``python:`` scorer describes what it ran in one canonical document,
kept beside the verdicts as ``scorer.json``::

    {"convention": "opentine.scorer-closure/1",
     "target": "python:FILE.py:FUNC",
     "python": "3.12.3",
     "modules": [{"name": "...", "sha256": "<hex>"}],   # every non-stdlib module it imported
     "data": [{"file": "...", "sha256": "<hex>"}],      # other files it read
     "inputs": [{"file": "...", "sha256": "<hex>"}],    # read-only inputs passed explicitly
     "lockfile": "sha256:<hex>" | null,
     "contract": "sha256:<hex>" | null,
     "isolation": {"level": "full" | "partial", "network": "namespace" | "audit",
                   "limits": true | false, "env": "empty"},
     "limits": {"cpu_seconds": n, "memory_mb": n, "timeout_seconds": n, "output_bytes": n}}

The module list is what the child's ``sys.modules`` held after the call, and the
parent hashes each resolved file itself. ``closure`` (:func:`closure_digest`) is
``sha256:`` over the code-bearing fields only (target, python, modules, data,
inputs, lockfile, contract), so the same scorer on another machine has the same
closure. The pin, ``sc1+sha256:<64 hex>`` over the whole canonical document, is
the ``scorer_version`` of every verdict the scorer signs: ``tine eval verify``
recomputes it (``eval.summary-mismatch`` when ``scorer.json`` was edited or is
missing), so the closure is inside the signed verdict body. No verdict field,
object kind or ``tine verify`` code is added.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json

CONVENTION = "opentine.scorer-closure/1"
FILE_NAME = "scorer.json"
PREFIX = "sc1+sha256:"
CODE_FIELDS = ("target", "python", "modules", "data", "inputs", "lockfile", "contract")
FIELDS = ("convention", *CODE_FIELDS, "isolation", "limits")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


TREE_FILES = 2000


def tree(roots: list[str], skip: list[str]) -> list[Path]:
    """Every file under the scorer's own import *roots* (not *skip*: stdlib, site dirs).

    The parent lists these itself, so a scorer that hides a helper from the module
    list it reports still has that helper in its closure. Bytecode caches are left
    out: the child never runs a cached ``.pyc``. More than ``TREE_FILES`` files is
    refused, so a scorer belongs in a directory of its own.
    """
    import os

    found: set[Path] = set()
    for root in roots:
        real = Path(root).resolve()
        if any(real == Path(s).resolve() or Path(s).resolve() in real.parents for s in skip):
            continue
        for top, dirs, files in os.walk(real):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            found.update(Path(top, f).resolve() for f in files if not f.endswith(".pyc"))
            if len(found) > TREE_FILES:
                raise ValueError(f"{real} holds more than {TREE_FILES} files")
    return sorted(found)


def display(path: Path, root: Path) -> str:
    """*path* relative to *root* when inside it, else absolute; always POSIX."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def closure_digest(doc: dict[str, Any]) -> str:
    body = {name: doc.get(name) for name in CODE_FIELDS}
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def pin(doc: dict[str, Any]) -> str:
    return PREFIX + hashlib.sha256(canonical_json(doc)).hexdigest()


def check(doc: Any) -> list[str]:
    """Problems with *doc* as a scorer closure document (none: valid)."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION:
        return ["not an opentine.scorer-closure/1 document"]
    if set(doc) != set(FIELDS):
        return ["fields are " + ", ".join(FIELDS)]
    problems = []
    for name in ("modules", "data", "inputs"):
        rows = doc[name]
        key = "name" if name == "modules" else "file"
        if not isinstance(rows, list) or not all(
            isinstance(r, dict) and set(r) == {key, "sha256"} and isinstance(r[key], str)
            and isinstance(r["sha256"], str) and len(r["sha256"]) == 64 for r in rows
        ):  # fmt: skip
            problems.append(f"{name} is a list of {{{key}, sha256}}")
    if not isinstance(doc["target"], str) or not doc["target"].startswith("python:"):
        problems.append("target is a python: scorer spec")
    return problems


def check_folder(folder: Path, rows: list[Any]) -> list[dict[str, Any]]:
    """``scorer.json`` must be what every closure-pinned verdict's ``scorer_version`` pins."""
    pinned = [r for r in rows if isinstance(r, dict)
              and str(r.get("scorer_version", "")).startswith(PREFIX)]  # fmt: skip
    path = folder / FILE_NAME if folder.is_dir() else None
    if not pinned:
        return []
    if path is None or not path.is_file():
        return [{"line": 0, "item": None, "reason": "eval.summary-mismatch",
                 "detail": "scorer.json is missing for a closure-pinned verdict"}]  # fmt: skip
    from opentine._json_shallow import loads

    try:
        doc = loads(path.read_bytes())
    except ValueError:
        doc = None
    good = isinstance(doc, dict) and not check(doc)
    for number, row in enumerate(rows, 1):
        if not good or row.get("scorer_version") != pin(doc):
            return [{"line": number, "item": row.get("item"), "reason": "eval.summary-mismatch",
                     "detail": "scorer.json is not the closure the verdict signs"}]  # fmt: skip
    return []


def read(folder: Path) -> dict[str, Any]:
    """The checked ``scorer.json`` of an eval folder."""
    from opentine._json_shallow import loads

    path = Path(folder) / FILE_NAME
    if not path.is_file():
        raise ValueError(f"{folder} has no scorer.json: it was not scored by an isolated scorer")
    doc = loads(path.read_bytes())
    problems = check(doc)
    if problems:
        raise ValueError(f"{path}: {'; '.join(problems)}")
    return doc


def write(folder: Path, doc: dict[str, Any]) -> None:
    from opentine._canon import atomic_write_text

    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    atomic_write_text(Path(folder) / FILE_NAME, text, newline="\n")


__all__ = ["CONVENTION", "FILE_NAME", "PREFIX", "check", "check_folder", "closure_digest",
           "display", "file_sha256", "tree", "pin", "read", "write"]  # fmt: skip
