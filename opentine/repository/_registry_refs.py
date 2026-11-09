"""Prompt versions and memory notes in a repository (0.47, SPEC 4.19-4.20).

Both kinds are stored as blobs of their canonical bytes (never redacted: they
are signed, and redaction would break the signature; ``tine memory add``
refuses text a secret detector fires on before it signs). Their refs::

    prompts/<name>/head            the newest version of a prompt
    prompts/<name>/labels/<label>  a version a label names (moves; the version does not)
    memory/<scope>/<hex>           one memory note, named by its blob digest

are ordinary typed refs (``blob``), so ``tine push``/``pull`` and bundles carry
them. Every write checks the record first (a new prompt version against the
current head) and moves its ref by compare-and-swap.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _memory, _prompt
from opentine.kernel import canonical_json

MAX_HISTORY = 10_000
MAX_NOTES = 50_000


def _load(repo: Any, oid: str) -> dict[str, Any]:
    return json.loads(repo.get(oid).payload())


def _put(repo: Any, record: dict[str, Any], expected: str) -> str:
    oid = repo.put("blob", canonical_json(record), redact=False)
    if oid != expected:
        raise ValueError("the stored record blob does not match its digest")
    return oid


# --- prompts ---------------------------------------------------------------- #


def head_ref(name: str) -> str:
    return f"prompts/{name}/head"


def label_ref(name: str, label: str) -> str:
    if not _prompt.LABEL.fullmatch(label) or label == "head":
        raise ValueError(f"invalid prompt label {label!r}")
    return f"prompts/{name}/labels/{label}"


def prompt_head(repo: Any, name: str) -> dict[str, Any] | None:
    oid = repo.read_ref(head_ref(name))
    return None if oid is None else _load(repo, oid)


def prompt_history(repo: Any, name: str) -> list[dict[str, Any]]:
    """Every version of *name*, oldest first, by following ``prev`` from the head."""
    out: list[dict[str, Any]] = []
    oid = repo.read_ref(head_ref(name))
    while oid is not None and len(out) < MAX_HISTORY:
        record = _load(repo, oid)
        out.append(record)
        oid = record.get("prev")
    return list(reversed(out))


def push_prompt(repo: Any, record: dict[str, Any]) -> str:
    """Store *record* as the next version of its prompt; return its blob oid."""
    name = record.get("name") if isinstance(record, dict) else None
    if not isinstance(name, str) or not _prompt.PROMPT_NAME.fullmatch(name):
        _prompt.body(record)  # raises the field error
    current_oid = repo.read_ref(head_ref(name))
    current = None if current_oid is None else _load(repo, current_oid)
    if current is None and record.get("version") != 1:
        raise ValueError("the first version of a prompt is version 1")
    _prompt.check(record, previous=current)
    oid = _put(repo, record, _prompt.digest(record))
    repo.update_ref(head_ref(name), oid, expected_old=current_oid)
    return oid


def resolve(repo: Any, spec: str) -> dict[str, Any]:
    """``NAME``, ``NAME@LABEL`` or ``NAME@vN`` -> the version record."""
    name, _, which = spec.partition("@")
    if not _prompt.PROMPT_NAME.fullmatch(name):
        raise ValueError(f"invalid prompt name {name!r}")
    if not which or which == "head":
        record = prompt_head(repo, name)
    elif which[:1] == "v" and which[1:].isdigit():
        wanted = int(which[1:])
        record = next((r for r in prompt_history(repo, name) if r["version"] == wanted), None)
    else:
        oid = repo.read_ref(label_ref(name, which))
        record = None if oid is None else _load(repo, oid)
    if record is None:
        raise LookupError(f"no prompt {spec}")
    return record


def set_label(repo: Any, name: str, label: str, version: int | None = None) -> dict[str, Any]:
    """Point *label* at a version of *name* (the head by default)."""
    history = prompt_history(repo, name)
    if not history:
        raise LookupError(f"no prompt {name}")
    record = history[-1] if version is None else next(
        (r for r in history if r["version"] == version), None
    )  # fmt: skip
    if record is None:
        raise LookupError(f"no version {version} of prompt {name}")
    ref = label_ref(name, label)
    repo.update_ref(ref, _prompt.digest(record), expected_old=repo.read_ref(ref))
    return record


def labels(repo: Any, name: str) -> dict[str, int]:
    prefix = f"prompts/{name}/labels/"
    out = {}
    for ref, oid in repo.list_refs().items():
        if ref.startswith(prefix):
            out[ref[len(prefix) :]] = _load(repo, oid)["version"]
    return dict(sorted(out.items()))


def prompt_names(repo: Any) -> list[str]:
    return sorted(
        ref.split("/")[1]
        for ref in repo.list_refs()
        if ref.startswith("prompts/") and ref.endswith("/head")
    )


# --- memory ----------------------------------------------------------------- #


def note_ref(record: dict[str, Any]) -> str:
    digest = _memory.digest(record)
    return f"memory/{record['scope']}/{digest.removeprefix('blob:sha256:')}"


def add_note(repo: Any, record: dict[str, Any]) -> str:
    """Store a signed note; return its blob oid (idempotent)."""
    _memory.check(record)
    oid = _put(repo, record, _memory.digest(record))
    ref = note_ref(record)
    if repo.read_ref(ref) is None:
        repo.update_ref(ref, oid, expected_old=None)
    return oid


def notes(repo: Any, *, team: Any = (), scope: str | None = None) -> list[dict[str, Any]]:
    """Every note that verifies (under *team* when given) and is not superseded.

    Each row is ``{"record", "check"}``; a note that does not verify is left
    out, never shown: memory reaches an agent's context.
    """
    rows = []
    for ref, oid in sorted(repo.list_refs().items()):
        if not ref.startswith("memory/") or len(rows) >= MAX_NOTES:
            continue
        if scope is not None and ref.split("/")[1] != scope:
            continue
        try:
            record = _load(repo, oid)
            rows.append({"record": record, "check": _memory.check(record, team=team)})
        except (ValueError, KeyError, TypeError):
            continue
    replaced = {row["check"]["supersedes"] for row in rows if row["check"]["supersedes"]}
    return [row for row in rows if row["check"]["digest"] not in replaced]


__all__ = [
    "add_note",
    "label_ref",
    "labels",
    "notes",
    "prompt_head",
    "prompt_history",
    "prompt_names",
    "push_prompt",
    "resolve",
    "set_label",
]
