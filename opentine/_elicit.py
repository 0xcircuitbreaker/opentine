"""Elicitation links (0.68): the ``opentine.elicit-link/1`` claim convention.

One signed JSON document says how one task was attempted under one
elicitation condition, how much effort that took, and what each item scored::

    {"convention": "opentine.elicit-link/1", "task": NAME, "safety_relevant": BOOL,
     "condition": {"name": NAME, "kind": "prompt"|"scaffold"|"fine-tune"|"best-of-n"|
                   "eval-cue"|"deployment-cue", "ref": TEXT|null,
                   "cue": "eval"|"deployment"|"none", "monitored": BOOL},
     "model": {"id": TEXT, "version": TEXT},
     "effort": {"attempts": INT>=1, "best_of_n": INT|null, "tokens": INT|null,
                "usd": NUM|null, "gpu_hours": NUM|null},
     "items": [{"id": NAME, "score": "0".."1"}],
     "created_at": TIME, "signer": "sha256:..", "signature": {tine-sig/3 block}}

Records sharing a task are *linked*: ``tine elicit report``
(:mod:`opentine._elicit_report`) pairs their items by ``(task, item id)``
across conditions. The ``effort`` field is the effort record. Records are filed
under ``REPO/.tine/elicit/links/<hex>.json``, named by :func:`digest`. No object
kind and no ``tine verify`` code is added (docs/ELICITATION.md).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _experiment as _exp

CONVENTION = "opentine.elicit-link/1"
DOMAIN = b"opentine.elicit-link.v1:"
FIELDS = ("convention", "task", "safety_relevant", "condition", "model", "effort", "items",
          "created_at", "signer")  # fmt: skip
KINDS = ("prompt", "scaffold", "fine-tune", "best-of-n", "eval-cue", "deployment-cue")
CUES = ("eval", "deployment", "none")
CONDITION = ("name", "kind", "ref", "cue", "monitored")
EFFORT = ("attempts", "best_of_n", "tokens", "usd", "gpu_hours")
FOLDER = Path(".tine") / "elicit" / "links"
MAX_ITEMS = 100_000
MAX_FILES = 100_000
NAME_RE = _exp.NAME_RE
SCORE_RE = _exp.SCORE_RE
TIME_RE = _exp.TIME_RE


def _int(value: Any, low: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= low


def _condition(cond: Any) -> str | None:
    if not isinstance(cond, dict) or set(cond) != set(CONDITION):
        return "condition is {name, kind, ref, cue, monitored}"
    if not isinstance(cond["name"], str) or not NAME_RE.fullmatch(cond["name"]):
        return "condition name is 1..128 safe characters"
    if cond["kind"] not in KINDS:
        return f"condition kind is one of {', '.join(KINDS)}"
    if cond["ref"] is not None and not (isinstance(cond["ref"], str) and cond["ref"]):
        return "condition ref is non-empty text or null"
    if cond["cue"] not in CUES:
        return f"condition cue is one of {', '.join(CUES)}"
    if not isinstance(cond["monitored"], bool):
        return "condition monitored is a boolean"
    implied = {"eval-cue": "eval", "deployment-cue": "deployment"}.get(cond["kind"])
    if implied and cond["cue"] != implied:  # a cue condition cannot hide or swap its cue
        return f"a {cond['kind']} condition carries cue {implied}"
    return None


def _effort(effort: Any) -> str | None:
    if not isinstance(effort, dict) or set(effort) != set(EFFORT):
        return "effort is {attempts, best_of_n, tokens, usd, gpu_hours}"
    if not _int(effort["attempts"], 1):
        return "effort attempts is an integer >= 1"
    for name in ("best_of_n", "tokens"):
        if effort[name] is not None and not _int(effort[name], 1 if name == "best_of_n" else 0):
            return f"effort {name} is a positive integer or null"
    for name in ("usd", "gpu_hours"):
        value = effort[name]
        if value is not None and (not _exp._num(value) or value < 0):
            return f"effort {name} is a non-negative number or null"
    return None


def _items(items: Any) -> str | None:
    if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
        return f"items is a list of 1..{MAX_ITEMS} rows"
    seen: set[str] = set()
    for row in items:
        if not isinstance(row, dict) or set(row) != {"id", "score"}:
            return "an item is {id, score}"
        if not isinstance(row["id"], str) or not NAME_RE.fullmatch(row["id"]):
            return "an item id is 1..128 safe characters"
        if row["id"] in seen:
            return f"item {row['id']} is listed twice"
        seen.add(row["id"])
        if not isinstance(row["score"], str) or not SCORE_RE.fullmatch(row["score"]):
            return f"item {row['id']}: score is a canonical decimal string in 0..1"
    return None


def problems(doc: Any) -> list[str]:
    """What is wrong with *doc*'s fields (signature not checked); none: well formed."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION:
        return [f"not an {CONVENTION} document"]
    missing = [f for f in FIELDS if f not in doc and f != "signer"]
    if missing:
        return [f"missing {', '.join(missing)}"]
    extra = set(doc) - {*FIELDS, "signature"}
    if extra:
        return [f"unknown fields {sorted(extra)}"]
    if not isinstance(doc["task"], str) or not NAME_RE.fullmatch(doc["task"]):
        return ["task is 1..128 safe characters"]
    if not isinstance(doc["safety_relevant"], bool):
        return ["safety_relevant is a boolean"]
    model = doc["model"]
    if not isinstance(model, dict) or set(model) != {"id", "version"} \
            or not all(isinstance(v, str) and v for v in model.values()):  # fmt: skip
        return ["model is {id, version} (non-empty text)"]
    if not isinstance(doc["created_at"], str) or not TIME_RE.fullmatch(doc["created_at"]):
        return ["created_at is YYYY-MM-DDTHH:MM:SSZ"]
    why = _condition(doc["condition"]) or _effort(doc["effort"]) or _items(doc["items"])
    return [why] if why else []


def body(doc: dict[str, Any]) -> dict[str, Any]:
    return {name: doc.get(name) for name in FIELDS}


def sign(doc: dict[str, Any], private_key: Any, *, at: str | None = None) -> dict[str, Any]:
    """*doc* signed (``signer``, ``created_at`` and ``signature`` set); raises if malformed."""
    from opentine import _signed_doc
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    private = load_ed25519_private(private_key)
    out = {k: v for k, v in doc.items() if k != "signature"}
    out["created_at"] = at or out.get("created_at") or _exp.now()
    out["signer"] = key_fingerprint(private.public_key().public_bytes_raw())
    found = problems(out)
    if found:
        raise ValueError(f"not a valid elicitation link: {found[0]}")
    out["signature"] = _signed_doc.sign(DOMAIN, body(out), private, signer=out["signer"],
                                        signed_at=out["created_at"])  # fmt: skip
    return out


def verify(doc: dict[str, Any]) -> str | None:
    """None when *doc*'s embedded signature is by its ``signer``; else the reason."""
    return _exp.verify(doc, DOMAIN, FIELDS)


def digest(doc: dict[str, Any]) -> str:
    return _exp.digest(doc, DOMAIN)


def file(doc: dict[str, Any], folder: Path) -> Path:
    """Write a signed record into *folder* under its digest; idempotent."""
    path = Path(folder) / f"{digest(doc)[7:]}.json"
    raw = _exp.dump(doc)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not (path.is_file() and path.read_bytes() == raw):
        path.write_bytes(raw)
    return path


def read_folder(folder: Path, *, max_files: int = MAX_FILES) -> list[tuple[str, bytes]]:
    """``(name, bytes)`` for each ``*.json`` in *folder*, sorted; refuses over *max_files*."""
    root = Path(folder)
    paths = sorted(root.glob("*.json")) if root.is_dir() else []
    if len(paths) > max_files:
        raise ValueError(f"elicit.too-large: {root} holds over {max_files} records")
    return [(p.name, p.read_bytes()) for p in paths if p.is_file()]


__all__ = ["CONVENTION", "CUES", "DOMAIN", "FIELDS", "FOLDER", "KINDS", "body", "digest",
           "file", "problems", "read_folder", "sign", "verify"]  # fmt: skip
