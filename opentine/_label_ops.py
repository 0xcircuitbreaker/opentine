"""The writing verbs of a rubric label queue (0.89): init, assign, reassign, submit, reveal.

Every verb appends one or more signed entries through
:func:`opentine._label_queue.append`, which checks an entry exactly as a reader
would before it is written, so a refused entry never reaches the log. Item and
judge-output files are untrusted JSON, read through :mod:`opentine._json_shallow`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from opentine import _label_queue as q
from opentine._label_queue import LabelError, digest, folder, read

MAX_FILE = 64 << 20
MAX_ITEMS = 100_000


def _bytes(path: Path) -> bytes:
    with open(path, "rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise LabelError("labels.too-large", f"{path} is over {MAX_FILE} bytes")
    return raw


def _json(raw: bytes, where: str) -> Any:
    from opentine import _json_shallow

    try:
        return _json_shallow.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LabelError("labels.bad-input", f"{where} is not JSON") from exc


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise LabelError("labels.chain", f"{path.name} exists with other content")
        return
    path.write_bytes(data)


def init(repo: Path, name: str, rubric_file: Path, key: Any, at: str) -> dict[str, Any]:
    rubric = q.check_rubric(_json(_bytes(rubric_file), str(rubric_file)))
    if (folder(repo, name) / "log.jsonl").exists():
        raise LabelError("labels.exists", f"queue {name!r} exists")
    import secrets

    from opentine._label_queue import _fresh

    claim = {"schema": q.RUBRIC, "name": name, "nonce": secrets.token_hex(32), "rubric": rubric,
             "rubric_sha256": digest(rubric)}  # fmt: skip
    state = q.append(repo, name, key, claim, at, _fresh())
    return {"queue": name, "queue_sha256": state["queue"], "rubric_sha256": state["rubric_sha256"],
            "rubric": rubric}  # fmt: skip


def items(raw: bytes) -> list[tuple[str, Any]]:
    """``[(item_sha256, item)]`` of a JSONL file (canonical-JSON digest of each line)."""
    out = []
    for n, line in enumerate(raw.split(b"\n"), 1):
        if line.strip():
            item = _json(line, f"items line {n}")
            out.append((digest(item), item))
    if not out or len(out) > MAX_ITEMS:
        raise LabelError("labels.bad-input", f"give 1..{MAX_ITEMS} items")
    return out


def assign(repo: Path, name: str, items_file: Path, reviewers: list[str], key: Any,
           at: str) -> dict[str, Any]:  # fmt: skip
    """Assign every item to every reviewer; an item already assigned to one is skipped."""
    from opentine._key_roles import KeyRoleError, normalize_key
    from opentine.kernel import canonical_json

    try:
        fprs = sorted({normalize_key(r) for r in reviewers})
    except KeyRoleError as exc:
        raise LabelError("labels.bad-input", str(exc)) from exc
    if not fprs:
        raise LabelError("labels.bad-input", "name at least one --reviewer")
    state, added, skipped = read(repo, name), 0, 0
    for sha, item in items(_bytes(items_file)):
        _write_new(folder(repo, name) / "items" / f"{sha}.json", canonical_json(item) + b"\n")
        for who in fprs:
            if who in state["assigned"].get(sha, {}) or (who, sha) in state["labels"]:
                skipped += 1
                continue
            q.append(repo, name, key, {"schema": q.ASSIGN, "item_sha256": sha, "reviewer": who,
                                     "from": None, "reason": None}, at, state)  # fmt: skip
            added += 1
    return {"queue": name, "assigned": added, "skipped": skipped, "items": len(state["items"])}


def reassign(repo: Path, name: str, item: str, was: str, to: str, reason: str, key: Any,
             at: str) -> dict[str, Any]:  # fmt: skip
    from opentine._key_roles import normalize_key

    claim = {"schema": q.ASSIGN, "item_sha256": item, "reviewer": normalize_key(to),
             "from": normalize_key(was), "reason": reason}  # fmt: skip
    state = q.append(repo, name, key, claim, at)
    return {"queue": name, "item_sha256": item, "from": claim["from"], "to": claim["reviewer"],
            "seq": state["seq"] - 1}  # fmt: skip


def submit(repo: Path, name: str, item: str, label: str, key: Any, at: str,
           state: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign one label; *state* (a verified queue, advanced in place) saves a re-read."""
    from opentine._promote import _who

    state = state if state is not None else read(repo, name)
    claim = {"schema": q.LABEL, "item_sha256": item, "label": label, "reviewer": _who(key),
             "rubric_sha256": state["rubric_sha256"]}  # fmt: skip
    q.append(repo, name, key, claim, at, state)
    return {"queue": name, "item_sha256": item, "label": label, "reviewer": claim["reviewer"],
            "rubric_sha256": state["rubric_sha256"], "seq": state["seq"] - 1}  # fmt: skip


def reveal(repo: Path, name: str, provenance: Path, outputs: Path, key: Any,
           at: str) -> dict[str, Any]:  # fmt: skip
    """File signed judge outcomes (``opentine.judge-outcome/1``) and sign their reveal."""
    from opentine import _judge_provenance as jp
    from opentine._judge_outcomes import OutcomeError, check

    doc = _json(_bytes(provenance), str(provenance))
    if jp.check(doc):
        raise LabelError("labels.bad-input", f"{provenance} is not judge provenance")
    raw = _bytes(outputs)
    try:
        check(raw, jp.pin(doc), Path(repo) / ".tine")
    except OutcomeError as exc:
        raise LabelError("labels.bad-input", str(exc)) from exc
    sha = hashlib.sha256(raw).hexdigest()
    state = read(repo, name)
    _write_new(folder(repo, name) / "judge" / f"{sha}.jsonl", raw)
    claim = {"schema": q.REVEAL, "judge": jp.pin(doc), "outputs_sha256": sha}
    q.append(repo, name, key, claim, at, state)
    return {"queue": name, "judge": claim["judge"], "outputs_sha256": sha,
            "seq": state["seq"] - 1}  # fmt: skip


def pending(repo: Path, name: str, reviewer: str) -> dict[str, Any]:
    """The items assigned to *reviewer* and not yet labelled -- never any judge output."""
    from opentine._key_roles import normalize_key

    who, state = normalize_key(reviewer), read(repo, name)
    rows = []
    for sha in sorted(state["items"]):
        if who in state["assigned"].get(sha, {}) and (who, sha) not in state["labels"]:
            path = folder(repo, name) / "items" / f"{sha}.json"
            item = _json(_bytes(path), path.name) if path.is_file() else None
            ok = item is not None and digest(item) == sha
            rows.append({"item_sha256": sha, "item": item if ok else None})
    return {"queue": name, "reviewer": who, "rubric": state["rubric"],
            "rubric_sha256": state["rubric_sha256"], "pending": rows}  # fmt: skip


__all__ = ["assign", "init", "items", "pending", "reassign", "reveal", "submit"]
