"""Rubric label queues (0.89): a signed, hash-chained log of assignments and labels.

A queue is ``REPO/.tine/labels/NAME/``: ``log.jsonl`` holds one signed document
per line, each an existing ``attestation`` shape whose claim follows one of the
``opentine.label-*/1`` conventions (docs/LABELS.md), and every later claim names
the ``queue`` (the SHA-256 of the first entry, which carries the queue name and a
random nonce), its ``seq`` (the line index) and ``prev`` (the
SHA-256 of the previous line's canonical JSON), so a line moved, replayed from
another queue or edited breaks the chain. ``items/<hex>.json`` keeps each
item; ``judge/<hex>.jsonl`` keeps revealed judge outputs.

* ``opentine.label-rubric/1`` (seq 0): the queue name, a nonce, the rubric and
  its digest (``rubric_sha256``).
* ``opentine.label-assign/1``: an item assigned to a reviewer, or reassigned
  (``from`` names the reviewer it is taken from, ``reason`` why).
* ``opentine.label/1``: one reviewer's label, bound to the reviewer key (the
  signer), the rubric digest and the item digest.
* ``opentine.label-reveal/1``: judge outputs revealed (their digest and the
  judge's ``jp1+sha256:`` pin). Only labels recorded before it count toward that
  judge's agreement, so no counted label was given with judge output in view.

The rubric, assignment and reveal entries are signed by a pinned ``policy`` key,
labels by a pinned ``reviewer`` key; both come only from the owner-pinned trust
bundle, and a key the bundle also names ``optimizer`` holds neither. Reading a
queue checks every line; any failure makes the whole queue invalid (fail closed).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

RUBRIC, ASSIGN = "opentine.label-rubric/1", "opentine.label-assign/1"
LABEL, REVEAL = "opentine.label/1", "opentine.label-reveal/1"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
HEX_RE = re.compile(r"[0-9a-f]{64}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_LOG = 64 << 20
MAX_LABELS = 64


class LabelError(ValueError):
    """A queue entry or request that is refused; ``code`` names why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def folder(repo: Path, name: str) -> Path:
    if not NAME_RE.fullmatch(name or ""):
        raise LabelError("labels.bad-name", f"a queue name matches {NAME_RE.pattern}")
    return Path(repo) / ".tine" / "labels" / name


def digest(document: Any) -> str:
    from opentine.kernel import canonical_json

    return hashlib.sha256(canonical_json(document)).hexdigest()


def check_rubric(rubric: Any) -> dict[str, Any]:
    """``{"name", "labels", "instructions"}``: 2..64 distinct labels, a name, text."""
    if not isinstance(rubric, dict) or set(rubric) - {"name", "labels", "instructions"}:
        raise LabelError("labels.bad-rubric", "a rubric is {name, labels, instructions}")
    labels = rubric.get("labels")
    if (not isinstance(labels, list) or not 2 <= len(labels) <= MAX_LABELS
            or len(set(map(str, labels))) != len(labels)
            or not all(isinstance(x, str) and LABEL_RE.fullmatch(x) for x in labels)):  # fmt: skip
        raise LabelError("labels.bad-rubric", f"labels are 2..{MAX_LABELS} distinct names")
    if not isinstance(rubric.get("name"), str) or not rubric["name"]:
        raise LabelError("labels.bad-rubric", "a rubric has a name")
    if not isinstance(rubric.get("instructions", ""), str):
        raise LabelError("labels.bad-rubric", "instructions are text")
    return {"name": rubric["name"], "labels": list(labels),
            "instructions": rubric.get("instructions", "")}  # fmt: skip


def signers(repo: Path) -> dict[str, tuple[set[str], str]]:
    """``{"policy": (keys, why), "reviewer": (keys, why)}`` from the pinned bundle."""
    from opentine._key_roles_pin import granting

    store = Path(repo) / ".tine"
    return {role: granting(store, role) for role in ("policy", "reviewer")}


def _line(raw: bytes, seq: int) -> dict[str, Any]:
    from opentine import _json_shallow

    try:
        doc = _json_shallow.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise LabelError("labels.bad-entry", f"line {seq} is not JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("claim"), dict):
        raise LabelError("labels.bad-entry", f"line {seq} is not a signed entry")
    return doc


def _fresh() -> dict[str, Any]:
    return {"rubric": None, "rubric_sha256": None, "queue": None, "head": None, "seq": 0,
            "items": set(),
            "assigned": {}, "labels": {}, "reveals": [], "log": []}  # fmt: skip


def apply(state: dict[str, Any], doc: dict[str, Any], keys: dict, name: str) -> None:
    """Check one entry against the queue so far and fold it in; refused entries raise."""
    from opentine._integrity_run import _signer

    claim, seq = doc["claim"], state["seq"]
    kind = claim.get("schema")
    who = _signer(doc)
    if who is None:
        raise LabelError("labels.bad-signature", f"entry {seq} does not verify")
    if claim.get("seq") != seq or claim.get("prev") != state["head"]:
        raise LabelError("labels.chain", f"entry {seq} is out of place (replayed or moved)")
    if seq and claim.get("queue") != state["queue"]:
        raise LabelError("labels.chain", f"entry {seq} names another queue")
    role = "reviewer" if kind == LABEL else "policy"
    allowed, why = keys[role]
    if who not in allowed:
        raise LabelError("labels.signer", f"entry {seq} ({kind}): {why}")
    if (seq == 0) != (kind == RUBRIC):
        raise LabelError("labels.bad-entry", "the rubric is the first entry and only that")
    if kind == RUBRIC:
        rubric = check_rubric(claim.get("rubric"))
        if claim.get("rubric_sha256") != digest(rubric):
            raise LabelError("labels.bad-rubric", "the rubric digest does not match")
        if claim.get("name") != name or not HEX_RE.fullmatch(str(claim.get("nonce"))):
            raise LabelError("labels.chain", f"the first entry is not queue {name!r}'s")
        state["rubric"], state["rubric_sha256"] = rubric, claim["rubric_sha256"]
        state["queue"] = digest(doc)
    elif kind == ASSIGN:
        _assign(state, claim, seq, who)
    elif kind == LABEL:
        _label(state, claim, who, seq)
    elif kind == REVEAL:
        if not (HEX_RE.fullmatch(str(claim.get("outputs_sha256")))
                and str(claim.get("judge", "")).startswith("jp1+sha256:")):  # fmt: skip
            raise LabelError("labels.bad-entry", f"entry {seq}: a reveal names outputs and judge")
        state["reveals"].append({"seq": seq, "judge": claim["judge"],
                                 "outputs_sha256": claim["outputs_sha256"]})  # fmt: skip
    else:
        raise LabelError("labels.bad-entry", f"entry {seq}: unknown convention {kind!r}")
    state["head"], state["seq"] = digest(doc), seq + 1
    state["log"].append({"seq": seq, "schema": kind, "signer": who})


def _assign(state: dict[str, Any], claim: dict[str, Any], seq: int, who: str) -> None:
    item, reviewer, was = claim.get("item_sha256"), claim.get("reviewer"), claim.get("from")
    if not (HEX_RE.fullmatch(str(item)) and str(reviewer).startswith("sha256:")):
        raise LabelError("labels.bad-entry", f"entry {seq}: an assignment names item, reviewer")
    if reviewer == who:
        raise LabelError("labels.self-assign", f"entry {seq}: a key cannot assign itself")
    held = state["assigned"].setdefault(item, {})
    if reviewer in held or (reviewer, item) in state["labels"]:
        raise LabelError("labels.duplicate", f"entry {seq}: {reviewer} already has {item[:12]}")
    if was is not None:
        if held.get(was) is None or not isinstance(claim.get("reason"), str):
            raise LabelError("labels.bad-entry", f"entry {seq}: reassigns from an unassigned "
                             "reviewer, or gives no reason")  # fmt: skip
        if (was, item) in state["labels"]:
            raise LabelError("labels.labelled", f"entry {seq}: {was} already labelled it")
        del held[was]
    held[reviewer] = seq
    state["items"].add(item)


def _label(state: dict[str, Any], claim: dict[str, Any], who: str, seq: int) -> None:
    item, value = claim.get("item_sha256"), claim.get("label")
    if claim.get("reviewer") != who:
        raise LabelError("labels.signer", f"entry {seq}: the label names another reviewer")
    if claim.get("rubric_sha256") != state["rubric_sha256"]:
        raise LabelError("labels.chain", f"entry {seq}: the label is for another rubric")
    if (who, item) in state["labels"]:
        raise LabelError("labels.duplicate", f"entry {seq}: a second label from {who}")
    if who not in state["assigned"].get(item, {}):
        raise LabelError("labels.unassigned", f"entry {seq}: {who} is not assigned the item")
    if value not in state["rubric"]["labels"]:
        raise LabelError("labels.bad-label", f"entry {seq}: {value!r} is not a rubric label")
    state["labels"][who, item] = {"label": value, "seq": seq}


def read(repo: Path, name: str) -> dict[str, Any]:
    """The verified queue state; any bad line raises (the queue is invalid)."""
    path = folder(repo, name) / "log.jsonl"
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_LOG + 1)
    except FileNotFoundError as exc:
        raise LabelError("labels.missing", f"no queue {name!r}") from exc
    if len(raw) > MAX_LOG:
        raise LabelError("labels.bad-entry", f"the log is over {MAX_LOG} bytes")
    state, keys = _fresh(), signers(repo)
    for seq, line in enumerate(raw.split(b"\n")[:-1] if raw.endswith(b"\n") else [raw]):
        apply(state, _line(line, seq), keys, name)
    if state["rubric"] is None:
        raise LabelError("labels.missing", f"queue {name!r} has no rubric")
    return state


def append(repo: Path, name: str, key: Any, claim: dict[str, Any], at: str,
           state: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign *claim* as the next entry, check it like a reader would, and append it."""
    from opentine._integrity_run import _sign

    state = state if state is not None else read(repo, name)
    body = {**claim, "seq": state["seq"], "prev": state["head"]}
    if state["seq"]:
        body["queue"] = state["queue"]
    doc = _sign(key, body, f"sha256:{body.get('queue') or body['rubric_sha256']}", at)
    apply(state, doc, signers(repo), name)
    path = folder(repo, name) / "log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    with open(path, "ab") as handle:
        handle.write(line.encode("utf-8"))
    return state


__all__ = ["ASSIGN", "LABEL", "REVEAL", "RUBRIC", "LabelError", "append", "apply",
           "check_rubric", "digest", "folder", "read", "signers"]  # fmt: skip
