"""Reviews with the standard library (0.47, SPEC 4.20).

An independent port, for ``tine-verify.pyz``, of ``opentine._review.check``,
``check_gate`` and ``verify_bundle``: a reviewer-signed, hash-chained
``opentine.review``, its ``opentine.review-gate`` decisions and the
``opentine.review-bundle`` that carries both. Signatures are ``tine-sig/3``
Ed25519 blocks over each kind's domain + JCS of ``{"body", "header"}``.
"""

from __future__ import annotations

import re
from typing import Any

from .. import kernel
from . import _sig
from ._gitobj import Refused
from ._project import digest

FIELDS = ("kind", "review_version", "review_id", "seq", "prev", "title", "reviewers", "repos",
          "subjects", "findings", "monitors", "gates", "updated_at")  # fmt: skip
GATE = ("kind", "gate_version", "review_id", "review", "seq", "gate", "decision", "reason",
        "decided_at")  # fmt: skip
ROWS = {"repos": ({"name", "project"}, 16), "subjects": ({"repo", "type", "id"}, 1024),
        "findings": ({"id", "severity", "subject", "message", "status"}, 1024),
        "monitors": ({"name", "scorer", "score", "threshold", "passed", "verdict"}, 64),
        }  # fmt: skip
_P = {"id": r"[a-z0-9][a-z0-9._-]{0,63}", "key": r"[0-9a-f]{64}",
      "blob": r"blob:sha256:[0-9a-f]{64}", "run": r"run:sha256:[0-9a-f]{64}",
      "commit": r"[0-9a-f]{40}|[0-9a-f]{64}", "scorer": r"[a-z0-9][a-z0-9-]{0,63}",
      "score": r"0|1|0\.[0-9]{0,5}[1-9]", "digest": r"sha256:[0-9a-f]{64}",
      "when": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"}  # fmt: skip


def _is(value: Any, name: str) -> bool:
    return isinstance(value, str) and re.fullmatch(_P[name], value) is not None


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _text(value: Any, limit: int, empty: bool = False) -> bool:
    if not isinstance(value, str) or (not empty and not value.strip()):
        return False
    return len(value.encode("utf-8", "surrogatepass")) <= limit and not re.search(
        r"[\x00-\x1f\x7f]", value
    )


def _micros(score: str) -> int:
    return int(score) * 1_000_000 if score in ("0", "1") else int(score[2:].ljust(6, "0"))


def bad(message: str) -> Refused:
    return Refused("review.malformed", f"review is malformed: {message}")


def _fields(record: Any, kind: str, names: tuple, code: str, subject: str) -> dict:
    if not isinstance(record, dict) or record.get("kind") != kind:
        raise Refused(f"{code}.malformed", f"{subject} is malformed: kind is not {kind}")
    if set(record) - {*names, "signature"} or set(names) - set(record):
        raise Refused(f"{code}.malformed", f"{subject} is malformed: wrong set of fields")
    return {name: record[name] for name in names}


def _rows(value: Any, what: str) -> list:
    names, limit = ROWS[what]
    if not isinstance(value, list) or len(value) > limit:
        raise bad(f"{what} is a list of at most {limit}")
    if not all(isinstance(row, dict) and set(row) == names for row in value):
        raise bad(f"each of {what} has exactly its fields")
    return value


def _distinct(values: list, what: str) -> None:
    if len(set(values)) != len(values):
        raise bad(f"{what} must be distinct")


def _body(record: Any) -> dict:
    body = _fields(record, "opentine.review", FIELDS, "review", "review")
    seq = body["seq"]
    for ok, message in (
        (body["review_version"] == 1 and _count(body["review_version"]), "review_version"),
        (_is(body["review_id"], "id"), "review_id"),
        (_count(seq), "seq is a count"),
        ((body["prev"] is None) if seq == 0 else _is(body["prev"], "blob"), "prev and seq"),
        (_text(body["title"], 256), "title"),
        (_is(body["updated_at"], "when"), "updated_at"),
    ):
        if not ok:
            raise bad(message)
    keys = body["reviewers"]
    if (
        not isinstance(keys, list)
        or not 1 <= len(keys) <= 16
        or not all(_is(k, "key") for k in keys)
    ):
        raise bad("reviewers is 1 to 16 Ed25519 public keys")
    _distinct(keys, "reviewers")
    names = [row["name"] for row in _rows(body["repos"], "repos")]
    if not names or not all(_is(n, "id") for n in names) or names != sorted(set(names)):
        raise bad("repos is 1 to 16 repos, sorted by distinct name")
    if not all(r["project"] is None or _is(r["project"], "id") for r in body["repos"]):
        raise bad("a repo's project is a project id or null")
    subjects = _rows(body["subjects"], "subjects")
    for row in subjects:
        kind = row["type"] if row["type"] in ("run", "commit") else None
        if row["repo"] not in names or kind is None or not _is(row["id"], kind):
            raise bad("a subject is a run oid or commit id in a listed repo")
    _distinct([(r["repo"], r["type"], r["id"]) for r in subjects], "subjects")
    for row in _rows(body["findings"], "findings"):
        at = row["subject"]
        if (
            not _is(row["id"], "id")
            or row["severity"] not in ("info", "low", "medium", "high", "critical")
            or row["status"] not in ("open", "resolved")
            or not _text(row["message"], 1024)
            or not (at is None or (_count(at) and at < len(subjects)))
        ):
            raise bad("a finding has an id, severity, status, message, subject")
    _distinct([row["id"] for row in body["findings"]], "finding ids")
    monitors = _rows(body["monitors"], "monitors")
    for row in monitors:
        if (
            row["name"] not in ("risk", "intent-drift", "coverage")
            or not _is(row["scorer"], "scorer")
            or not (_is(row["score"], "score") and _is(row["threshold"], "score"))
            or not isinstance(row["passed"], bool)
            or not (row["verdict"] is None or _is(row["verdict"], "digest"))
        ):
            raise bad("a monitor is risk, intent-drift or coverage with a score")
    _distinct([row["name"] for row in monitors], "monitor names")
    for row in monitors:
        if row["passed"] != (_micros(row["score"]) >= _micros(row["threshold"])):
            raise Refused("review.inconsistent", f"monitor {row['name']}: passed disagrees")
    gates = body["gates"]
    if not isinstance(gates, list) or len(gates) > 32 or not all(_is(g, "id") for g in gates):
        raise bad("gates is at most 32 gate names")
    if gates != sorted(set(gates)):
        raise bad("gates are sorted and distinct")
    return body


def gate_body(record: Any) -> dict:
    body = _fields(record, "opentine.review-gate", GATE, "review-gate", "review gate decision")
    for ok, message in (
        (body["gate_version"] == 1 and _count(body["gate_version"]), "gate_version"),
        (_is(body["review_id"], "id") and _is(body["gate"], "id"), "review_id and gate"),
        (_is(body["review"], "blob") and _count(body["seq"]), "review and seq"),
        (body["decision"] in ("approve", "reject"), "decision is approve or reject"),
        (_text(body["reason"], 1024, True) and _is(body["decided_at"], "when"), "reason, time"),
    ):
        if not ok:
            raise Refused("review-gate.malformed", f"review gate decision is malformed: {message}")
    return body


def _signer(record: dict, body: dict, gate: bool) -> str:
    code, domain = ("review-gate", b"opentine.review-gate.v1:") if gate else ("review", b"")
    domain = domain or b"opentine.review.v1:"
    block = record.get("signature")
    if block is None:
        raise Refused(f"{code}.unsigned", f"the {code} is unsigned")
    if not isinstance(block, dict):
        raise Refused(f"{code}.bad-signature", f"the {code} signature is not a block")
    if block.get("alg") != "ed25519":
        raise Refused(f"{code}.wrong-signer", f"a {code} is signed with an Ed25519 key")
    raw = block.get("public_key")
    public = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b"\0" * 32

    def message(header: dict[str, Any]) -> bytes:
        return domain + kernel.canonical_json({"body": body, "header": header})

    ok, found, reason = _sig.verify_block(block, message, ("tine-sig/3",), hmac_key=None,
                                          public_key=public)  # fmt: skip
    if not ok:
        raise Refused(f"{code}.bad-signature", f"the {code} signature does not hold ({reason})")
    return raw


def review_verify(record: Any, previous: Any = None, reviewer_key: str | None = None) -> dict:
    body = _body(record)
    signer = _signer(record, body, False)
    state, reviewers = "verified-tofu", body["reviewers"]
    if previous is not None:
        prior = _body(previous)
        if (
            body["prev"] != digest(previous)
            or body["seq"] != prior["seq"] + 1
            or body["review_id"] != prior["review_id"]
        ):
            raise Refused("review.chain-break", f"version {body['seq']} breaks the review chain")
        state, reviewers = "verified", prior["reviewers"]
    elif reviewer_key is not None:
        if signer != reviewer_key:
            raise Refused("review.wrong-signer", "not signed by the pinned reviewer key")
        state = "verified"
    if signer not in reviewers:
        raise Refused("review.wrong-signer", "the review is not signed by a reviewer")
    return {"review_id": body["review_id"], "seq": body["seq"], "digest": digest(record),
            "signer": signer, "state": state}  # fmt: skip


def gate_verify(record: Any, version: Any) -> dict:
    body, review = gate_body(record), _body(version)
    signer = _signer(record, body, True)
    if (body["review"], body["seq"], body["review_id"]) != (
        digest(version),
        review["seq"],
        review["review_id"],
    ):
        raise Refused("review-gate.wrong-review", "the decision names another review version")
    if body["gate"] not in review["gates"]:
        raise Refused("review-gate.unknown-gate", f"gate {body['gate']} is not a gate of it")
    if signer not in review["reviewers"]:
        raise Refused("review-gate.wrong-signer", "the decision is not signed by a reviewer")
    failing = [m["name"] for m in review["monitors"] if not m["passed"]] + [
        f["id"] for f in review["findings"] if f["severity"] == "critical" and f["status"] == "open"
    ]
    if body["decision"] == "approve" and failing:
        raise Refused("review-gate.blocked", f"an approval is blocked by {failing[0]}")
    return {"review_id": body["review_id"], "gate": body["gate"], "decision": body["decision"],
            "seq": body["seq"], "signer": signer, "state": "verified"}  # fmt: skip


__all__ = ["digest", "gate_verify", "review_verify"]
