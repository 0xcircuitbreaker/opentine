"""JSON Schemas for Reviews (0.47, SPEC 4.20).

``opentine-review-1`` (one ``opentine.review`` version),
``opentine-review-gate-1`` (one signed gate decision) and
``opentine-review-bundle-1`` (a Review whole, as ``tine review export`` writes
it) are the records; ``tine-cli-review-1`` is the ``--json`` output of every
``tine review`` action. The schemas check shape; the signatures, the chain,
the monitor arithmetic and the gate rules are the verifier's
(``opentine._review``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, SIG, STR, closed, doc, open_, opt

_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_BLOB: dict[str, Any] = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_SCORE: dict[str, Any] = {"type": "string", "pattern": "^(0|1|0\\.[0-9]{0,5}[1-9])$"}
_TEXT: dict[str, Any] = {"type": "string", "minLength": 1, "maxLength": 1024}
_REPO = closed(["name", "project"], {"name": _ID, "project": opt(_ID)})
_SUBJECT_ID = "^(run:sha256:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{64})$"
_SUBJECT = closed(["repo", "type", "id"], {
    "repo": _ID, "type": {"enum": ["run", "commit"]},
    "id": {"type": "string", "pattern": _SUBJECT_ID}})  # fmt: skip
_FINDING = closed(["id", "severity", "subject", "message", "status"], {
    "id": _ID, "severity": {"enum": ["info", "low", "medium", "high", "critical"]},
    "subject": opt(INT), "message": _TEXT, "status": {"enum": ["open", "resolved"]}})  # fmt: skip
_MONITOR = closed(["name", "scorer", "score", "threshold", "passed", "verdict"], {
    "name": {"enum": ["risk", "intent-drift", "coverage"]},
    "scorer": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"},
    "score": _SCORE, "threshold": _SCORE, "passed": BOOL,
    "verdict": opt({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})})  # fmt: skip
_VERSION = {"$ref": "opentine-review-1.schema.json"}
_DECISION = {"$ref": "opentine-review-gate-1.schema.json"}
_GATES = {"type": "object", "additionalProperties": {"enum": ["approved", "rejected", "pending"]}}


def _list(items: dict[str, Any], most: int, least: int = 0) -> dict[str, Any]:
    return {"type": "array", "items": items, "minItems": least, "maxItems": most}


SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-review-1": doc("opentine-review-1", "opentine.review (review_version 1)",
        "One version of a Review (SPEC 4.20): the repos it spans, the runs and commits it "
        "covers, its findings, its monitors (eval scorers) and its gates. `prev` is the "
        "previous version's blob-oid digest (null for seq 0); `signature` is an Ed25519 "
        "tine-sig/3 block by a reviewer of the previous version, over `opentine.review.v1:` + "
        "JCS({body, header}).",
        closed(["kind", "review_version", "review_id", "seq", "prev", "title", "reviewers",
                "repos", "subjects", "findings", "monitors", "gates", "updated_at",
                "signature"], {
            "kind": {"const": "opentine.review"}, "review_version": {"const": 1},
            "review_id": _ID, "seq": INT, "prev": opt(_BLOB),
            "title": {"type": "string", "minLength": 1, "maxLength": 256},
            "reviewers": _list({"type": "string", "pattern": "^[0-9a-f]{64}$"}, 16, 1),
            "repos": _list(_REPO, 16, 1), "subjects": _list(_SUBJECT, 1024),
            "findings": _list(_FINDING, 1024), "monitors": _list(_MONITOR, 64),
            "gates": _list(_ID, 32), "updated_at": _WHEN, "signature": SIG})),
    "opentine-review-gate-1": doc("opentine-review-gate-1",
        "opentine.review-gate (gate_version 1)",
        "One reviewer's signed decision on one gate of one Review version (SPEC 4.20), named by "
        "its digest and seq; an approval is refused while a monitor of that version fails or "
        "a critical finding is open. Signed (Ed25519 tine-sig/3) over "
        "`opentine.review-gate.v1:` + JCS({body, header}).",
        closed(["kind", "gate_version", "review_id", "review", "seq", "gate", "decision",
                "reason", "decided_at", "signature"], {
            "kind": {"const": "opentine.review-gate"}, "gate_version": {"const": 1},
            "review_id": _ID, "review": _BLOB, "seq": INT, "gate": _ID,
            "decision": {"enum": ["approve", "reject"]},
            "reason": {"type": "string", "maxLength": 1024}, "decided_at": _WHEN,
            "signature": SIG})),
    "opentine-review-bundle-1": doc("opentine-review-bundle-1",
        "opentine.review-bundle (bundle_version 1)",
        "A Review whole (SPEC 4.20): every version oldest first and every gate decision, as "
        "`tine review export` writes it and `tine-verify.pyz --offline` checks it. Unsigned "
        "itself; everything in it is signed.",
        closed(["kind", "bundle_version", "versions", "decisions"], {
            "kind": {"const": "opentine.review-bundle"}, "bundle_version": {"const": 1},
            "versions": _list(_VERSION, 10_000, 1), "decisions": _list(_DECISION, 10_000)})),
    "tine-cli-review-1": doc("tine-cli-review-1", "tine review ACTION --json",
        "Every `tine review` action. `create`/`add`: the new `version` and its `digest`; "
        "`gate`: the signed `decision`, its `digest` and the `gate` check; `show`, `export`, "
        "`verify`: `result`, the bundle check (`show` adds the head `version`); `import`: "
        "`added`; `push`: `versions`, `decisions`, `head`; `run` (0.48): the reviewer fleet's "
        "`fleet`, `fleet_id`, `exit_code`, `members`, the signed `findings` (each checked), "
        "the lines `skipped` and the new `head`; `findings`: the stored `findings`, each "
        "checked. A refusal is the error envelope, exit 4 for a verification failure.",
        open_(["command", "action", "ok"], {
            "command": {"const": "review"},
            "action": {"enum": ["create", "add", "gate", "show", "export", "verify", "import",
                                "push", "run", "findings"]},
            "ok": BOOL, "version": _VERSION, "decision": _DECISION, "digest": _BLOB,
            "gate": open_(["review_id", "gate", "decision", "seq", "state"], {
                "review_id": _ID, "gate": _ID, "decision": STR, "seq": INT, "state": STR}),
            "result": open_(["review_id", "head", "seq", "versions", "decisions", "gates",
                             "status", "state"], {
                "review_id": _ID, "head": _BLOB, "seq": INT, "versions": INT, "decisions": INT,
                "gates": _GATES, "status": {"enum": ["approved", "rejected", "pending"]},
                "state": STR}),
            "added": closed(["versions", "decisions"], {"versions": INT, "decisions": INT}),
            "versions": INT, "decisions": INT, "head": opt(_BLOB),
            "review_id": _ID, "fleet": STR, "fleet_id": STR, "exit_code": INT, "skipped": INT,
            "members": _list(open_(["key", "name", "status"], {
                "key": STR, "name": STR, "status": STR}), 10_000),
            "findings": _list(open_(["finding_id", "state"], {
                "finding_id": opt(STR), "state": {"enum": ["verified", "verified-tofu",
                                                           "failed"]}}), 100_000)})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"review": "tine-cli-review-1"}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.review": "opentine-review-1",
    "opentine.review-gate": "opentine-review-gate-1",
    "opentine.review-bundle": "opentine-review-bundle-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
