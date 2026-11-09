"""The field rules of ``opentine.review`` and ``opentine.review-gate`` (0.47, SPEC 4.19-4.20).

:func:`review_body` and :func:`gate_body` return a record's signed body after
every rule here, or raise :class:`opentine._signed_record.RecordError` with a
``review.*`` / ``review-gate.*`` code: ``malformed`` for a missing, extra or
ill-formed field and ``review.inconsistent`` for a monitor whose ``passed``
disagrees with its score and threshold. Ported to the pyz
(``opentine._pyz._review``) and the TS verifier (``src/review.ts``).

Scores and thresholds are the decimal strings of ``tine-eval-verdict/1`` (at
most six places, no trailing zero) and every monitor is a scorer: it passes
when ``score >= threshold``, compared exactly in millionths (:func:`micros`).
"""

from __future__ import annotations

import re
from typing import Any

from opentine._signed_record import DIGEST, RUN_OID, WHEN, RecordError, fields

KIND = "opentine.review"
GATE_KIND = "opentine.review-gate"
BUNDLE_KIND = "opentine.review-bundle"
FIELDS = ("kind", "review_version", "review_id", "seq", "prev", "title", "reviewers", "repos",
          "subjects", "findings", "monitors", "gates", "updated_at")  # fmt: skip
GATE_FIELDS = ("kind", "gate_version", "review_id", "review", "seq", "gate", "decision",
               "reason", "decided_at")  # fmt: skip
REPO_FIELDS = ("name", "project")
SUBJECT_FIELDS = ("repo", "type", "id")
FINDING_FIELDS = ("id", "severity", "subject", "message", "status")
MONITOR_FIELDS = ("name", "scorer", "score", "threshold", "passed", "verdict")
SEVERITIES = ("info", "low", "medium", "high", "critical")
MONITORS = ("risk", "intent-drift", "coverage")
DECISIONS = ("approve", "reject")
LIMITS = {"reviewers": 16, "repos": 16, "subjects": 1024, "findings": 1024, "monitors": 64,
          "gates": 32}  # fmt: skip
ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
KEY = re.compile(r"[0-9a-f]{64}")
BLOB_OID = re.compile(r"blob:sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SCORER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SCORE = re.compile(r"0|1|0\.[0-9]{0,5}[1-9]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def malformed(code: str, message: str) -> RecordError:
    subject = "review" if code == "review" else "review gate decision"
    return RecordError(f"{code}.malformed", f"{subject} is malformed: {message}")


def _is(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def text_ok(value: Any, limit: int, *, empty: bool = False) -> bool:
    """1 (or 0, with *empty*) to *limit* UTF-8 bytes of text without control characters."""
    if not isinstance(value, str) or (not empty and not value.strip()):
        return False
    return len(value.encode("utf-8", "surrogatepass")) <= limit and not _CONTROL.search(value)


def micros(score: str) -> int:
    """A score string in millionths: ``"0.75"`` is 750000."""
    if score in ("0", "1"):
        return int(score) * 1_000_000
    return int(score[2:].ljust(6, "0"))


def _rows(value: Any, names: tuple[str, ...], what: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > LIMITS[what]:
        raise malformed("review", f"{what} is a list of at most {LIMITS[what]}")
    for row in value:
        if not isinstance(row, dict) or set(row) != set(names):
            raise malformed("review", f"each of {what} has exactly " + ", ".join(names))
    return value


def _distinct(values: list[Any], what: str) -> None:
    if len(set(values)) != len(values):
        raise malformed("review", f"{what} must be distinct")


def _subjects(found: dict[str, Any], repos: set[str]) -> None:
    subjects = _rows(found["subjects"], SUBJECT_FIELDS, "subjects")
    for row in subjects:
        pattern = RUN_OID if row["type"] == "run" else COMMIT if row["type"] == "commit" else None
        if row["repo"] not in repos or pattern is None or not _is(row["id"], pattern):
            raise malformed("review", "a subject is a run oid or commit id in a listed repo")
    _distinct([(r["repo"], r["type"], r["id"]) for r in subjects], "subjects")
    findings = _rows(found["findings"], FINDING_FIELDS, "findings")
    for row in findings:
        at = row["subject"]
        if (
            not _is(row["id"], ID)
            or row["severity"] not in SEVERITIES
            or row["status"] not in ("open", "resolved")
            or not text_ok(row["message"], 1024)
            or not (at is None or (_count(at) and at < len(subjects)))
        ):
            raise malformed("review", "a finding has an id, severity, status, message, subject")
    _distinct([row["id"] for row in findings], "finding ids")


def _monitors(found: dict[str, Any]) -> None:
    monitors = _rows(found["monitors"], MONITOR_FIELDS, "monitors")
    for row in monitors:
        if (
            row["name"] not in MONITORS
            or not _is(row["scorer"], SCORER)
            or not _is(row["score"], SCORE)
            or not _is(row["threshold"], SCORE)
            or not isinstance(row["passed"], bool)
            or not (row["verdict"] is None or _is(row["verdict"], DIGEST))
        ):
            raise malformed("review", "a monitor is risk, intent-drift or coverage with a score")
    _distinct([row["name"] for row in monitors], "monitor names")
    for row in monitors:
        if row["passed"] != (micros(row["score"]) >= micros(row["threshold"])):
            raise RecordError(
                "review.inconsistent", f"monitor {row['name']}: passed disagrees with its score"
            )


def review_body(record: Any) -> dict[str, Any]:
    """The signed body of a review version, after the field rules."""
    found = fields(record, KIND, FIELDS, "review", "review")
    seq, prev = found["seq"], found["prev"]
    checks = (
        (found["review_version"] == 1 and _count(found["review_version"]), "review_version is 1"),
        (_is(found["review_id"], ID), "review_id is [a-z0-9][a-z0-9._-]{0,63}"),
        (_count(seq), "seq is a count"),
        (prev is None if seq == 0 else _is(prev, BLOB_OID), "prev and seq disagree"),
        (text_ok(found["title"], 256), "title is 1 to 256 bytes of text"),
        (_is(found["updated_at"], WHEN), "updated_at is an RFC 3339 UTC time"),
    )
    for ok, message in checks:
        if not ok:
            raise malformed("review", message)
    reviewers = found["reviewers"]
    if (
        not isinstance(reviewers, list)
        or not 1 <= len(reviewers) <= LIMITS["reviewers"]
        or not all(_is(key, KEY) for key in reviewers)
    ):
        raise malformed("review", "reviewers is 1 to 16 Ed25519 public keys")
    _distinct(reviewers, "reviewers")
    repos = _rows(found["repos"], REPO_FIELDS, "repos")
    names = [row["name"] for row in repos]
    if not repos or not all(_is(n, ID) for n in names) or names != sorted(set(names)):
        raise malformed("review", "repos is 1 to 16 repos, sorted by distinct name")
    if not all(row["project"] is None or _is(row["project"], ID) for row in repos):
        raise malformed("review", "a repo's project is a project id or null")
    _subjects(found, set(names))
    _monitors(found)
    gates = found["gates"]
    if (
        not isinstance(gates, list)
        or len(gates) > LIMITS["gates"]
        or not all(_is(g, ID) for g in gates)
        or gates != sorted(set(gates))
    ):
        raise malformed("review", "gates is at most 32 sorted, distinct gate names")
    return found


def gate_body(record: Any) -> dict[str, Any]:
    """The signed body of a gate decision, after the field rules."""
    found = fields(record, GATE_KIND, GATE_FIELDS, "review-gate", "review gate decision")
    checks = (
        (found["gate_version"] == 1 and _count(found["gate_version"]), "gate_version is 1"),
        (_is(found["review_id"], ID) and _is(found["gate"], ID), "review_id and gate are ids"),
        (_is(found["review"], BLOB_OID), "review is the decided version's blob oid"),
        (_count(found["seq"]), "seq is a count"),
        (found["decision"] in DECISIONS, "decision is approve or reject"),
        (text_ok(found["reason"], 1024, empty=True), "reason is at most 1024 bytes of text"),
        (_is(found["decided_at"], WHEN), "decided_at is an RFC 3339 UTC time"),
    )
    for ok, message in checks:
        if not ok:
            raise malformed("review-gate", message)
    return found


__all__ = [
    "BUNDLE_KIND",
    "DECISIONS",
    "FIELDS",
    "GATE_FIELDS",
    "GATE_KIND",
    "ID",
    "KIND",
    "MONITORS",
    "SEVERITIES",
    "gate_body",
    "micros",
    "review_body",
    "text_ok",
]
