"""Reviews: ``opentine.review``, its gate decisions and the review bundle (0.47, SPEC 4.20).

A Review is a unit of work across runs and commits, in one repository or
several: the repos it spans (``repos``, each optionally an ``opentine.project``),
the runs and commits it covers (``subjects``), its findings, its monitors (risk,
intent drift and coverage, each an eval scorer's score against a threshold)
and the gates that must be decided. Every change is a new version: ``seq``
counts from 0, ``prev`` is the blob oid of the previous version's canonical
bytes (:func:`digest`), and a version is signed (``tine-sig/3``, Ed25519 only)
over ``opentine.review.v1:`` + JCS of ``{body, header}`` by a reviewer of the
version before it (the first version: one of its own).

A gate decision (``opentine.review-gate``) approves or rejects one gate of one
version, named by digest and seq, signed over ``opentine.review-gate.v1:`` by
a reviewer of that version. An approval is refused while a monitor of that
version fails or a critical finding is open (``review-gate.blocked``).

A review bundle (``opentine.review-bundle``) carries a Review whole: every
version, oldest first, and every decision. :func:`verify_bundle` checks it
offline, decision by decision; only decisions over the head version count
towards the gate status. :func:`check`, :func:`check_gate` and
:func:`verify_bundle` are the references for the ``review.verify``,
``review-gate.verify`` and ``review.bundle`` conformance ops
(``vectors/70-review.json``), ported to the pyz and the TS verifier.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from opentine._review_rules import BUNDLE_KIND, FIELDS, GATE_KIND, KIND, gate_body, review_body
from opentine._signed_record import RecordError, check_signature
from opentine._signed_record import sign as _sign
from opentine.kernel import ObjectEnvelope, canonical_json

DOMAIN = b"opentine.review.v1:"
GATE_DOMAIN = b"opentine.review-gate.v1:"
MAX_VERSIONS = 10_000
MAX_DECISIONS = 10_000


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(record: dict[str, Any]) -> str:
    """The blob oid of *record*'s canonical bytes: what ``prev`` and a decision name."""
    return ObjectEnvelope.create("blob", canonical_json(record)).oid


Rows = list[dict[str, Any]]


def build(review_id: str, *, title: str, reviewers: list[str], repos: Rows,
          subjects: Rows | None = None, findings: Rows | None = None,
          monitors: Rows | None = None, gates: list[str] | None = None,
          previous: dict | None = None, updated_at: str | None = None) -> dict:  # fmt: skip
    """An unsigned version; with *previous*, the next version of its chain."""
    record = {
        "kind": KIND,
        "review_version": 1,
        "review_id": review_id,
        "seq": 0 if previous is None else previous["seq"] + 1,
        "prev": None if previous is None else digest(previous),
        "title": title,
        "reviewers": list(reviewers),
        "repos": sorted(repos, key=lambda row: row["name"]),
        "subjects": list(subjects or []),
        "findings": list(findings or []),
        "monitors": list(monitors or []),
        "gates": sorted(set(gates or [])),
        "updated_at": updated_at or now(),
    }
    return review_body(record)


def build_gate(version: dict[str, Any], gate: str, decision: str, reason: str = "",
               decided_at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """An unsigned decision on *gate* of *version*; *reason* is redacted first."""
    from opentine.redaction import redact_blob

    clean = redact_blob(reason.strip().encode("utf-8")).decode("utf-8", "replace")
    record = {"kind": GATE_KIND, "gate_version": 1, "review_id": version["review_id"],
              "review": digest(version), "seq": version["seq"], "gate": gate,
              "decision": decision, "reason": clean, "decided_at": decided_at or now()}  # fmt: skip
    return gate_body(record)


def sign(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    return _sign(review_body(record), DOMAIN, "review", key, algorithm="ed25519", **header)


def sign_gate(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    body = gate_body(record)
    return _sign(body, GATE_DOMAIN, "review gate decision", key, algorithm="ed25519", **header)


def _signer(record: dict[str, Any], body: dict[str, Any], gate: bool) -> str:
    code, domain, subject = (
        ("review-gate", GATE_DOMAIN, "review gate decision")
        if gate
        else ("review", DOMAIN, "review")
    )
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError(
            f"{code}.wrong-signer", f"a {subject} is signed with a reviewer's Ed25519 key"
        )
    check_signature(record, body, domain=domain, code=code, subject=subject)
    return str(block["public_key"])  # type: ignore[index]


def check(record: Any, *, previous: Any = None, reviewer_key: str | None = None) -> dict[str, Any]:
    """``{review_id, seq, digest, signer, state}`` for one version; refuse else.

    With *previous* the version must follow it and be signed by one of its
    reviewers (``verified``). Without one it is signed by one of its own:
    ``verified`` when that is *reviewer_key*, else ``verified-tofu``.
    """
    found = review_body(record)
    signer = _signer(record, found, False)
    state, reviewers = "verified-tofu", found["reviewers"]
    if previous is not None:
        prior = review_body(previous)
        if (
            found["prev"] != digest(previous)
            or found["seq"] != prior["seq"] + 1
            or found["review_id"] != prior["review_id"]
        ):
            raise RecordError(
                "review.chain-break", f"version {found['seq']} breaks the review chain"
            )
        state, reviewers = "verified", prior["reviewers"]
    elif reviewer_key is not None:
        if signer != reviewer_key:
            raise RecordError("review.wrong-signer", "not signed by the pinned reviewer key")
        state = "verified"
    if signer not in reviewers:
        raise RecordError("review.wrong-signer", "the review is not signed by a reviewer")
    return {"review_id": found["review_id"], "seq": found["seq"], "digest": digest(record),
            "signer": signer, "state": state}  # fmt: skip


def chain(versions: Any, *, reviewer_key: str | None = None) -> dict[str, Any]:
    """Verify a history, oldest first: ``{review_id, head, seq, versions, state}``."""
    if not isinstance(versions, list) or not 1 <= len(versions) <= MAX_VERSIONS:
        raise RecordError("review.malformed", "review is malformed: not a history")
    first = check(versions[0], reviewer_key=reviewer_key)
    if first["seq"] != 0:
        raise RecordError(
            "review.chain-break", "the history does not start at seq 0: it breaks the review chain"
        )
    last = first
    for previous, record in zip(versions, versions[1:]):
        last = check(record, previous=previous)
    return {"review_id": first["review_id"], "head": last["digest"], "seq": last["seq"],
            "versions": len(versions), "state": first["state"]}  # fmt: skip


def blocked(version: dict[str, Any]) -> str | None:
    """Why *version* cannot be approved (a failing monitor, an open critical finding)."""
    for row in version["monitors"]:
        if not row["passed"]:
            return f"monitor {row['name']} fails ({row['score']} < {row['threshold']})"
    for row in version["findings"]:
        if row["severity"] == "critical" and row["status"] == "open":
            return f"critical finding {row['id']} is open"
    return None


def check_gate(record: Any, version: Any) -> dict[str, Any]:
    """``{review_id, gate, decision, seq, signer, state}`` for a decision on *version*."""
    found = gate_body(record)
    review = review_body(version)
    signer = _signer(record, found, True)
    if (
        found["review"] != digest(version)
        or found["seq"] != review["seq"]
        or found["review_id"] != review["review_id"]
    ):
        raise RecordError("review-gate.wrong-review", "the decision names another review version")
    if found["gate"] not in review["gates"]:
        raise RecordError("review-gate.unknown-gate", f"gate {found['gate']} is not a gate of it")
    if signer not in review["reviewers"]:
        raise RecordError("review-gate.wrong-signer", "the decision is not signed by a reviewer")
    why = blocked(review) if found["decision"] == "approve" else None
    if why is not None:
        raise RecordError("review-gate.blocked", f"an approval is blocked: {why}")
    return {"review_id": found["review_id"], "gate": found["gate"], "decision": found["decision"],
            "seq": found["seq"], "signer": signer, "state": "verified"}  # fmt: skip


def bundle(versions: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> dict[str, Any]:
    return {"kind": BUNDLE_KIND, "bundle_version": 1, "versions": versions,
            "decisions": decisions}  # fmt: skip


def gate_status(head: dict[str, Any], decided: list[dict[str, Any]]) -> dict[str, str]:
    """Each gate of *head*: ``rejected`` on a reject, ``approved`` on an approval, or pending."""
    out = {gate: "pending" for gate in head["gates"]}
    for row in decided:
        if out.get(row["gate"]) != "rejected":
            out[row["gate"]] = "rejected" if row["decision"] == "reject" else "approved"
    return out


def verify_bundle(value: Any, *, reviewer_key: str | None = None) -> dict[str, Any]:
    """Verify a review bundle whole: the chain, then every decision against its version."""
    if (
        not isinstance(value, dict)
        or value.get("kind") != BUNDLE_KIND
        or set(value) != {"kind", "bundle_version", "versions", "decisions"}
        or value.get("bundle_version") != 1
        or not isinstance(value.get("decisions"), list)
        or len(value["decisions"]) > MAX_DECISIONS
    ):
        raise RecordError("review.malformed", "review is malformed: not a review bundle")
    versions = value["versions"]
    found = chain(versions, reviewer_key=reviewer_key)
    by_digest = {digest(record): record for record in versions}
    current: list[dict[str, Any]] = []
    for record in value["decisions"]:
        named = gate_body(record)["review"]
        if named not in by_digest:
            raise RecordError("review-gate.wrong-review", "the decision names no version here")
        checked = check_gate(record, by_digest[named])
        if named == found["head"]:
            current.append(checked)
    gates = gate_status(versions[-1], current)
    states = set(gates.values())
    status = "approved" if gates and states == {"approved"} else "pending"
    status = "rejected" if "rejected" in states else status
    return {**found, "decisions": len(value["decisions"]), "gates": gates, "status": status}


__all__ = ["DOMAIN", "FIELDS", "GATE_DOMAIN", "KIND", "blocked", "build", "build_gate", "bundle",
           "chain", "check", "check_gate", "digest", "gate_status", "sign", "sign_gate",
           "verify_bundle"]  # fmt: skip
