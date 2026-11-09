"""SPEC 4.19 Reviews: versions, gate decisions and the review bundle (0.47).

Every record is signed with the published Ed25519 seeds in ``keys``
(deterministic, and every record fixes ``signed_at``, ``updated_at`` and
``decided_at``), so the input bytes are stable. ``ed25519_seed`` is the first
reviewer, ``ed25519_seed_b`` a stranger (a reviewer once a version adds it).
Bodies the field rules would refuse are signed with the raw signer, so each
refusal is the one the case names. Only the ops in ``adapter_review`` answer.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _review
from opentine._signed_record import sign as raw_sign
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
WHEN = "2026-11-09T00:00:00Z"
RUN = "run:sha256:" + "1" * 64
COMMIT = "a" * 40


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _hex(name: str) -> str:
    return _key(name).public_key().public_bytes_raw().hex()


ALICE, BOB = _hex("ed25519_seed"), _hex("ed25519_seed_b")


def _edited(record: dict, **fields) -> dict:
    out = copy.deepcopy(record)
    out.update(fields)
    return out


def _monitor(name="coverage", score="0.9", threshold="0.8", passed=True) -> dict:
    return {"name": name, "scorer": "exact", "score": score, "threshold": threshold,
            "passed": passed, "verdict": None}  # fmt: skip


def _version(previous=None, **fields) -> dict:
    return {"kind": _review.KIND, "review_version": 1, "review_id": "auth-rework",
            "seq": 0 if previous is None else previous["seq"] + 1,
            "prev": None if previous is None else _review.digest(previous),
            "title": "Rework the auth flow", "reviewers": [ALICE],
            "repos": [{"name": "app", "project": "app"}, {"name": "infra", "project": None}],
            "subjects": [], "findings": [], "monitors": [], "gates": ["ship"],
            "updated_at": WHEN, **fields}  # fmt: skip


def _signed(record: dict, key: str = "ed25519_seed", *, gate: bool = False) -> dict:
    domain, subject = (
        (_review.GATE_DOMAIN, "review gate decision") if gate else (_review.DOMAIN, "review")
    )
    return raw_sign(record, domain, subject, _key(key), algorithm="ed25519", key_id="vector",
                    signed_at=WHEN)  # fmt: skip


def _hmac_signed(record: dict) -> dict:
    return raw_sign(record, _review.DOMAIN, "review", KEYS["hmac_a"], algorithm="hmac-sha256",
                    key_id="vector", signed_at=WHEN)  # fmt: skip


_SUBJECTS = [{"repo": "app", "type": "run", "id": RUN},
             {"repo": "infra", "type": "commit", "id": COMMIT}]  # fmt: skip
_FINDING = {"id": "f1", "severity": "high", "subject": 0, "message": "a token is logged",
            "status": "open"}  # fmt: skip
_V0 = _signed(_version())
_V1 = _signed(_version(_V0, reviewers=[ALICE, BOB], subjects=_SUBJECTS, findings=[_FINDING],
                       monitors=[_monitor()]))  # fmt: skip
_V2 = _signed(_version(_V1, reviewers=[ALICE, BOB], subjects=_SUBJECTS,
                       findings=[{**_FINDING, "status": "resolved"}],
                       monitors=[_monitor(), _monitor("risk", "0.95", "0.9")]),
              "ed25519_seed_b")  # fmt: skip
_FAILING = _signed(_version(_V0, monitors=[_monitor("intent-drift", "0.4", "0.7", False)]))
_CRITICAL = _signed(_version(_V0, subjects=_SUBJECTS[:1],
                             findings=[{**_FINDING, "severity": "critical"}]))  # fmt: skip


def _decision(version: dict, decision: str = "approve", **fields) -> dict:
    return {"kind": "opentine.review-gate", "gate_version": 1, "review_id": "auth-rework",
            "review": _review.digest(version), "seq": version["seq"], "gate": "ship",
            "decision": decision, "reason": "", "decided_at": WHEN, **fields}  # fmt: skip


def _gate(version: dict, key: str = "ed25519_seed", **fields) -> dict:
    return _signed(_decision(version, **fields), key, gate=True)


_APPROVE = _gate(_V2, "ed25519_seed_b", reason="coverage and risk hold")
_STALE = _gate(_V1)


def _r(name, expect, intent, record, reason=None, *, previous=None, pin=None) -> Case:
    value = {"version": record, "previous": previous, "reviewer_key": pin}
    return Case(id=f"review.{name}", section="4.19", checklist=(8,), op="review.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


def _g(name, expect, intent, record, version, reason=None) -> Case:
    return Case(id=f"review-gate.{name}", section="4.19", checklist=(8,),
                op="review-gate.verify", profile=VERIFIER, expect=expect, intent=intent,
                input=V({"decision": record, "version": version}), reason=reason)  # fmt: skip


def _b(name, expect, intent, versions, decisions, reason=None, **extra) -> Case:
    bundle = {**_review.bundle(versions, decisions), **extra}
    return Case(id=f"review.bundle.{name}", section="4.19", checklist=(8,), op="review.bundle",
                profile=VERIFIER, expect=expect, intent=intent,
                input=V({"bundle": bundle, "reviewer_key": None}), reason=reason)  # fmt: skip


REVIEW = Family(
    "70-review.json",
    "4.19",
    "review",
    (
        _r("valid-first", ACCEPT, "a first version signed by its own reviewer (trust on first use)",
           _V0),
        _r("valid-first-pinned", ACCEPT, "a first version under the pinned reviewer key", _V0,
           pin=ALICE),
        _r("valid-next", ACCEPT, "runs and commits in two repos, a finding and a monitor", _V1,
           previous=_V0),
        _r("valid-added-reviewer", ACCEPT, "a reviewer the previous version added signs the next",
           _V2, previous=_V1),
        _r("unsigned", REJECT, "a version without a signature is refused", _version(),
           "review.unsigned"),
        _r("tampered", REJECT, "a title edited after signing fails",
           _edited(_V0, title="Something else"), "review.bad-signature"),
        _r("wrong-signer-first", REJECT, "a first version signed by a key it does not list",
           _signed(_version(), "ed25519_seed_b"), "review.wrong-signer"),
        _r("wrong-pinned", REJECT, "a first version under another pinned reviewer key", _V0,
           "review.wrong-signer", pin=BOB),
        _r("self-added", REJECT, "a stranger cannot add itself and sign that same version",
           _signed(_version(_V0, reviewers=[ALICE, BOB]), "ed25519_seed_b"),
           "review.wrong-signer", previous=_V0),
        _r("not-ed25519", REJECT, "a review is signed with a reviewer's Ed25519 key",
           _hmac_signed(_version()), "review.wrong-signer"),
        _r("chain-break-prev", REJECT, "prev names something other than the predecessor",
           _signed(_version(_V0, prev="blob:sha256:" + "9" * 64)), "review.chain-break",
           previous=_V0),
        _r("chain-break-seq", REJECT, "seq skips a version", _signed(_version(_V0, seq=2)),
           "review.chain-break", previous=_V0),
        _r("chain-break-id", REJECT, "a version cannot move to another review",
           _signed(_version(_V0, review_id="other")), "review.chain-break", previous=_V0),
        _r("extra-field", REJECT, "a field the review format does not define",
           _edited(_V0, assignee="bob"), "review.malformed"),
        _r("unknown-repo", REJECT, "a subject names a repo the review does not span",
           _signed(_version(subjects=[{"repo": "docs", "type": "run", "id": RUN}])),
           "review.malformed"),
        _r("bad-commit", REJECT, "a commit id is 40 or 64 lowercase hex",
           _signed(_version(subjects=[{"repo": "infra", "type": "commit", "id": "HEAD"}])),
           "review.malformed"),
        _r("unsorted-repos", REJECT, "repos are sorted by distinct name",
           _signed(_version(repos=[{"name": "infra", "project": None},
                                   {"name": "app", "project": "app"}])), "review.malformed"),
        _r("unsorted-gates", REJECT, "gates are sorted and distinct",
           _signed(_version(gates=["ship", "security"])), "review.malformed"),
        _r("finding-subject", REJECT, "a finding's subject indexes the subjects list",
           _signed(_version(findings=[_FINDING])), "review.malformed"),
        _r("trailing-zero", REJECT, "a score is a canonical decimal (no trailing zero)",
           _signed(_version(monitors=[_monitor(score="0.90")])), "review.malformed"),
        _r("unknown-monitor", REJECT, "monitors are risk, intent-drift and coverage",
           _signed(_version(monitors=[_monitor(name="vibes")])), "review.malformed"),
        _r("passed-disagrees", REJECT, "a monitor that passes below its threshold",
           _signed(_version(monitors=[_monitor(score="0.5", passed=True)])),
           "review.inconsistent"),
        _r("first-with-prev", REJECT, "seq 0 has no predecessor",
           _signed(_version(prev="blob:sha256:" + "1" * 64)), "review.malformed"),
        _g("approve", ACCEPT, "a reviewer approves a gate of the version it names", _APPROVE,
           _V2),
        _g("reject-blocked", ACCEPT, "a reject needs no passing monitor",
           _gate(_FAILING, decision="reject", reason="intent drifted"), _FAILING),
        _g("unsigned", REJECT, "a decision without a signature is refused", _decision(_V2),
           _V2, "review-gate.unsigned"),
        _g("tampered", REJECT, "a reject turned into an approval after signing",
           _edited(_gate(_V2, decision="reject"), decision="approve"), _V2,
           "review-gate.bad-signature"),
        _g("stranger", REJECT, "a key that is not a reviewer of that version",
           _gate(_V0, "ed25519_seed_b"), _V0, "review-gate.wrong-signer"),
        _g("other-version", REJECT, "a decision on one version checked against another",
           _STALE, _V2, "review-gate.wrong-review"),
        _g("unknown-gate", REJECT, "a gate the version does not list",
           _gate(_V2, gate="deploy"), _V2, "review-gate.unknown-gate"),
        _g("blocked-monitor", REJECT, "no approval while a monitor fails", _gate(_FAILING),
           _FAILING, "review-gate.blocked"),
        _g("blocked-critical", REJECT, "no approval while a critical finding is open",
           _gate(_CRITICAL), _CRITICAL, "review-gate.blocked"),
        _g("bad-decision", REJECT, "a decision is approve or reject",
           _gate(_V2, decision="maybe"), _V2, "review-gate.malformed"),
        _b("approved", ACCEPT, "every gate of the head version approved", [_V0, _V1, _V2],
           [_STALE, _APPROVE]),
        _b("pending", ACCEPT, "a decision on an older version does not count for the head",
           [_V0, _V1, _V2], [_STALE]),
        _b("rejected", ACCEPT, "one reject outweighs an approval",
           [_V0, _V1, _V2], [_APPROVE, _gate(_V2, decision="reject", reason="no")]),
        _b("foreign-decision", REJECT, "a decision on a version the bundle does not hold",
           [_V0, _V1], [_APPROVE], "review-gate.wrong-review"),
        _b("reordered", REJECT, "versions are oldest first", [_V1, _V0], [],
           "review.chain-break"),
        _b("forged-decision", REJECT, "a decision edited inside the bundle",
           [_V0, _V1, _V2], [_edited(_APPROVE, reason="forged")], "review-gate.bad-signature"),
        _b("extra-key", REJECT, "a bundle has exactly its four keys", [_V0], [],
           "review.malformed", signatures=[]),
    ),
)  # fmt: skip

FAMILIES = (REVIEW,)
