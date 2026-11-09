"""SPEC 4.25 review findings (0.48): one reviewer's signed ``opentine.review-finding``.

Records are signed with the published Ed25519 seeds in ``keys`` (``ed25519_seed``
the reviewer who ran the review, ``ed25519_seed_b`` a stranger) and fix
``created_at`` and ``signed_at``, so the input bytes are stable. Only
``adapter_registry.op_review_finding_verify`` answers.
"""

from __future__ import annotations

from opentine import _review_finding
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.cases_registry import AUTHOR, STRANGER, WHEN, _edited, _hmac, _signed

_RUN = "run:sha256:" + "cd" * 32


def _finding(**fields) -> dict:
    return {"kind": _review_finding.KIND, "finding_version": 1, "review_id": "auth",
            "finding_id": "rf-0a1b2c3d4e5f", "severity": "high", "path": "src/auth/login.py",
            "line": 42, "message": "the session token is written to the debug log",
            "reviewer": "security-0", "run": None, "created_at": WHEN, **fields}  # fmt: skip


def _fs(record: dict, key: str = "ed25519_seed") -> dict:
    return _signed(record, _review_finding.DOMAIN, "review finding", key)


_F1 = _fs(_finding())


def _f(name, expect, intent, record, reason=None, *, key=None, reviewers=()) -> Case:
    value = {"record": record, "public_key": key, "reviewers": list(reviewers)}
    return Case(id=f"review-finding.{name}", section="4.25", checklist=(8,),
                op="review-finding.verify", profile="verifier", expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


REVIEW_FINDING = Family(
    "74-review-finding.json",
    "4.25",
    "review-finding",
    (
        _f("valid-tofu", ACCEPT, "a finding resting on its embedded key", _F1),
        _f("valid-pinned", ACCEPT, "a finding under the pinned key", _F1, key=AUTHOR),
        _f("valid-reviewers", ACCEPT, "a finding signed by a reviewer of the Review", _F1,
           reviewers=(STRANGER, AUTHOR)),
        _f("valid-no-location", ACCEPT, "a finding about the change as a whole",
           _fs(_finding(path=None, line=None, severity="info"))),
        _f("valid-path-only", ACCEPT, "a path without a line", _fs(_finding(line=None))),
        _f("valid-run", ACCEPT, "the reviewer recorded its run", _fs(_finding(run=_RUN))),
        _f("untrusted-signer", REJECT, "a finding by a key that is not a reviewer", _F1,
           "review-finding.untrusted-signer", reviewers=(STRANGER,)),
        _f("wrong-pinned-key", REJECT, "signed by a key other than the pinned one", _F1,
           "review-finding.wrong-key", key=STRANGER),
        _f("hmac", REJECT, "a review finding is Ed25519 only",
           _hmac(_finding(), _review_finding.DOMAIN, "review finding"),
           "review-finding.wrong-key"),
        _f("line-without-path", REJECT, "a line needs a path",
           _fs(_finding(path=None)), "review-finding.malformed"),
        _f("line-zero", REJECT, "lines count from 1", _fs(_finding(line=0)),
           "review-finding.malformed"),
        _f("absolute-path", REJECT, "a path is repository-relative",
           _fs(_finding(path="/etc/passwd")), "review-finding.malformed"),
        _f("dotdot-path", REJECT, "a path never climbs out of the repository",
           _fs(_finding(path="src/../../secret")), "review-finding.malformed"),
        _f("backslash-path", REJECT, "a path is POSIX", _fs(_finding(path="src\\auth.py")),
           "review-finding.malformed"),
        _f("bad-severity", REJECT, "severity is one of the five Review severities",
           _fs(_finding(severity="blocker")), "review-finding.malformed"),
        _f("control-character", REJECT, "a message holds no control character",
           _fs(_finding(message="ring\x07the bell")), "review-finding.malformed"),
        _f("oversized-message", REJECT, "a message is at most 1024 bytes",
           _fs(_finding(message="x" * 1025)), "review-finding.malformed"),
        _f("bad-run", REJECT, "run is a run oid or null",
           _fs(_finding(run="blob:sha256:" + "cd" * 32)), "review-finding.malformed"),
        _f("extra-field", REJECT, "a field the format does not define",
           _edited(_F1, verdict="pass"), "review-finding.malformed"),
        _f("unsigned", REJECT, "a finding without a signature is refused", _finding(),
           "review-finding.unsigned"),
        _f("tampered", REJECT, "a severity lowered after signing fails",
           _edited(_F1, severity="low"), "review-finding.bad-signature"),
    ),
)  # fmt: skip

FAMILIES = (REVIEW_FINDING,)
