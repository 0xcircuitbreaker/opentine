"""SPEC 4.12 ``tine-eval-verdict/1``: verifying a signed eval verdict offline (0.45).

Verdicts are signed here with the published seeds in ``keys`` (Ed25519 is
deterministic and every verdict fixes ``created_at``), so the input bytes are
stable. The ``inconsistent`` and ``judge-mismatch`` cases are signed bodies
that ``make`` would never produce, so they are signed through ``_signed_doc``.
Only the op in ``adapter_eval`` produces an answer.
"""

from __future__ import annotations

import copy
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _signed_doc
from opentine._eval_verdict import DOMAIN, FIELDS, make
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
WHEN = "2026-11-08T00:00:00Z"
KEY, OTHER = "ed25519_seed", "ed25519_seed_b"


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _public(name: str) -> str:
    private = Ed25519PrivateKey.from_private_bytes(KEYS[name])
    return private.public_key().public_bytes_raw().hex()


BASE = {
    "eval": _digest("eval"),
    "dataset": _digest("dataset"),
    "item": "q-0001",
    "item_digest": _digest("item"),
    "run": "run:sha256:" + hashlib.sha256(b"run").hexdigest(),
    "scorer": "exact",
    "scorer_version": "1",
    "created_at": WHEN,
}


def _verdict(key: str = KEY, **fields) -> dict:
    values = {**BASE, "score": 1, "threshold": 1, "judge_run": "", **fields}
    return make(KEYS[key], **values)


def _forced(**fields) -> dict:
    """A verdict signed over a body ``make`` refuses to build."""
    good = _verdict()
    body = {**{name: good[name] for name in FIELDS}, **fields}
    signature = _signed_doc.sign(
        DOMAIN, body, KEYS[KEY], signer=body["signer"], signed_at=body["created_at"]
    )
    return {**body, "signature": signature}


def _edited(**fields) -> dict:
    verdict = copy.deepcopy(_verdict())
    verdict.update(fields)
    return verdict


def _foreign_key() -> dict:
    verdict = _verdict()
    verdict["signature"]["public_key"] = _public(OTHER)
    return verdict


def _case(name: str, expect: str, intent: str, verdict, reason=None, key=None) -> Case:
    return Case(
        id=f"eval-verdict.{name}",
        section="4.12",
        checklist=(8,),
        op="eval-verdict.verify",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V({"verdict": verdict, "public_key": key}),
        reason=reason,
    )


_JUDGE = "run:sha256:" + hashlib.sha256(b"judge").hexdigest()

EVAL_VERDICT = Family(
    "58-eval-verdict.json",
    "4.12",
    "eval-verdict",
    (
        _case("valid-tofu", ACCEPT, "a verdict verifies under its embedded key", _verdict()),
        _case(
            "valid-trusted",
            ACCEPT,
            "a verdict verifies under the supplied trusted key",
            _verdict(score=0.25, threshold=0.5),
            key=_public(KEY),
        ),
        _case(
            "valid-judge",
            ACCEPT,
            "an llm-judge verdict names the run that recorded the judge",
            _verdict(
                scorer="llm-judge",
                scorer_version="1+sha256:0123456789abcdef",
                score=0.75,
                threshold=0.7,
                judge_run=_JUDGE,
            ),  # fmt: skip
        ),
        _case(
            "score-edited",
            REJECT,
            "a score edited after signing fails the signature",
            _edited(score="0", passed=False),
            "eval-verdict.bad-signature",
        ),
        _case(
            "foreign-key",
            REJECT,
            "an embedded key that is not the named signer is refused",
            _foreign_key(),
            "eval-verdict.bad-signature",
        ),
        _case(
            "wrong-key",
            REJECT,
            "a verdict signed by a key other than the trusted one is refused",
            _verdict(),
            "eval-verdict.wrong-key",
            key=_public(OTHER),
        ),
        _case(
            "inconsistent",
            REJECT,
            "a signed verdict whose passed disagrees with score >= threshold is refused",
            _forced(score="0.5", passed=True),
            "eval-verdict.inconsistent",
        ),
        _case(
            "judge-missing",
            REJECT,
            "a signed llm-judge verdict without a judge_run is refused",
            _forced(scorer="llm-judge"),
            "eval-verdict.judge-mismatch",
        ),
        _case(
            "score-not-canonical",
            REJECT,
            "a score with a trailing zero is malformed",
            _edited(score="0.50"),
            "eval-verdict.malformed",
        ),
        _case(
            "missing-field",
            REJECT,
            "a verdict without its run is malformed",
            {k: v for k, v in _verdict().items() if k != "run"},
            "eval-verdict.malformed",
        ),
    ),
)

FAMILIES = (EVAL_VERDICT,)
