"""``tine-eval-verdict/1``: one signed score for one dataset item (0.45).

An eval run (``tine eval run``) scores every item of a dataset and signs one
verdict per item with a ``tine-sig/3`` Ed25519 block over its own domain
(``_signed_doc``)::

    {"scheme": "tine-eval-verdict/1",
     "eval": "sha256:<eval id>", "dataset": "sha256:<dataset digest>",
     "item": "<item id>", "item_digest": "sha256:<JCS digest of the item>",
     "run": "<the run whose output was scored>",
     "scorer": "exact" | "regex" | "json-schema" | "python" | "llm-judge" | ...,
     "scorer_version": "<what pins the scorer's configuration>",
     "score": "0".."1", "threshold": "0".."1", "passed": score >= threshold,
     "judge_run": "" | "<the run that recorded the LLM judge>",
     "signer": "sha256:<fingerprint of the signing key>",
     "created_at": "YYYY-MM-DDTHH:MM:SSZ",
     "signature": {tine-sig/3 block, Ed25519, embedded signer key}}

Scores and thresholds are decimal strings with at most six places and no
trailing zero, so every verifier compares them exactly. Verification is
offline; every refusal carries an ``eval-verdict.*`` code.
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from typing import Any

from opentine import _signed_doc
from opentine._signing_pins import key_fingerprint
from opentine.kernel import KernelError, canonical_json

SCHEME = "tine-eval-verdict/1"
DOMAIN = b"opentine.eval-verdict.v1:"
JUDGE = "llm-judge"
FIELDS = (
    "scheme", "eval", "dataset", "item", "item_digest", "run", "scorer", "scorer_version",
    "score", "threshold", "passed", "judge_run", "signer", "created_at",
)  # fmt: skip
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
SCORER_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
VERSION_RE = re.compile(r"[A-Za-z0-9_.:+/-]{1,160}")
SCORE_RE = re.compile(r"0|1|0\.[0-9]{0,5}[1-9]")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class EvalVerdictError(ValueError):
    """A refusal; ``code`` is the conformance reason (``eval-verdict.*``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> EvalVerdictError:
    return EvalVerdictError("eval-verdict.malformed", message)


def score_text(value: float | int | Decimal) -> str:
    """The canonical decimal string for a score in 0..1 (six places, no trailing zero)."""
    number = Decimal(str(value))
    if not number.is_finite() or not 0 <= number <= 1:
        raise _malformed(f"score {value!r} is outside 0..1")
    text = f"{number.quantize(Decimal('0.000001')):f}".rstrip("0").rstrip(".")
    return text or "0"


def _check(out: dict[str, Any]) -> None:
    for name in ("eval", "dataset", "item_digest", "signer"):
        if not isinstance(out[name], str) or not DIGEST_RE.fullmatch(out[name]):
            raise _malformed(f"{name} must be sha256: + 64 lower hex")
    for name in ("item", "run"):
        if not isinstance(out[name], str) or not NAME_RE.fullmatch(out[name]):
            raise _malformed(f"{name} must be a name of 1..256 safe characters")
    if not isinstance(out["scorer"], str) or not SCORER_RE.fullmatch(out["scorer"]):
        raise _malformed("scorer must be a lower-case scorer id")
    version = out["scorer_version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise _malformed("scorer_version must be 1..160 safe characters")
    for name in ("score", "threshold"):
        if not isinstance(out[name], str) or not SCORE_RE.fullmatch(out[name]):
            raise _malformed(f"{name} must be a canonical decimal string in 0..1")
    if not isinstance(out["passed"], bool):
        raise _malformed("passed must be a boolean")
    judge = out["judge_run"]
    if judge != "" and not (isinstance(judge, str) and NAME_RE.fullmatch(judge)):
        raise _malformed("judge_run must be empty or a run name")
    if not isinstance(out["created_at"], str) or not TIME_RE.fullmatch(out["created_at"]):
        raise _malformed("created_at must be YYYY-MM-DDTHH:MM:SSZ")


def body(verdict: Any) -> dict[str, Any]:
    """The signed part of *verdict*, checked field by field (no semantic checks)."""
    if not isinstance(verdict, dict) or verdict.get("scheme") != SCHEME:
        raise _malformed("not a tine-eval-verdict/1 object")
    if set(verdict) - {*FIELDS, "signature"} or set(FIELDS) - set(verdict):
        raise _malformed("a verdict has exactly the tine-eval-verdict/1 fields")
    out = {name: verdict[name] for name in FIELDS}
    _check(out)
    return out


def digest(verdict: dict[str, Any]) -> str:
    """``sha256:`` over the domain and JCS of the whole verdict, signature included."""
    try:
        return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(verdict)).hexdigest()
    except KernelError as exc:
        raise _malformed(f"verdict cannot be canonicalized: {exc}") from exc


def make(private_key: Any, **fields: Any) -> dict[str, Any]:
    """A signed verdict; ``score``/``threshold`` may be numbers, ``passed`` is derived."""
    from opentine._signing_keys import load_ed25519_private

    private = load_ed25519_private(private_key)
    score, threshold = score_text(fields.pop("score")), score_text(fields.pop("threshold"))
    verdict = {
        "scheme": SCHEME,
        **fields,
        "judge_run": fields.get("judge_run") or "",
        "score": score,
        "threshold": threshold,
        "passed": Decimal(score) >= Decimal(threshold),
        "signer": key_fingerprint(private.public_key().public_bytes_raw()),
    }
    checked = body(verdict)
    verdict["signature"] = _signed_doc.sign(
        DOMAIN, checked, private, signer=checked["signer"], signed_at=checked["created_at"]
    )
    return verdict


def verify(verdict: Any, *, public_key: bytes | None = None) -> dict[str, Any]:
    """``{digest, item, run, passed, signer}`` for a good verdict; raises otherwise.

    The embedded key must be the named ``signer``; with *public_key* it must also
    be that key (``eval-verdict.wrong-key``), else the verdict rests on the
    embedded key alone (trust on first use).
    """
    checked = body(verdict)
    block = verdict.get("signature")
    raw = block.get("public_key") if isinstance(block, dict) else None
    try:
        embedded = bytes.fromhex(raw) if isinstance(raw, str) else b""
    except ValueError:
        embedded = b""
    if len(embedded) != 32 or key_fingerprint(embedded) != checked["signer"]:
        raise EvalVerdictError("eval-verdict.bad-signature", "the signing key is not the signer")
    if public_key is not None and bytes(public_key) != embedded:
        raise EvalVerdictError(
            "eval-verdict.wrong-key", "signed by a key other than the trusted one"
        )
    result = _signed_doc.verify(DOMAIN, checked, block, public_key=embedded)
    if not result.ok:
        raise EvalVerdictError(
            "eval-verdict.bad-signature", f"signature {result.state}: {result.reason}"
        )
    if checked["passed"] != (Decimal(checked["score"]) >= Decimal(checked["threshold"])):
        raise EvalVerdictError("eval-verdict.inconsistent", "passed disagrees with score")
    if (checked["scorer"] == JUDGE) != (checked["judge_run"] != ""):
        raise EvalVerdictError(
            "eval-verdict.judge-mismatch", "an llm-judge verdict, and only one, names a judge_run"
        )
    keep = ("item", "run", "passed", "signer")
    return {"digest": digest(verdict), **{name: checked[name] for name in keep}}


__all__ = [
    "DOMAIN",
    "JUDGE",
    "SCHEME",
    "EvalVerdictError",
    "body",
    "digest",
    "make",
    "score_text",
    "verify",
]
