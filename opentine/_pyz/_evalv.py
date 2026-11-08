"""``tine-eval-verdict/1`` verdicts, checked with the standard library alone (0.45).

An independent port of ``opentine._eval_verdict.verify`` for ``tine-verify.pyz``:
the same field rules, the embedded key must be the named ``signer`` (and the
``--pubkey`` key when one is given), the Ed25519 ``tine-sig/3`` block is over
``opentine.eval-verdict.v1:`` + JCS of ``{"body": ..., "header": ...}``,
``passed`` must equal ``score >= threshold`` and only an ``llm-judge`` verdict
names a ``judge_run``. Input is an eval folder (``verdicts.jsonl``) or a
``.jsonl`` file of verdicts; reason codes are the conformance suite's.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

from .. import kernel
from . import _sig
from ._artifact import check

SCHEME = "tine-eval-verdict/1"
DOMAIN = b"opentine.eval-verdict.v1:"
EVAL_DOMAIN = b"opentine.eval.v1:"
PINNED = ("dataset", "scorer", "scorer_version", "threshold", "created_at", "signer")
FIELDS = (
    "scheme", "eval", "dataset", "item", "item_digest", "run", "scorer", "scorer_version",
    "score", "threshold", "passed", "judge_run", "signer", "created_at",
)  # fmt: skip
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_PATTERNS = {
    "eval": _DIGEST, "dataset": _DIGEST, "item_digest": _DIGEST, "signer": _DIGEST,
    "item": _NAME, "run": _NAME,
    "scorer": re.compile(r"[a-z0-9][a-z0-9-]{0,63}"),
    "scorer_version": re.compile(r"[A-Za-z0-9_.:+/-]{1,160}"),
    "score": re.compile(r"0|1|0\.[0-9]{0,5}[1-9]"),
    "threshold": re.compile(r"0|1|0\.[0-9]{0,5}[1-9]"),
    "created_at": re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"),
}  # fmt: skip


class Refused(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _body(verdict: Any) -> dict[str, Any]:
    if not isinstance(verdict, dict) or verdict.get("scheme") != SCHEME:
        raise Refused("eval-verdict.malformed", "not a tine-eval-verdict/1 object")
    if set(verdict) - {*FIELDS, "signature"} or set(FIELDS) - set(verdict):
        raise Refused("eval-verdict.malformed", "a verdict has exactly the verdict fields")
    body = {name: verdict[name] for name in FIELDS}
    for name, pattern in _PATTERNS.items():
        if not isinstance(body[name], str) or not pattern.fullmatch(body[name]):
            raise Refused("eval-verdict.malformed", f"{name} is malformed")
    judge = body["judge_run"]
    if not isinstance(body["passed"], bool) or not (
        judge == "" or (isinstance(judge, str) and _NAME.fullmatch(judge))
    ):
        raise Refused("eval-verdict.malformed", "passed or judge_run is malformed")
    return body


def verify(verdict: Any, public_key: bytes | None = None) -> dict[str, Any]:
    """``{item, passed, signer}`` for a good verdict; :class:`Refused` otherwise."""
    body = _body(verdict)
    block = verdict.get("signature")
    raw = block.get("public_key") if isinstance(block, dict) else None
    embedded = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b""
    if not embedded or "sha256:" + hashlib.sha256(embedded).hexdigest() != body["signer"]:
        raise Refused("eval-verdict.bad-signature", "the signing key is not the signer")
    if public_key is not None and bytes(public_key) != embedded:
        raise Refused("eval-verdict.wrong-key", "signed by a key other than the trusted one")
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        raise Refused("eval-verdict.bad-signature", "Ed25519 only")

    def message(header: dict[str, Any]) -> bytes:
        return DOMAIN + kernel.canonical_json({"body": body, "header": header})

    ok, state, reason = _sig.verify_block(
        block, message, ("tine-sig/3",), hmac_key=None, public_key=embedded
    )
    if not ok:
        raise Refused("eval-verdict.bad-signature", f"signature {state}: {reason}")
    if body["passed"] != (Decimal(body["score"]) >= Decimal(body["threshold"])):
        raise Refused("eval-verdict.inconsistent", "passed disagrees with score")
    if (body["scorer"] == "llm-judge") != (body["judge_run"] != ""):
        raise Refused("eval-verdict.judge-mismatch", "judge_run does not match the scorer")
    return {"item": body["item"], "passed": body["passed"], "signer": body["signer"]}


def is_eval(path: Path) -> bool:
    return (path.is_dir() and (path / "verdicts.jsonl").is_file()) or path.suffix == ".jsonl"


def verify_eval(path: Path, public_key: bytes | None) -> list[dict[str, Any]]:
    """One check per verdict line, then a summary check over the whole file."""
    source = path / "verdicts.jsonl" if path.is_dir() else path
    checks: list[dict[str, Any]] = []
    evals: set[str] = set()
    items: set[str] = set()
    passed = total = 0
    try:
        lines = [line for line in source.read_text("utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError) as exc:
        return [check("verdicts", "fail", "eval.unreadable", str(exc))]
    for number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
            found = verify(row, public_key)
        except Refused as exc:
            checks.append(check(f"verdict:{number}", "fail", exc.code, str(exc)))
            continue
        except (ValueError, kernel.KernelError) as exc:
            checks.append(check(f"verdict:{number}", "fail", "eval-verdict.malformed", str(exc)))
            continue
        pinned = kernel.canonical_json({name: row[name] for name in PINNED})
        if row["eval"] != "sha256:" + hashlib.sha256(EVAL_DOMAIN + pinned).hexdigest():
            checks.append(check(f"verdict:{number}", "fail", "eval.id-mismatch", "eval id"))
            continue
        if row["item"] in items:
            checks.append(check(f"verdict:{number}", "fail", "eval.duplicate-item", row["item"]))
            continue
        items.add(row["item"])
        evals.add(row["eval"])
        total += 1
        passed += found["passed"]
    basis = "the supplied key" if public_key is not None else "embedded keys (trust on first use)"
    ok = bool(lines) and total == len(lines) and len(evals) == 1
    detail = f"{total}/{len(lines)} verdict(s) verified under {basis}; {passed} passed"
    reason = "eval.verified" if ok else ("eval.mixed-evals" if len(evals) > 1 else "eval.failed")
    return [*checks, check("verdicts", "pass" if ok else "fail", reason, detail, passed=passed)]


__all__ = ["Refused", "is_eval", "verify", "verify_eval"]
