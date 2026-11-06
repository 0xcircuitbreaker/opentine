"""A ``tine-verify-report/2`` as evidence: signed, timestamped, checked offline (X22).

``tine verify RUN --offline --report PATH --sign-key KEY`` writes the report as
canonical JSON with a ``signature`` member: an Ed25519 ``tine-sig/3`` block
(``_signed_doc``) over ``opentine.verify-report.v2:`` + JCS of every member
except ``signature`` and ``signature_timestamps``. Any edit to a check, the
verdict or the path breaks it.

A report can carry RFC 3161 tokens in ``signature_timestamps`` (``{"bound",
"token"}``, base64 DER), each over ``sig:sha256:<hex>`` of that signature block
(X20), so a token's genTime is when the report, verdict included, already
existed. They sit outside the signed bytes because a token can only be minted
once the signature exists. ``tine verify-report data PATH`` prints the bytes a
TSA query must cover and ``tine verify-report attach PATH TOKEN.tsr`` stores
the response; opentine never contacts a TSA.

:func:`check` verifies all of it with no network. A ``/1`` report, or an
unsigned ``/2`` one, is read and summarised but is not evidence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine._timestamp_sidecar import signature_bound
from opentine._verify_report import SCHEMA, SCHEMA_V1
from opentine.kernel import canonical_json

DOMAIN = b"opentine.verify-report.v2:"
UNSIGNED = ("signature", "signature_timestamps")
MAX_BYTES = 4 * 1024 * 1024
MAX_TOKENS = 16


def body(doc: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in doc.items() if key not in UNSIGNED}


def dumps(doc: dict[str, Any]) -> bytes:
    return canonical_json(doc) + b"\n"


def load(path: str | Path) -> dict[str, Any]:
    """The report at *path*; ``ValueError`` when it is not a verify report."""
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{Path(path).name} exceeds {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw)
    except (RecursionError, ValueError):
        raise ValueError(f"{Path(path).name} is not JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") not in (SCHEMA, SCHEMA_V1):
        raise ValueError(f"{Path(path).name} is not a {SCHEMA} or {SCHEMA_V1} document")
    return doc


def sign_report(doc: dict[str, Any], private_key: Any, signer: str | None = None) -> dict[str, Any]:
    if doc.get("schema") != SCHEMA:
        raise ValueError(f"only a {SCHEMA} report can be signed")
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    block = _signed_doc.sign(DOMAIN, body(doc), private_key, signer=signer, signed_at=now)
    return {**body(doc), "signature": block}


def bound(doc: dict[str, Any]) -> str:
    """The ``sig:sha256:`` bytes a timestamp token over the report must cover."""
    if not isinstance(doc.get("signature"), dict):
        raise ValueError("the report is not signed; sign it with --sign-key first")
    return signature_bound(doc["signature"])


def attach(doc: dict[str, Any], token: bytes) -> dict[str, Any]:
    """*doc* with *token* added; ``ValueError`` when it does not cover the signature."""
    from opentine._tsp import HASHES, parse

    target = bound(doc)
    parsed = parse(token)
    if parsed.hash_oid not in HASHES:
        raise ValueError(f"unsupported imprint hash {parsed.hash_oid}")
    if hashlib.new(parsed.hash_name, target.encode("utf-8")).digest() != parsed.imprint:
        raise ValueError(f"the token does not cover {target}; see `tine verify-report data`")
    stamps = list(doc.get("signature_timestamps") or [])
    entry = {"bound": target, "token": base64.b64encode(token).decode("ascii")}
    if entry not in stamps:
        stamps.append(entry)
    if len(stamps) > MAX_TOKENS:
        raise ValueError(f"a report holds at most {MAX_TOKENS} timestamp tokens")
    return {**doc, "signature_timestamps": stamps}


def _tokens(doc: dict[str, Any], args: Any, target: str | None) -> list[dict[str, Any]]:
    from opentine._tsp_verify import verify_token
    from opentine._verify_timestamp import _roots

    stamps = doc.get("signature_timestamps") or []
    if not stamps:
        return []
    roots, windowed, _basis = _roots(args)
    out = []
    for entry in stamps if isinstance(stamps, list) else [None]:
        try:
            stored, raw = entry["bound"], base64.b64decode(entry["token"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error):
            out.append({"outcome": "fail", "reason": "timestamp.malformed"})
            continue
        if stored != target:
            out.append({"bound": stored, "outcome": "fail", "reason": "timestamp.bound-mismatch"})
            continue
        verdict = verify_token(raw, stored.encode("utf-8"), roots, windowed)
        outcome = "pass" if verdict.ok else "fail"
        if verdict.no_roots:
            outcome = "unavailable-offline"
        out.append({"bound": stored, "outcome": outcome, "reason": verdict.reason, **verdict.info})
    return out


def check(doc: dict[str, Any], args: Any, public_key: Any | None = None) -> dict[str, Any]:
    """The offline verdict on a report document (see the module docstring)."""
    result: dict[str, Any] = {
        "schema": doc.get("schema"),
        "report_verdict": doc.get("verdict"),
        "path": doc.get("path"),
        "signed": "signature" in doc,
        "signature": None,
        "timestamps": [],
        "signing_time": None,
    }
    if doc.get("schema") == SCHEMA_V1 or "signature" not in doc:
        result["evidence"] = False
        result["ok"] = False
        result["reason"] = "report.unsigned"
        return result
    verdict = _signed_doc.verify(DOMAIN, body(doc), doc["signature"], public_key=public_key)
    result["signature"] = {
        "ok": verdict.ok,
        "state": verdict.state,
        "reason": verdict.reason,
        "signer": verdict.signer,
        "signed_at": verdict.signed_at,
        "trust_basis": _signed_doc.basis(doc["signature"], public_key),
    }
    target = bound(doc) if verdict.ok else None
    stamps = _tokens(doc, args, target)
    result["timestamps"] = stamps
    passed = [s["gen_time"] for s in stamps if s["outcome"] == "pass" and s.get("gen_time")]
    result["signing_time"] = min(passed) if passed else None
    failed = any(s["outcome"] == "fail" for s in stamps)
    result["evidence"] = verdict.ok
    result["ok"] = verdict.ok and not failed
    result["reason"] = (
        "report.verified"
        if result["ok"]
        else ("report.signature-invalid" if not verdict.ok else "report.timestamp-failed")
    )
    return result


__all__ = ["DOMAIN", "attach", "bound", "check", "dumps", "load", "sign_report"]
