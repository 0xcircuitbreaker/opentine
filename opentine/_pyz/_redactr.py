"""Signed redaction reports, checked with the standard library alone (0.45.1).

An independent port of ``opentine._redact_report.check`` for ``tine-verify.pyz``
(SPEC 4.13): exactly the report fields, a ``tine-sig/3`` block over
``opentine.redaction-report.v1:`` + JCS of ``{"body": ..., "header": ...}``
(HMAC-SHA256, or Ed25519 under ``--pubkey`` or, without one, the embedded key:
trust on first use), and ``clean`` must equal "no findings". Reason codes are
the conformance suite's ``redaction-report.*``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import kernel
from . import _sig
from ._artifact import check as row

KIND = "opentine.redaction-report"
DOMAIN = b"opentine.redaction-report.v1:"
FIELDS = ("kind", "report_version", "ruleset", "run", "objects", "findings", "clean")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")


class Refused(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> Refused:
    return Refused("redaction-report.malformed", f"redaction report is malformed: {message}")


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _body(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or report.get("kind") != KIND:
        raise _malformed(f"kind is not {KIND}")
    if set(report) - {*FIELDS, "signature"} or set(FIELDS) - set(report):
        raise _malformed("a report has exactly the redaction report fields")
    body = {name: report[name] for name in FIELDS}
    if not _count(body["report_version"]) or body["report_version"] != 1:
        raise _malformed("report_version must be 1")
    for name in ("ruleset", "run"):
        if not isinstance(body[name], str) or not _NAME.fullmatch(body[name]):
            raise _malformed(f"{name} must be a name")
    if not _count(body["objects"]):
        raise _malformed("objects must be a count")
    findings = body["findings"]
    if not isinstance(findings, list) or len(findings) > body["objects"]:
        raise _malformed("findings must be a list no longer than objects")
    for hit in findings:
        if not (isinstance(hit, dict) and set(hit) == {"oid", "kind"}) or not all(
            isinstance(hit[k], str) and _NAME.fullmatch(hit[k]) for k in ("oid", "kind")
        ):
            raise _malformed("each finding is {oid, kind}")
    if not isinstance(body["clean"], bool):
        raise _malformed("clean must be a boolean")
    return body


def verify(
    report: Any, *, hmac_key: bytes | None = None, public_key: bytes | None = None
) -> dict[str, Any]:
    """``{run, clean, objects, findings, state}``; :class:`Refused` otherwise."""
    body = _body(report)
    block = report.get("signature")
    if block is None:
        raise Refused("redaction-report.unsigned", "the redaction report is unsigned")
    if not isinstance(block, dict):
        raise Refused("redaction-report.bad-signature", "the report signature is not a block")
    algorithm = block.get("alg")
    if algorithm == "hmac-sha256" and hmac_key is None:
        raise Refused("redaction-report.no-key", "no key for an hmac-sha256 report")
    state = "verified"
    if public_key is not None:
        if algorithm != "ed25519" or block.get("public_key") != bytes(public_key).hex():
            raise Refused(
                "redaction-report.wrong-key", "signed by a key other than the trusted key"
            )
    elif algorithm == "ed25519":
        raw = block.get("public_key")
        public_key = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b"\0" * 32
        state = "verified-tofu"

    def message(header: dict[str, Any]) -> bytes:
        return DOMAIN + kernel.canonical_json({"body": body, "header": header})

    ok, found, reason = _sig.verify_block(
        block,
        message,
        ("tine-sig/3",),
        hmac_key=hmac_key if algorithm == "hmac-sha256" else None,
        public_key=public_key if algorithm != "hmac-sha256" else None,
    )
    if not ok:
        raise Refused(
            "redaction-report.bad-signature",
            f"the report signature does not hold ({found}: {reason})",
        )
    if body["clean"] != (not body["findings"]):
        raise Refused("redaction-report.inconsistent", "clean disagrees with the findings")
    return {
        "run": body["run"],
        "clean": body["clean"],
        "objects": body["objects"],
        "findings": len(body["findings"]),
        "state": state,
    }


def is_report(path: Path) -> bool:
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 64 << 20:
        return False
    try:
        return json.loads(path.read_text("utf-8")).get("kind") == KIND
    except (OSError, ValueError, AttributeError, RecursionError):
        return False


def verify_report(path: Path, hmac_key: bytes | None, public_key: bytes | None) -> list:
    """One ``redaction-report`` check for the report file at *path*."""
    try:
        found = verify(
            json.loads(path.read_text("utf-8")), hmac_key=hmac_key, public_key=public_key
        )
    except Refused as exc:
        return [row("redaction-report", "fail", exc.code, str(exc))]
    detail = f"{found['run']}: {found['findings']} finding(s) in {found['objects']} object(s)"
    return [row("redaction-report", "pass", "redaction-report.verified", detail, **found)]


__all__ = ["KIND", "Refused", "is_report", "verify", "verify_report"]
