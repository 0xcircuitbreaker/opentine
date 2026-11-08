"""Verifying a signed redaction report: ``tine redact verify REPORT`` (0.45.1).

:func:`check` is the reference for the ``redaction-report.verify`` conformance
op (``docs/conformance/vectors/59-redaction-report.json``) and is ported to the
pyz (``opentine._pyz._redactr``) and the TS verifier (``src/redactreport.ts``).
A report is exactly the fields :func:`opentine._push_gate.run_report` writes plus
a ``tine-sig/3`` block; ``clean`` must equal "no findings" even when signed.

Keys: an HMAC report needs ``hmac_key``. An Ed25519 report verifies under the
supplied ``public_key`` (whose bytes must be the embedded key) or, given none,
under its embedded key (trust on first use, reported as ``verified-tofu``).
Every refusal is a :class:`ReportError` with a ``redaction-report.*`` code.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._push_gate import DOMAIN_PREFIX, REPORT_KIND
from opentine._signing_v4 import SCHEME_V3
from opentine._signing_verify import HEADER_KEYS, verify_block
from opentine.kernel import canonical_json

FIELDS = ("kind", "report_version", "ruleset", "run", "objects", "findings", "clean")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ReportError(ValueError):
    """A refusal; ``code`` is the conformance reason (``redaction-report.*``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _malformed(message: str) -> ReportError:
    return ReportError("redaction-report.malformed", f"redaction report is malformed: {message}")


def body(report: Any) -> dict[str, Any]:
    """The signed body of *report*, after the field rules."""
    if not isinstance(report, dict) or report.get("kind") != REPORT_KIND:
        raise _malformed(f"kind is not {REPORT_KIND}")
    if set(report) - {*FIELDS, "signature"} or set(FIELDS) - set(report):
        raise _malformed("a report has exactly the redaction report fields")
    out = {name: report[name] for name in FIELDS}
    if out["report_version"] != 1 or isinstance(out["report_version"], bool):
        raise _malformed("report_version must be 1")
    for name in ("ruleset", "run"):
        if not isinstance(out[name], str) or not _NAME.fullmatch(out[name]):
            raise _malformed(f"{name} must be a name")
    objects = out["objects"]
    if isinstance(objects, bool) or not isinstance(objects, int) or not 0 <= objects < 2**53:
        raise _malformed("objects must be a count")
    findings = out["findings"]
    if not isinstance(findings, list) or len(findings) > objects:
        raise _malformed("findings must be a list no longer than objects")
    for hit in findings:
        if not (isinstance(hit, dict) and set(hit) == {"oid", "kind"}) or not all(
            isinstance(hit[k], str) and _NAME.fullmatch(hit[k]) for k in ("oid", "kind")
        ):
            raise _malformed("each finding is {oid, kind}")
    if not isinstance(out["clean"], bool):
        raise _malformed("clean must be a boolean")
    return out


def check(
    report: Any, *, hmac_key: bytes | None = None, public_key: bytes | None = None
) -> dict[str, Any]:
    """``{run, clean, objects, findings, state}`` for a good report; :class:`ReportError` else."""
    found = body(report)
    block = report.get("signature")
    if block is None:
        raise ReportError("redaction-report.unsigned", "the redaction report is unsigned")
    if not isinstance(block, dict):
        raise ReportError("redaction-report.bad-signature", "the report signature is not a block")
    algorithm = block.get("alg")
    if algorithm == "hmac-sha256" and hmac_key is None:
        raise ReportError("redaction-report.no-key", "no key for an hmac-sha256 report")
    if hmac_key is not None and algorithm != "hmac-sha256":
        raise ReportError("redaction-report.wrong-key", "not the trusted key's algorithm")
    if public_key is not None:
        if algorithm != "ed25519":
            raise ReportError("redaction-report.wrong-key", "not the trusted key's algorithm")
        if block.get("public_key") != bytes(public_key).hex():
            raise ReportError(
                "redaction-report.wrong-key", "signed by a key other than the trusted key"
            )
    keys: dict[str, Any] = {}
    if algorithm == "hmac-sha256":
        keys["hmac_key"] = hmac_key
    elif public_key is not None:
        keys["public_key"] = bytes(public_key)
    else:
        keys["trust_embedded"] = True

    def message(header: dict[str, Any]) -> bytes:
        view = {"body": found, "header": {key: header.get(key) for key in HEADER_KEYS}}
        return DOMAIN_PREFIX + canonical_json(view)

    result = verify_block(block, message, schemes=(SCHEME_V3,), subject="redaction report", **keys)
    if not result.ok:
        raise ReportError(
            "redaction-report.bad-signature",
            f"the report signature does not hold ({result.state}: {result.reason})",
        )
    if found["clean"] != (not found["findings"]):
        raise ReportError("redaction-report.inconsistent", "clean disagrees with the findings")
    return {
        "run": found["run"],
        "clean": found["clean"],
        "objects": found["objects"],
        "findings": len(found["findings"]),
        "state": result.state,
    }


__all__ = ["FIELDS", "ReportError", "body", "check"]
