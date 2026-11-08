"""Reference op for SPEC 4.13 (signed redaction report verification)."""

from __future__ import annotations

from typing import Any

from opentine._redact_report import check


def op_redaction_report_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.13: verify one report under the HMAC key or trusted Ed25519 key given."""
    value = inp.value
    hmac, public = value.get("hmac_key_hex"), value.get("public_key")
    return check(
        value["report"],
        hmac_key=bytes.fromhex(hmac) if hmac else None,
        public_key=bytes.fromhex(public) if public else None,
    )


OPS = {"redaction-report.verify": op_redaction_report_verify}
