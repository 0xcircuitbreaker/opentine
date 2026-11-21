"""JSON Schema for ``tine sign --keyless --json`` and ``tine keyless verify --json`` (0.74).

The evidence itself is the existing Sigstore bundle v0.3 (docs/KEYLESS.md): no
new object kind. Codes are command-level (``keyless.trusted``,
``caveat:keyless-*``, ``fail:keyless-*``), never ``tine verify`` codes.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-keyless/1"}}
TIERS = {"enum": ["keyless-workflow", "keyless-person", "keyless-unbound"]}
_CAVEATS = ["caveat:keyless-unpinned", "caveat:keyless-outside-window"]
_FAILS = ["malformed", "not-keyless", "receipt", "signature", "chain", "subject"]
CODES = {"enum": ["keyless.trusted", *_CAVEATS, *(f"fail:keyless-{f}" for f in _FAILS)]}
_FIELDS = ["issuer", "build_signer_uri", "build_signer_digest", "runner_environment",
           "source_repository_uri", "source_repository_digest", "source_repository_ref",
           "build_trigger"]  # fmt: skip
IDENTITY = closed(["san", "san_email", "san_uri", *_FIELDS], {
    "san": strs(), "san_email": strs(), "san_uri": strs(),
    **{name: opt(STR) for name in _FIELDS}})  # fmt: skip
_SUBJECT = {"type": "object", "required": ["name", "digest"]}
_VERIFY = closed(["command", "schema", "bundle", "outcome", "code", "reason", "trusted"], {
    **_HEAD, "command": {"const": "keyless verify"}, "bundle": STR,
    "outcome": {"enum": ["pass", "caveat", "fail"]}, "code": CODES, "reason": STR,
    "trusted": BOOL, "identity": IDENTITY, "assurance_tier": TIERS, "integrated_time": STR,
    "log_index": INT, "not_before": STR, "not_after": STR, "subject": _SUBJECT})  # fmt: skip
_SIGN = closed(["command", "schema", "mode", "run", "bundle", "log_index"], {
    **_HEAD, "command": {"const": "sign"}, "mode": {"const": "keyless"}, "run": STR,
    "bundle": STR, "log_index": {"type": "integer"}})  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-keyless-1": doc("tine-cli-keyless-1", "tine sign --keyless / tine keyless verify",
        "Keyless signing and offline verification. A keyless identity is trusted only "
        "when an owner-pinned trust bundle names its issuer and exact identity; "
        "`assurance_tier` describes the identity and never grants trust.",
        {"anyOf": [_SIGN, _VERIFY]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {"keyless verify": "tine-cli-keyless-1"}

__all__ = ["CODES", "COMMAND_SCHEMAS", "IDENTITY", "SCHEMAS", "TIERS"]
