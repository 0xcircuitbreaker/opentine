"""Reference ops for SPEC 4.14 (tombstones) and 4.15 (redacted public copies)."""

from __future__ import annotations

from typing import Any

from opentine import _redacted_copy, _tombstone


def _keys(value: dict) -> dict[str, Any]:
    hmac, public = value.get("hmac_key_hex"), value.get("public_key")
    return {
        "hmac_key": bytes.fromhex(hmac) if hmac else None,
        "public_key": bytes.fromhex(public) if public else None,
    }


def op_tombstone_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.14: verify one tombstone under the HMAC key or trusted Ed25519 key given."""
    value = inp.value
    return _tombstone.check(value["tombstone"], **_keys(value))


def op_redacted_copy_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.15: verify one redacted-copy record, and its pack digest when given."""
    value = inp.value
    return _redacted_copy.check(value["record"], pack=value.get("pack"), **_keys(value))


def op_tombstone_closure(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.14: walk a run's closure; a tombstoned missing blob is content-unavailable."""
    import base64

    from opentine._tombstone_closure import closure

    value = inp.value
    objects = {row["id"]: base64.b64decode(row["data_b64"]) for row in value["objects"]}
    return closure(value["run"], objects, value["tombstones"])


OPS = {
    "tombstone.closure": op_tombstone_closure,
    "tombstone.verify": op_tombstone_verify,
    "redacted-copy.verify": op_redacted_copy_verify,
}
