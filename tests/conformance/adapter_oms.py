"""Reference op for SPEC 4.26: an OMS model-signature bundle under a pinned P-256 key."""

from __future__ import annotations

from typing import Any

from opentine import _oms


def op_oms_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.26: the bundle, then its manifest against the model's files when given."""
    value = inp.value
    key = value.get("public_key")
    return _oms.check(value["bundle"], value.get("files"), bytes.fromhex(key) if key else None)


OPS = {"oms.verify": op_oms_verify}
