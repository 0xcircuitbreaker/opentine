"""Reference op for SPEC 8.12.1 (an RFC 3161 token bound to a Rekor v2 keyless signature)."""

from __future__ import annotations

from typing import Any

from opentine._keyless_tsa import bind_request


def op_keyless_signing_time(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 8.12.1: the verified signing time, ``unchecked`` without a token; refuse else."""
    return bind_request(inp.value)


OPS = {"keyless.signing-time": op_keyless_signing_time}
