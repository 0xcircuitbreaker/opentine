"""Reference op for SPEC 8.14: a remote's signed SLSA VSA, as a verdict."""

from __future__ import annotations

from typing import Any

from opentine import _vsa_verify


def op_vsa_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    return _vsa_verify.verify_case(inp.value)


OPS = {"vsa.verify": op_vsa_verify}
