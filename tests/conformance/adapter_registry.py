"""Reference ops for SPEC 4.19 (prompt versions) and 4.20 (memory notes)."""

from __future__ import annotations

from typing import Any

from opentine import _memory, _prompt


def _key(value: dict[str, Any]) -> bytes | None:
    key = value.get("public_key")
    return bytes.fromhex(key) if key else None


def op_prompt_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: one prompt version, after its predecessor when one is given."""
    value = inp.value
    return _prompt.check(value["record"], previous=value.get("previous"), public_key=_key(value))


def op_memory_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.20: one memory note, under a pinned key or a team when given."""
    value = inp.value
    return _memory.check(value["record"], public_key=_key(value), team=value.get("team") or ())


OPS = {"prompt.verify": op_prompt_verify, "memory.verify": op_memory_verify}
