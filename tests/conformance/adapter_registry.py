"""Reference ops for SPEC 4.21 (prompt versions), 4.22 (memory notes), 4.25 (findings)."""

from __future__ import annotations

from typing import Any

from opentine import _memory, _prompt, _review_finding


def _key(value: dict[str, Any]) -> bytes | None:
    key = value.get("public_key")
    return bytes.fromhex(key) if key else None


def op_prompt_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.21: one prompt version, after its predecessor when one is given."""
    value = inp.value
    return _prompt.check(value["record"], previous=value.get("previous"), public_key=_key(value))


def op_memory_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.22: one memory note, under a pinned key or a team when given."""
    value = inp.value
    return _memory.check(value["record"], public_key=_key(value), team=value.get("team") or ())


def op_review_finding_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.25: one review finding, under a pinned key or the Review's reviewers."""
    value = inp.value
    return _review_finding.check(value["record"], public_key=_key(value),
                                 reviewers=value.get("reviewers") or ())  # fmt: skip


OPS = {"prompt.verify": op_prompt_verify, "memory.verify": op_memory_verify,
       "review-finding.verify": op_review_finding_verify}  # fmt: skip
