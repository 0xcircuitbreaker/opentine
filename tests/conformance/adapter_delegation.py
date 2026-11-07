"""Reference op for SPEC 4.10 (``opentine-delegation/1`` chain verification)."""

from __future__ import annotations

from typing import Any

from opentine._delegation_verify import verify_chain


def op_delegation_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.10: verify a chain for a signer, time, agent and tools; refuse otherwise."""
    value = inp.value
    result = verify_chain(
        value["chain"],
        signer=value["signer"],
        at=value["at"],
        agent=value.get("agent"),
        actions=list(value.get("actions") or ()),
    )
    return {"root": result["root"], "links": result["links"]}


OPS = {"delegation.verify": op_delegation_verify}
