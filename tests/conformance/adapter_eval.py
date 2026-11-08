"""Reference op for SPEC 4.12 (``tine-eval-verdict/1`` verification)."""

from __future__ import annotations

from typing import Any

from opentine._eval_verdict import verify


def op_eval_verdict_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.12: verify one verdict, under a trusted key when one is given."""
    value = inp.value
    key = value.get("public_key")
    found = verify(value["verdict"], public_key=bytes.fromhex(key) if key else None)
    return {"item": found["item"], "passed": found["passed"], "signer": found["signer"]}


OPS = {"eval-verdict.verify": op_eval_verdict_verify}
