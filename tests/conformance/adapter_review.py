"""Reference ops for SPEC 4.19 (Reviews, gate decisions and the review bundle)."""

from __future__ import annotations

from typing import Any

from opentine import _review


def op_review_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: one review version, after its predecessor when one is given."""
    value = inp.value
    return _review.check(
        value["version"], previous=value.get("previous"), reviewer_key=value.get("reviewer_key")
    )


def op_review_gate_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: one gate decision on the version it names."""
    value = inp.value
    return _review.check_gate(value["decision"], value["version"])


def op_review_bundle(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: a whole review bundle, every version and every decision."""
    value = inp.value
    return _review.verify_bundle(value["bundle"], reviewer_key=value.get("reviewer_key"))


OPS = {
    "review.verify": op_review_verify,
    "review-gate.verify": op_review_gate_verify,
    "review.bundle": op_review_bundle,
}
