"""The authored half of a conformance case.

A ``Case`` declares what a rule *is* and what an implementation must *do* with
one input. It never declares an answer: no digest, no oid, no canonical byte
string, no verdict. Those are filled in by ``generate`` from the reference
implementation, and the generator aborts if the observed disposition disagrees
with the ``expect`` declared here. Making opentine accept what it used to reject
therefore requires a human to edit one ``expect=`` in this package, and that
one-line diff is what review has to see.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACCEPT = "accept"
REJECT = "reject"
VERDICT = "verdict"


@dataclass(frozen=True)
class Case:
    id: str
    section: str
    checklist: tuple[int, ...]
    op: str
    profile: str
    expect: str
    intent: str
    input: dict[str, Any]
    args: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    reason_any: tuple[str, ...] | None = None
    tier: str = "core"
    repair_temptation: str | None = None
    twin: str | None = None
    #: Whether this case's ``output`` MUST differ from its ``twin``'s. Set on the
    #: canonicalizer divergence pairs, on their agreement controls, and wherever
    #: else two near-identical inputs must not collapse to one answer.
    must_differ: bool | None = None
    reachable: bool | None = None
    requires: tuple[str, ...] = ()
    spec_note: str | None = None
    forbidden: dict[str, Any] | None = None


def V(value: Any) -> dict[str, Any]:
    """An input spelled as a tagged value tree."""
    return {"value": value}


def B(data: bytes, *, store: str | None = None) -> dict[str, Any]:
    """An input spelled as bytes; ``store`` forces a side file (``blob``/``frame``)."""
    return {"bytes": data, "store": store}


def P(path: str) -> dict[str, Any]:
    """An input spelled as a repository-relative path.

    The only spelling that reaches outside ``docs/conformance/``, and it exists
    for exactly one family: SPEC 5.1's read guarantee is backed by the golden
    fixtures under ``tests/fixtures/compat/``, whose bytes ARE the evidence.
    Copying them into the suite would create a second set that can drift from
    them, so the compat family points at them and pins their SHA-256 instead.
    """
    return {"path": path}


def G(recipe: dict[str, Any]) -> dict[str, Any]:
    """An input spelled as one of the three closed generation recipes."""
    return {"gen": recipe}


@dataclass(frozen=True)
class Family:
    """One vector file: a section, a name, and its authored cases."""

    filename: str
    section: str
    name: str
    cases: tuple[Case, ...]
