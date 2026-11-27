"""Evaluator invariant contracts (0.85): ``tine eval run --contract FILE``.

A contract (``opentine.scorer-contract/1``, a JSON file) states what must hold
of a scorer however it scores, so a broken evaluator fails as such instead of
reporting an inflated score::

    {"convention": "opentine.scorer-contract/1",
     "deterministic": true,                         # scored twice, the same scores
     "anchors": [{"item": {...}, "output": ..., "score": 0.5}],   # known answers
     "output_schema": {...},                        # what every output must look like
     "output_length": {"min": 0, "max": 100000},    # len() of every output
     "length_relation": {"field": "expected", "relation": "eq"}}  # len(output) vs item

Every key but ``convention`` is optional. A violation refuses the eval with
``scorer.contract`` and nothing is signed. Under ``--isolate`` the contract's
digest is in ``scorer.json`` and so inside the signed ``scorer_version``.
A timing floor is not part of the contract: it would depend on the machine.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from opentine._eval_scorers import Scorer, ScorerError, conforms

CONVENTION = "opentine.scorer-contract/1"
KEYS = {"convention", "deterministic", "anchors", "output_schema", "output_length",
        "length_relation"}  # fmt: skip
RELATIONS = {"eq": lambda a, b: a == b, "le": lambda a, b: a <= b, "ge": lambda a, b: a >= b}
MAX_ANCHORS = 1000


def load(path: Path) -> tuple[dict[str, Any], str]:
    """The checked contract and ``sha256:`` of its bytes."""
    from opentine._json_shallow import loads

    raw = Path(path).read_bytes()
    doc = loads(raw)
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION or set(doc) - KEYS:
        raise ScorerError(f"{path}: a contract is an opentine.scorer-contract/1 object of "
                          + ", ".join(sorted(KEYS)))  # fmt: skip
    anchors = doc.get("anchors", [])
    if not isinstance(anchors, list) or len(anchors) > MAX_ANCHORS or not all(
        isinstance(a, dict) and set(a) == {"item", "output", "score"}
        and isinstance(a["item"], dict) and isinstance(a["score"], int | float)
        and not isinstance(a["score"], bool) for a in anchors
    ):  # fmt: skip
        raise ScorerError(f"{path}: anchors is a list of {{item, output, score}}")
    bounds = doc.get("output_length", {})
    if not isinstance(bounds, dict) or set(bounds) - {"min", "max"} or not all(
        isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in bounds.values()
    ):  # fmt: skip
        raise ScorerError(f"{path}: output_length is {{min, max}} non-negative integers")
    relation = doc.get("length_relation")
    if relation is not None and not (
        isinstance(relation, dict) and set(relation) == {"field", "relation"}
        and isinstance(relation["field"], str) and relation["relation"] in RELATIONS
    ):  # fmt: skip
        raise ScorerError(f"{path}: length_relation is {{field, relation: eq|le|ge}}")
    if not isinstance(doc.get("deterministic", False), bool):
        raise ScorerError(f"{path}: deterministic is true or false")
    return doc, "sha256:" + hashlib.sha256(raw).hexdigest()


def _length(value: Any) -> int | None:
    return len(value) if isinstance(value, str | list | dict) else None


def _shape(contract: dict[str, Any], item: dict[str, Any], output: Any) -> str | None:
    name = item.get("id")
    if "output_schema" in contract and not conforms(output, contract["output_schema"]):
        return f"item {name!r}: the output does not have the contracted shape"
    size = _length(output)
    bounds = contract.get("output_length", {})
    if bounds and (size is None or not bounds.get("min", 0) <= size <= bounds.get("max", size)):
        return f"item {name!r}: output length {size} is outside {bounds}"
    relation = contract.get("length_relation")
    if relation is not None:
        other = _length(item.get(relation["field"]))
        if size is None or other is None or not RELATIONS[relation["relation"]](size, other):
            return (f"item {name!r}: len(output) {size} is not {relation['relation']} "
                    f"len({relation['field']}) {other}")  # fmt: skip
    return None


def bind(scorer: Scorer, contract: dict[str, Any], digest: str) -> Scorer:
    """*scorer* scoring in one batch that refuses with ``scorer.contract`` on a violation."""
    from opentine._scorer_isolated import ScorerRefused

    inner = scorer.batch
    scorer.config["contract"] = digest
    anchors = contract.get("anchors", [])

    def score_all(pairs: list[tuple[dict[str, Any], Any]]) -> list[float]:
        if inner is not None:
            return inner(pairs)
        return [scorer.func(item, output)[0] for item, output in pairs]

    def batch(pairs: list[tuple[dict[str, Any], Any]]) -> list[float]:
        for item, output in pairs:
            problem = _shape(contract, item, output)
            if problem:
                raise ScorerRefused("scorer.contract", problem)
        every = list(pairs) + [(a["item"], a["output"]) for a in anchors]
        first = score_all(every)
        if contract.get("deterministic") and score_all(every) != first:
            raise ScorerRefused("scorer.contract", "scored twice, the scores differ")
        for number, anchor in enumerate(anchors):
            got = first[len(pairs) + number]
            if abs(got - float(anchor["score"])) > 1e-9:
                raise ScorerRefused("scorer.contract",
                                    f"anchor {number} scored {got}, the contract says "
                                    f"{anchor['score']}")  # fmt: skip
        return first[: len(pairs)]

    scorer.batch = batch
    return scorer


__all__ = ["CONVENTION", "bind", "load"]
