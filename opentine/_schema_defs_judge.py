"""JSON Schema for ``tine judge VERB --json`` (0.89).

A CLI output, not an object kind: a human label is an existing attestation under
the ``opentine.rubric-label/1`` claim convention and a validation one under
``opentine.judge-validation/1`` (docs/JUDGES.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, OBJ, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-judge/1"}}
_DEC = {"type": "string", "pattern": "^-?[0-9]+(\\.[0-9]+)?$"}
_OUTCOME = {"type": "object", "required": ["status", "label", "probability"], "properties": {
    "status": {"enum": ["label", "abstain", "error"]}, "label": opt(STR),
    "probability": opt(_DEC), "reason": STR, "judge_run": STR, "votes": INT,
    "groups": INT}}  # fmt: skip
_FINDING = {"type": "object", "required": ["code"], "properties": {
    "code": {"type": "string", "pattern": "^(fail|advisory):[a-z.-]+$"}, "detail": STR,
    "id": STR, "item": opt(STR), "kind": STR, "match": STR}}  # fmt: skip
_IND = closed(["groups", "independent", "links", "findings"], {
    "groups": {"type": "array", "items": {"type": "array", "items": INT}},
    "independent": INT, "findings": {"type": "array", "items": _FINDING},
    "links": {"type": "array", "items": closed(["members", "because"], {
        "members": {"type": "array", "items": INT}, "because": strs()})}})  # fmt: skip
_MEMBER = closed(["pin", "model", "prompt_digest", "lineage"], {
    "pin": STR, "model": STR, "prompt_digest": FPR, "lineage": opt(STR)})  # fmt: skip
_AGREE = {"type": "object", "required": ["method", "value", "ci", "floor", "meets_floor",
                                         "coverage", "counted", "labelled"], "properties": {
    "method": {"enum": ["cohen-kappa", "fleiss-kappa", "krippendorff-alpha"]},
    "value": opt(_DEC), "ci": {"type": "array", "items": opt(_DEC)}, "floor": _DEC,
    "meets_floor": BOOL, "coverage": _DEC, "counted": INT, "labelled": INT,
    "reasons": strs(), "unassigned_labels": INT,
    "judge_vs_consensus": closed(["method", "value", "ci", "items"], {
        "method": {"const": "cohen-kappa"}, "value": opt(_DEC),
        "ci": {"type": "array", "items": opt(_DEC)}, "items": INT})}}  # fmt: skip


def _verb(name: str, required: list[str], props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "required": ["command", "schema", *required], "properties": {
        **_HEAD, "command": {"const": f"judge {name}"}, **props}}  # fmt: skip


_VERBS = [
    _verb("classify", ["labels", "members", "independence", "rows", "advisories", "counts"], {
        "labels": strs(), "aggregate": STR, "members": {"type": "array", "items": _MEMBER},
        "independence": _IND, "advisories": {"type": "array", "items": _FINDING},
        "counts": {"type": "object", "additionalProperties": INT},
        "rows": {"type": "array", "items": closed(["item", "outcome", "members"], {
            "item": STR, "outcome": _OUTCOME,
            "members": {"type": "array", "items": _OUTCOME}})}}),
    _verb("label", ["record", "claim"], {"record": STR, "claim": OBJ}),
    _verb("queue", ["rubric", "reviewers", "pinned"], {
        "rubric": FPR, "pinned": BOOL, "why": opt(STR), "short": strs(),
        "reviewers": {"type": "object", "additionalProperties": closed(
            ["assigned", "pending"], {"assigned": strs(), "pending": strs()})},
        "unassigned_labels": {"type": "array", "items": OBJ},
        "conflicts": {"type": "array", "items": OBJ}, "ignored": {"type": "array", "items": OBJ}}),
    _verb("agreement", ["rubric", "agreement", "advisory"], {
        "rubric": FPR, "agreement": _AGREE, "advisory": BOOL}),
    _verb("validate", ["record", "claim"], {"record": STR, "claim": OBJ}),
    _verb("independence", ["candidate", "family", "rows", "findings"], {
        "candidate": STR, "family": closed(["variants", "runs"], {"variants": strs(),
                                                                  "runs": strs()}),
        "rows": {"type": "array", "items": {"type": "object", "required": [
            "kind", "id", "independent", "because"], "properties": {
            "kind": {"enum": ["judge", "monitor", "item"]}, "id": opt(STR),
            "independent": BOOL, "because": strs()}}},
        "findings": {"type": "array", "items": _FINDING}}),
    _verb("injection", ["findings", "advisory"], {
        "findings": {"type": "array", "items": _FINDING}, "advisory": BOOL}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-judge-1": doc("tine-cli-judge-1", "tine judge VERB --json",
        "Judge assurance (0.89). `classify` runs label judges (label, probability, explicit "
        "abstain; a parse failure is an error, never a 0) and ensembles whose members must be "
        "independent (copies of one judge count once). `label` signs one human rubric label "
        "with a pinned reviewer key; `queue` lists each reviewer's assigned and pending items; "
        "`agreement` reports judge-vs-human agreement with a bootstrap interval and floor; "
        "`validate` signs a judge or monitor validation (adversarial cases plus the floor); "
        "`independence` checks judges, monitors and eval items against the candidate's "
        "lineage; `injection` lists candidate outputs aimed at their judge (advisory).",
        {"oneOf": _VERBS}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"judge {name}": "tine-cli-judge-1"
    for name in ("classify", "label", "queue", "agreement", "validate", "independence", "injection")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
