"""JSON Schema for ``tine judge VERB --json`` (0.89).

A CLI output, not an object kind: a signed judge outcome is an existing
attestation under the ``opentine.judge-outcome/1`` claim convention and a
validation one under ``opentine.judge-validation/1`` (docs/JUDGES.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, OBJ, STR, closed, doc, opt, strs
from opentine._schema_defs_label import REPORT

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
    _verb("agreement", ["queue", "ok", "advisory", "human", "judges"], {
        **REPORT, "advisory": BOOL}),
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
        "independent (copies of one judge count once); with `--key --out` it writes signed "
        "`opentine.judge-outcome/1` lines. `agreement` recomputes human and judge-vs-human "
        "agreement over a `tine label` queue (judge-vs-consensus Cohen's kappa and multi-rater "
        "Krippendorff's alpha, bootstrap intervals; undefined never passes); `validate` signs a "
        "judge validation (signed adversarial outcomes plus the floor); "
        "`independence` checks judges, monitors and eval items against the candidate's "
        "lineage; `injection` lists candidate outputs aimed at their judge (advisory).",
        {"oneOf": _VERBS}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"judge {name}": "tine-cli-judge-1"
    for name in ("classify", "agreement", "validate", "independence", "injection")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
