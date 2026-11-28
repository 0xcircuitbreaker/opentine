"""JSON Schema for ``tine label VERB --json`` (0.89): rubric label queues.

A CLI output, not an object kind: queue entries are existing attestations under
the ``opentine.label-*/1`` claim conventions (docs/JUDGES.md). The agreement
report shapes (``REPORT``) are shared with ``tine judge agreement``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, opt

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_DEC = opt({"type": "string", "pattern": "^-?[0-9]+\\.[0-9]{6}$"})
_HEAD = {"schema": {"const": "tine-cli-label/1"}, "queue": STR}
_JUDGE = {"type": "string", "pattern": "^jp1\\+sha256:[0-9a-f]{64}$"}
_RUBRIC = closed(["name", "labels", "instructions"], {
    "name": STR, "labels": {"type": "array", "items": STR}, "instructions": STR})  # fmt: skip
_STAT = closed(["value", "reason", "lower", "upper", "undefined_resamples"], {
    "value": _DEC, "reason": opt(STR), "lower": _DEC, "upper": _DEC,
    "undefined_resamples": opt(INT)})  # fmt: skip
_SETTINGS = closed(["floor", "alpha", "seed", "resamples", "min_items", "min_coverage"], {
    "floor": STR, "alpha": STR, "seed": INT, "resamples": INT, "min_items": INT,
    "min_coverage": STR})  # fmt: skip
_HUMAN = closed(["items", "pairable", "reviewers", "krippendorff", "fleiss", "cohen", "primary",
                 "floor_ok"], {
    "items": INT, "pairable": INT, "reviewers": INT, "krippendorff": _STAT, "fleiss": _STAT,
    "cohen": _STAT, "primary": {"enum": ["cohen", "krippendorff"]}, "floor_ok": BOOL})  # fmt: skip
_JUDGE_ROW = closed(["judge", "outputs_sha256", "reveal_seq", "consensus_items", "ties",
                                      "compared", "abstained", "errors", "missing", "coverage",
                     "judge_vs_consensus", "multi_rater", "floor", "floor_ok", "reasons"], {
    "judge": _JUDGE, "outputs_sha256": _HEX, "reveal_seq": INT, "consensus_items": INT,
    "ties": INT, "compared": INT, "abstained": INT, "errors": INT, "missing": INT,
    "coverage": _DEC, "judge_vs_consensus": _STAT, "multi_rater": _STAT, "floor": STR,
    "floor_ok": BOOL,
    "reasons": {"type": "array", "items": STR}})  # fmt: skip


#: The agreement report of a queue (``tine judge agreement``), as properties.
REPORT = {"queue": STR, "ok": BOOL, "queue_sha256": _HEX, "rubric_sha256": _HEX,
          "entries": INT, "settings": _SETTINGS, "human": _HUMAN,
          "judges": {"type": "array", "items": _JUDGE_ROW}}  # fmt: skip
JUDGE_ROW = _JUDGE_ROW


def _verb(name: str, required: list[str], props: dict[str, Any]) -> dict[str, Any]:
    return closed(["command", "schema", "queue", *required], {
        **_HEAD, "command": {"const": f"label {name}"}, **props})  # fmt: skip


_VERBS = [
    _verb("init", ["queue_sha256", "rubric_sha256", "rubric"],
          {"queue_sha256": _HEX, "rubric_sha256": _HEX, "rubric": _RUBRIC}),
    _verb("assign", ["assigned", "skipped", "items"],
          {"assigned": INT, "skipped": INT, "items": INT}),
    _verb("reassign", ["item_sha256", "from", "to", "seq"],
          {"item_sha256": _HEX, "from": FPR, "to": FPR, "seq": INT}),
    _verb("submit", ["item_sha256", "label", "reviewer", "rubric_sha256", "seq"],
          {"item_sha256": _HEX, "label": STR, "reviewer": FPR, "rubric_sha256": _HEX,
           "seq": INT}),
    _verb("reveal", ["judge", "outputs_sha256", "seq"],
          {"judge": _JUDGE, "outputs_sha256": _HEX, "seq": INT}),
    _verb("next", ["reviewer", "rubric", "rubric_sha256", "pending"],
          {"reviewer": FPR, "rubric": _RUBRIC, "rubric_sha256": _HEX,
           "pending": {"type": "array", "items": closed(["item_sha256", "item"], {
               "item_sha256": _HEX, "item": {}})}}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-label-1": doc("tine-cli-label-1", "tine label VERB --json",
        "Rubric label queues (0.89). `init` starts a queue with a rubric pinned by digest; "
        "`assign` and `reassign` record who labels which item (reassignment names `from` and "
        "a reason); `next` lists a reviewer's unlabelled items without any judge output; "
        "`submit` signs one label bound to the reviewer key, rubric digest and item digest; "
        "`reveal` files a judge's signed `opentine.judge-outcome/1` outcomes (labels recorded "
        "after it do not count toward that judge). Agreement over a queue is `tine judge "
        "agreement`.",
        {"oneOf": _VERBS}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"label {name}": "tine-cli-label-1"
    for name in ("init", "assign", "reassign", "next", "submit", "reveal")
}

__all__ = ["COMMAND_SCHEMAS", "JUDGE_ROW", "REPORT", "SCHEMAS"]
