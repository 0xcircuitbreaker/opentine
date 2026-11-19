"""JSON Schemas for sabotage task records (0.68).

``tine-cli-sabotage-1`` is the ``tine sabotage ... --json`` output.
``opentine-sabotage-task-1`` is the claim of a sabotage task attestation; it is
a claim convention on an existing object, not an object kind (docs/SABOTAGE.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-sabotage/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_TASK = {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,128}$"}
_CLASS = {"enum": ["code", "decision"]}
_DEC = {"type": "string", "pattern": "^[0-9]+\\.[0-9]{6}$"}
_STRS = {"type": "array", "items": STR}
_FINDING = closed(["level", "code", "task", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):sabotage\\.[a-z-]+$"},
    "task": STR, "message": STR})  # fmt: skip
_VERDICT = closed(["verdict", "verification", "action", "caught"], {
    "verdict": STR, "verification": STR, "action": opt(STR), "caught": BOOL})  # fmt: skip
_TASK_ROW = closed(
    ["task", "class", "run", "records", "counted", "main_task", "main_passed", "side_task",
     "attempted", "achieved", "caught", "verdicts", "evidence"], {
        "task": _TASK, "class": _CLASS, "run": opt(STR), "records": INT, "counted": INT,
        "main_task": STR, "main_passed": opt(BOOL), "side_task": STR, "attempted": BOOL,
        "achieved": BOOL, "caught": BOOL, "verdicts": {"type": "array", "items": _VERDICT},
        "evidence": _STRS})  # fmt: skip
_CLASS_ROW = closed(
    ["class", "tasks", "attempted", "achieved", "caught", "achieved_uncaught", "catch_rate",
     "ci"], {
        "class": _CLASS, "tasks": INT, "attempted": INT, "achieved": INT, "caught": INT,
        "achieved_uncaught": INT, "catch_rate": opt(_DEC),
        "ci": opt({"type": "array", "items": _DEC, "minItems": 2, "maxItems": 2})})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "record", "task", "class", "run"], {
        **_HEAD, "command": {"const": "sabotage record"}, "record": _ATT, "task": _TASK,
        "class": _CLASS, "run": STR}),
    closed(["command", "schema", "ok", "strict", "blocking", "advisory", "seed", "resamples",
            "alpha", "tasks", "classes", "findings"], {
        **_HEAD, "command": {"const": "sabotage report"}, "ok": BOOL, "strict": BOOL,
        "blocking": INT, "advisory": {"const": True}, "seed": INT, "resamples": INT,
        "alpha": STR, "tasks": {"type": "array", "items": _TASK_ROW},
        "classes": {"type": "array", "items": _CLASS_ROW},
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip
TASK_CLAIM = closed(
    ["convention", "task", "class", "main_task", "side_task", "evidence", "monitor_verdicts",
     "at"], {
        "convention": {"const": "opentine.sabotage-task/1"}, "task": _TASK, "class": _CLASS,
        "main_task": closed(["id", "score", "passed"], {
            "id": STR, "score": opt(STR), "passed": opt(BOOL)}),
        "side_task": closed(["id", "attempted", "achieved"], {
            "id": STR, "attempted": BOOL, "achieved": BOOL}),
        "evidence": _STRS, "monitor_verdicts": {"type": "array", "items": _ATT},
        "at": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-sabotage-1": doc("tine-cli-sabotage-1", "tine sabotage ... --json",
        "Sabotage task records. `record` writes one signed, held `opentine.sabotage-task/1` "
        "attestation on a run; `report` gives catch rate per sabotage class with a seeded "
        "bootstrap interval and D12 findings (advisory statistics, not proof of intent).",
        {"anyOf": _SHAPES}),
    "opentine-sabotage-task-1": doc("opentine-sabotage-task-1", "opentine.sabotage-task/1 claim",
        "The claim of an attestation on a run recording one SHADE-style sabotage task "
        "outcome: main task, side task attempted/achieved, evidence and linked monitor "
        "verdicts. A claim convention, not an object kind.", TASK_CLAIM),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"sabotage {verb}": "tine-cli-sabotage-1" for verb in ("record", "report")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS", "TASK_CLAIM"]
