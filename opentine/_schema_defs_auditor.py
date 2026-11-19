"""JSON Schemas for auditor runs, blind audit games and judge provenance (0.65).

``tine-cli-auditor-1`` is the ``tine auditor ... --json`` output.
``opentine-audit-game-1`` is the claim of an audit-game attestation and
``opentine-judge-provenance-1`` the ``judge.json`` an llm-judge eval writes;
both are claim conventions on existing objects, not object kinds
(docs/AUDIT_GAMES.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, NUM, OBJ, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-auditor/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_GAME_NAME = {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$"}
_FINDING = closed(["level", "code", "game", "message"], {
    "level": {"enum": ["fail", "advisory"]},
    "code": {"type": "string", "pattern": "^(fail|advisory):audit-game\\.[a-z-]+$"},
    "game": STR, "message": STR})  # fmt: skip
_GAME = closed(["game", "state", "records", "seal", "findings", "verdict", "reveal", "target"], {
    "game": STR, "state": {"enum": ["empty", "sealed", "submitted", "revealed"]},
    "records": INT, "seal": opt(_ATT), "findings": opt(_ATT),
    "verdict": opt({"enum": ["concern", "no-concern"]}), "reveal": opt(_ATT),
    "target": opt(STR)})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "run", "transcript", "steps", "auditor_model", "judge_model",
            "target_model", "sealed", "scores"], {
        **_HEAD, "command": {"const": "auditor import-petri"}, "run": STR, "transcript": STR,
        "steps": INT, "auditor_model": STR, "judge_model": STR, "target_model": opt(STR),
        "sealed": opt(FPR), "scores": {"type": "object", "additionalProperties": NUM}}),
    closed(["command", "schema", "record", "game", "step"], {
        **_HEAD, "command": {"enum": ["auditor seal", "auditor findings", "auditor reveal"]},
        "record": _ATT, "game": _GAME_NAME,
        "step": {"enum": ["seal", "findings", "reveal"]}}),
    closed(["command", "schema", "ok", "strict", "blocking", "games", "findings"], {
        **_HEAD, "command": {"const": "auditor check"}, "ok": BOOL, "strict": BOOL,
        "blocking": INT, "games": {"type": "array", "items": _GAME},
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip
GAME_CLAIM = closed(["convention", "game", "step", "at"], {
    "convention": {"const": "opentine.audit-game/1"}, "game": _GAME_NAME,
    "step": {"enum": ["seal", "findings", "reveal"]}, "at": STR, "commitment": FPR,
    "seal": _ATT, "findings_digest": FPR, "verdict": {"enum": ["concern", "no-concern"]},
    "findings": opt(_ATT), "target": STR, "objective": STR, "nonce": STR})  # fmt: skip
PROVENANCE = closed(["convention", "model", "prompt_digest", "rubric_digest", "sampling"], {
    "convention": {"const": "opentine.judge-provenance/1"}, "model": STR,
    "prompt_digest": FPR, "rubric_digest": opt(FPR),
    "sampling": {**OBJ, "additionalProperties": STR}})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-auditor-1": doc("tine-cli-auditor-1", "tine auditor ... --json",
        "Auditor runs and blind audit games. `import-petri` records a Petri or Bloom "
        "transcript as a `role=auditor` run (with `--blind`, the target is a commitment); "
        "`seal`/`findings`/`reveal` write one signed, held `opentine.audit-game/1` "
        "attestation; `check` judges every game (D12 findings).",
        {"anyOf": _SHAPES}),
    "opentine-audit-game-1": doc("opentine-audit-game-1", "opentine.audit-game/1 claim",
        "The claim of an attestation on a role=auditor run recording one step of a blind "
        "audit game. A claim convention, not an object kind.", GAME_CLAIM),
    "opentine-judge-provenance-1": doc("opentine-judge-provenance-1",
        "opentine.judge-provenance/1 document",
        "What an llm-judge scorer is: its pin (jp1+sha256 over the canonical JSON) is the "
        "signed scorer_version of every verdict it scores; eval folders keep it as "
        "judge.json. A claim convention, not an object kind.", PROVENANCE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"auditor {verb}": "tine-cli-auditor-1"
    for verb in ("import-petri", "seal", "findings", "reveal", "check")
}

__all__ = ["COMMAND_SCHEMAS", "GAME_CLAIM", "PROVENANCE", "SCHEMAS"]
