"""JSON Schema shapes for ``tine monitor backtest|collusion --json`` (0.63).

Joined into ``tine-cli-monitor-1`` by :mod:`opentine._schema_defs_monitor`.

CLI outputs, not object kinds: an online monitor verdict is an existing
attestation under the ``opentine.monitor.verdict`` claim convention
(docs/MONITOR.md); backtests and collusion tests only read recorded verdicts.
"""

from __future__ import annotations

from opentine._monitor_collusion import CODES
from opentine._monitor_rule import ACTIONS
from opentine._schema_defs import BOOL, FPR, INT, NUM, STR, closed, opt

_HEAD = {"schema": {"const": "tine-cli-monitor/1"}}
_RATE = opt(NUM)
_ACTION = opt({"enum": list(ACTIONS)})
_SIDE = {"caught": INT, "false_positives": INT, "catch_rate": _RATE, "false_positive_rate": _RATE}
_GROUP = closed(["trajectories", "attacks", "benign", "unlabelled", "replay", "online"], {
    "trajectories": INT, "attacks": INT, "benign": INT, "unlabelled": INT,
    "replay": closed(list(_SIDE), _SIDE),
    "online": closed(["judged", "attacks", "benign", *_SIDE], {
        **_SIDE, "judged": INT, "attacks": INT, "benign": INT})})  # fmt: skip
_COUNTS = ("steps", "reproduced", "not_reproduced", "other_monitor", "visibility_mismatch",
           "input_mismatch", "no_online_verdict", "skipped_trajectories")  # fmt: skip
_BACKTEST = closed(["command", "schema", "ok", "monitor", "monitor_digest", "visibility",
                    "counts", "groups", "diff", "bit_identical"], {
    **_HEAD, "command": {"const": "monitor backtest"}, "ok": BOOL, "monitor": STR,
    "monitor_digest": FPR, "visibility": opt(STR), "bit_identical": BOOL,
    "counts": closed(list(_COUNTS), {k: INT for k in _COUNTS}),
    "groups": {"type": "object", "additionalProperties": _GROUP},
    "diff": {"type": "array", "items": closed(
        ["run", "step", "outcome", "online_action", "replay_action", "online_score",
         "replay_score"], {
            "run": STR, "step": INT,
            "outcome": {"enum": ["reproduced", "not_reproduced", "other_monitor"]},
            "online_action": _ACTION, "replay_action": {"enum": list(ACTIONS)},
            "online_score": _RATE, "replay_score": NUM})}})  # fmt: skip
_WHO = closed(
    ["monitor", "monitor_digest", "trust"],
    {"monitor": STR, "monitor_digest": FPR, "trust": {"enum": ["trusted", "untrusted"]}},
)
_RATES = closed(
    ["attacks", "untrusted_catch_rate", "reference_catch_rate"],
    {"attacks": INT, "untrusted_catch_rate": _RATE, "reference_catch_rate": _RATE},
)
_COLLUSION = closed(["command", "schema", "ok", "advisory_only", "untrusted", "reference",
                     "margin", "min_samples", "rates", "missed_runs", "findings", "log"], {
    **_HEAD, "command": {"const": "monitor collusion"}, "ok": {"const": True},
    "advisory_only": {"const": True}, "untrusted": _WHO, "reference": opt(_WHO),
    "margin": NUM, "min_samples": {"type": "integer"},
    "rates": closed(["signal", "plain"], {"signal": _RATES, "plain": _RATES}),
    "missed_runs": {"type": "array", "items": STR}, "log": opt(STR),
    "findings": {"type": "array", "items": closed(["level", "code", "detail"], {
        "level": {"const": "advisory"}, "code": {"enum": list(CODES)},
        "detail": STR})}})  # fmt: skip

EVAL_DESCRIPTION = (
    "`backtest` replays recorded trajectories against a rule monitor and reports, per "
    "reasoning-visibility group (never pooled across groups), catch rate on attack-labelled "
    "trajectories and false-positive rate on benign ones, for the replay and for the recorded "
    "online verdicts. Online verdicts that saw another reasoning visibility or another input "
    "are counted, not compared. A verdict from the same monitor digest must reproduce byte for "
    "byte (`bit_identical`); `diff` lists every compared step whose action or decision changed. "
    "`collusion` compares an untrusted monitor's catch rate on attacks that carry a "
    "coordination signal with those that do not; its findings are advisory only (D12) and "
    "`ok` is always true."
)
EVAL_SHAPES = [_BACKTEST, _COLLUSION]
EVAL_COMMANDS = ("monitor backtest", "monitor collusion")

__all__ = ["EVAL_COMMANDS", "EVAL_DESCRIPTION", "EVAL_SHAPES"]
