"""Replay recorded trajectories against a monitor offline (``tine monitor backtest``, 0.63).

A trajectory file is JSON Lines (or one JSON object or array) of
``{"run", "label"?, "steps": [{"tool", "input", "reasoning", "reasoning_text"?,
"verdict"?}]}``; ``verdict`` is the online verdict recorded for the step
(the decision fields of an ``opentine.monitor-verdict/1`` verdict,
docs/MONITOR_BACKTESTS.md) and ``label``
is ``{"attack": bool}`` for control evaluations. Every step is replayed through
the monitor (:func:`opentine._monitor_rule.decide`).

Like with like: an online verdict is compared only when it saw the same
reasoning visibility as the replay (``captured``, ``redacted`` or
``unavailable``) and the same input digest; others are counted as
``visibility_mismatch`` or ``input_mismatch`` and left out of the diff. Rates
are reported per visibility group (the set of states a trajectory's steps
carry) and never pooled across groups. When the online verdict came from the
same monitor digest the replay must reproduce its decision bytes exactly
(``reproduced``), the input digest included, so a recorded step
edited after its verdict is ``not_reproduced`` rather than set aside.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._monitor_rule import decide, decision_bytes

CAUGHT = frozenset({"flag", "resample", "defer", "block"})


def read_trajectories(paths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        data = Path(path).read_bytes()
        text = data.decode("utf-8").strip()
        if text.startswith("["):
            found = json.loads(text)
        elif text.startswith("{") and "\n" not in text:
            found = [json.loads(text)]
        else:
            found = [json.loads(line) for line in text.split("\n") if line.strip()]
        for i, row in enumerate(found):
            if not isinstance(row, dict) or not isinstance(row.get("steps"), list):
                raise ValueError(f"{Path(path).as_posix()}[{i}]: a trajectory has a steps list")
            rows.append(row)
    return rows


def group_of(trajectory: dict[str, Any]) -> str:
    states = {str(s.get("reasoning", "unavailable")) for s in trajectory["steps"]}
    return "+".join(sorted(states)) or "empty"


def _rate(hit: int, total: int) -> float | None:
    return None if total == 0 else hit / total


def _metrics() -> dict[str, Any]:
    return {"trajectories": 0, "attacks": 0, "benign": 0, "unlabelled": 0,
            "replay": {"caught": 0, "false_positives": 0},
            "online": {"judged": 0, "caught": 0, "false_positives": 0, "attacks": 0,
                       "benign": 0}}  # fmt: skip


def _compare(step: dict[str, Any], replay: dict[str, Any]) -> str:
    online = step.get("verdict")
    if not isinstance(online, dict):
        return "no_online_verdict"
    if online.get("reasoning") != replay["reasoning"]:
        return "visibility_mismatch"
    if online.get("monitor_digest") == replay["monitor_digest"]:
        # Same monitor, same visibility: the input digest is part of the decision
        # bytes, so a step edited after its verdict is not reproduced.
        same = decision_bytes(online) == decision_bytes(replay)
        return "reproduced" if same else "not_reproduced"
    if online.get("input_digest") != replay["input_digest"]:
        return "input_mismatch"
    return "other_monitor"


def backtest(
    monitor: dict[str, Any], trajectories: list[dict[str, Any]], *, visibility: str | None = None
) -> dict[str, Any]:
    counts = {k: 0 for k in ("steps", "reproduced", "not_reproduced", "other_monitor",
                             "visibility_mismatch", "input_mismatch", "no_online_verdict",
                             "skipped_trajectories", "unverified_verdicts")}  # fmt: skip
    groups: dict[str, dict[str, Any]] = {}
    diff: list[dict[str, Any]] = []
    for trajectory in trajectories:
        group = group_of(trajectory)
        if visibility is not None and group != visibility:
            counts["skipped_trajectories"] += 1
            continue
        m = groups.setdefault(group, _metrics())
        m["trajectories"] += 1
        hit, online_hit, online_all = False, False, bool(trajectory["steps"])
        for index, step in enumerate(trajectory["steps"]):
            replay = decide(monitor, step)
            outcome = _compare(step, replay)
            counts["steps"] += 1
            counts[outcome] += 1
            hit = hit or replay["action"] in CAUGHT
            comparable = outcome in ("reproduced", "not_reproduced", "other_monitor")
            online_all = online_all and comparable
            if comparable:
                before = step["verdict"].get("action")
                online_hit = online_hit or before in CAUGHT
                if outcome == "not_reproduced" or before != replay["action"]:
                    diff.append({"run": str(trajectory.get("run", "")), "step": index,
                                 "outcome": outcome, "online_action": before,
                                 "replay_action": replay["action"],
                                 "online_score": step["verdict"].get("score"),
                                 "replay_score": replay["score"]})  # fmt: skip
        label = trajectory.get("label")
        attack = label.get("attack") if isinstance(label, dict) else None
        if not isinstance(attack, bool):
            m["unlabelled"] += 1
            continue
        side = "attacks" if attack else "benign"
        field = "caught" if attack else "false_positives"
        m[side] += 1
        m["replay"][field] += int(hit)
        if online_all:
            m["online"]["judged"] += 1
            m["online"][side] += 1
            m["online"][field] += int(online_hit)
    for m in groups.values():
        for row, base in ((m["replay"], m), (m["online"], m["online"])):
            row["catch_rate"] = _rate(row["caught"], base["attacks"])
            row["false_positive_rate"] = _rate(row["false_positives"], base["benign"])
    return {"monitor": monitor["monitor"], "monitor_digest": monitor["_digest"],
            "visibility": visibility, "counts": counts,
            "groups": dict(sorted(groups.items())), "diff": diff,
            "bit_identical": counts["not_reproduced"] == 0}  # fmt: skip


__all__ = ["CAUGHT", "backtest", "group_of", "read_trajectories"]
