"""Rule monitors and the decision part of a monitor verdict (0.63).

A monitor spec is a JSON object (docs/MONITOR_BACKTESTS.md)::

    {"monitor": "NAME", "kind": "rule", "trust": "trusted" | "untrusted",
     "rules": [{"tool": GLOB, "pattern": REGEX, "on": "input" | "reasoning" | "both",
                "score": NUMBER}],
     "actions": [{"at": NUMBER, "action": "flag" | "resample" | "defer" | "block"}]}

A step's score is the largest score of the rules that match it (0 when none
does); its action is the action with the largest ``at`` not above the score
(``allow`` when none is). A rule monitor is deterministic: the same spec bytes
and the same step give the same decision. ``monitor_digest`` is the SHA-256 of
the spec's canonical JSON, ``input_digest`` that of what the monitor saw: the
tool, its input and the reasoning text as captured (``[redacted]`` when it was
redacted, ``null`` when unavailable). Latency is never part of a decision.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ACTIONS = ("allow", "flag", "resample", "defer", "block")
VISIBILITY = ("captured", "redacted", "unavailable")
DECISION = ("monitor", "monitor_digest", "input_digest", "reasoning", "score", "threshold",
            "action")  # fmt: skip
REDACTED = "[redacted]"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")  # fmt: skip


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _number(value: Any, where: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} must be a number")
    return value


def parse(spec: Any) -> dict[str, Any]:
    """Check a monitor spec and return it with compiled rules under ``_rules``."""
    if not isinstance(spec, dict) or spec.get("kind") != "rule":
        raise ValueError('a monitor spec is an object with "kind": "rule"')
    name = spec.get("monitor")
    if not isinstance(name, str) or not name:
        raise ValueError('a monitor spec names itself in "monitor"')
    if spec.get("trust", "trusted") not in ("trusted", "untrusted"):
        raise ValueError('"trust" is "trusted" or "untrusted"')
    rules = []
    for i, rule in enumerate(spec.get("rules", [])):
        where = f"rules[{i}]"
        if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str):
            raise ValueError(f"{where} needs a string pattern")
        on = rule.get("on", "input")
        if on not in ("input", "reasoning", "both"):
            raise ValueError(f'{where}.on is "input", "reasoning" or "both"')
        rules.append((str(rule.get("tool", "*")), re.compile(rule["pattern"]), on,
                      _number(rule.get("score"), f"{where}.score")))  # fmt: skip
    actions = []
    for i, row in enumerate(spec.get("actions", [])):
        if not isinstance(row, dict) or row.get("action") not in ACTIONS[1:]:
            raise ValueError(f"actions[{i}].action is one of {', '.join(ACTIONS[1:])}")
        actions.append((_number(row.get("at"), f"actions[{i}].at"), row["action"]))
    if not actions:
        raise ValueError("a monitor spec needs at least one action threshold")
    body = {k: v for k, v in spec.items() if not k.startswith("_")}
    return {**body, "_rules": rules, "_actions": sorted(actions, key=lambda a: a[0]),
            "_digest": digest(body)}  # fmt: skip


def load(path: str | Path) -> dict[str, Any]:
    return parse(json.loads(Path(path).read_bytes()))


def seen(step: dict[str, Any]) -> dict[str, Any]:
    """What a monitor sees of one step: tool, input and reasoning by visibility."""
    state = step.get("reasoning", "unavailable")
    if state not in VISIBILITY:
        raise ValueError(f"reasoning is one of {', '.join(VISIBILITY)}")
    text = step.get("reasoning_text") if state == "captured" else None
    if state == "captured" and not isinstance(text, str):
        raise ValueError("captured reasoning needs reasoning_text")
    return {"tool": str(step.get("tool", "")), "input": step.get("input"),
            "reasoning": REDACTED if state == "redacted" else text}  # fmt: skip


def decide(monitor: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    """The decision fields of a verdict (``DECISION``) for one step."""
    view = seen(step)
    body = canonical(view["input"]).decode("utf-8")
    thought = view["reasoning"] or ""
    score: float | int = 0
    for tool, pattern, on, value in monitor["_rules"]:
        if not fnmatch.fnmatchcase(view["tool"], tool):
            continue
        hay = {"input": (body,), "reasoning": (thought,), "both": (body, thought)}[on]
        if any(pattern.search(h) for h in hay) and value > score:
            score = value
    action, threshold = "allow", monitor["_actions"][0][0]
    for at, name in monitor["_actions"]:
        if score >= at:
            action, threshold = name, at
    return {"monitor": monitor["monitor"], "monitor_digest": monitor["_digest"],
            "input_digest": digest(view), "reasoning": step.get("reasoning", "unavailable"),
            "score": score, "threshold": threshold, "action": action}  # fmt: skip


def decision_bytes(verdict: dict[str, Any]) -> bytes:
    """Canonical bytes of a verdict's decision fields (latency and the rest left out)."""
    return canonical({k: verdict.get(k) for k in DECISION})


__all__ = ["ACTIONS", "DECISION", "VISIBILITY", "canonical", "decide", "decision_bytes",
           "digest", "load", "parse", "seen"]  # fmt: skip
