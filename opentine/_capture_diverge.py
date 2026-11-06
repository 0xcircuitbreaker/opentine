"""The divergence report: a proxy capture against an imported transcript.

A proxy (``tine mcp-proxy`` / ``tine record``) sees what really crossed the
wire; a transcript is what the agent says happened. Both are reduced to the
same sequence of comparable actions --

* ``("tool", name, arguments)`` -- an MCP ``tools/call`` on the proxy side, a
  tool step on the import side (an ``mcp__<server>__`` prefix is dropped);
* ``("prompt", text)`` -- a human prompt --

and aligned with :class:`difflib.SequenceMatcher`. Every non-equal block is one
divergence: ``missing`` (the witness saw it, the transcript does not say so),
``unwitnessed`` (the transcript claims it, the witness never saw it) or
``changed``. Protocol chatter the transcript cannot hold (``initialize``,
``tools/list``, notifications) is left out of the proxy side, and a kind of
action only one side can observe at all (an MCP proxy sees no prompts) is left
out of both.
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any

_MCP_PREFIX = re.compile(r"^mcp__[^_].*?__")


def _name(value: Any) -> str:
    return _MCP_PREFIX.sub("", str(value or ""))


def _args(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, default=str)


def actions(run: Any) -> list[tuple[str, str, str | None]]:
    """The comparable action sequence of one run."""
    found: list[tuple[str, str, str | None]] = []
    for step in run.steps:
        inputs = step.inputs if isinstance(step.inputs, dict) else {}
        kind = step.v3_kind or getattr(step.kind, "value", str(step.kind))
        if "method" in inputs and "transport" in inputs:  # an MCP proxy step
            if inputs.get("method") != "tools/call" or inputs.get("from") != "client":
                continue
            params = inputs.get("params") if isinstance(inputs.get("params"), dict) else {}
            found.append(("tool", _name(params.get("name")), _args(params.get("arguments"))))
        elif kind == "tool":
            name = inputs.get("name") or (step.tool_info or {}).get("name")
            raw = next((inputs[k] for k in ("arguments", "input", "args") if k in inputs), None)
            found.append(("tool", _name(name), _args(raw)))
        elif kind == "human":
            text = inputs.get("text") or inputs.get("prompt") or ""
            found.append(("prompt", "", str(text)))
    return found


def _same(a: tuple[str, str, str | None], b: tuple[str, str, str | None]) -> bool:
    """Equal kind and name; arguments only when both sides recorded them."""
    return a[:2] == b[:2] and (a[2] is None or b[2] is None or a[2] == b[2])


def _show(action: tuple[str, str, str | None] | None) -> dict[str, Any] | None:
    if action is None:
        return None
    kind, name, detail = action
    return {"kind": kind, "name": name or None, "detail": detail}


def compare(witness_path: Path, other_path: Path, args: Any = None) -> dict[str, Any]:
    """Compare two saved runs; the JSON report ``tine verify --compare-capture`` emits."""
    from opentine._assurance import assess, rank
    from opentine.core import Run

    runs = [Run.load(witness_path), Run.load(other_path)]
    tiers = [assess(witness_path, args), assess(other_path, args)]
    if rank(tiers[1]["verified"]) > rank(tiers[0]["verified"]):  # the better-witnessed run leads
        runs.reverse()
        tiers.reverse()
        witness_path, other_path = other_path, witness_path
    left, right = actions(runs[0]), actions(runs[1])
    # Compare only what both captures can see: an MCP proxy never sees a prompt.
    seen = {a[0] for a in left} & {a[0] for a in right}
    left, right = [a for a in left if a[0] in seen], [a for a in right if a[0] in seen]
    keys_l = [(a[0], a[1]) for a in left]
    keys_r = [(a[0], a[1]) for a in right]
    divergences: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(a=keys_l, b=keys_r, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                a, b = left[i1 + offset], right[j1 + offset]
                if not _same(a, b):
                    divergences.append(_entry("changed", i1 + offset, j1 + offset, a, b))
            continue
        width = max(i2 - i1, j2 - j1)
        for offset in range(width):
            i, j = i1 + offset, j1 + offset
            a = left[i] if i < i2 else None
            b = right[j] if j < j2 else None
            kind = "changed" if a and b else ("missing" if a else "unwitnessed")
            divergences.append(_entry(kind, i if a else None, j if b else None, a, b))
    return {
        "command": "verify",
        "mode": "compare-capture",
        "witness": {"path": str(witness_path), "assurance": tiers[0], "actions": len(left)},
        "other": {"path": str(other_path), "assurance": tiers[1], "actions": len(right)},
        "consistent": not divergences,
        "divergences": divergences,
    }


def _entry(kind: str, i: int | None, j: int | None, a: Any, b: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "witness_index": i,
        "other_index": j,
        "witness": _show(a),
        "other": _show(b),
    }


def render(result: dict[str, Any]) -> list[str]:
    from rich.markup import escape

    lines = []
    for side in ("witness", "other"):
        entry = result[side]
        tier = entry["assurance"]
        lines.append(
            f"{side:<8} {escape(entry['path'])}: {entry['actions']} action(s), "
            f"assurance {tier['verified']} (claimed {tier['claimed']})"
        )
    for item in result["divergences"]:
        a, b = item["witness"], item["other"]
        left = f"{a['kind']} {a['name'] or ''} {a['detail'] or ''}".strip() if a else "-"
        right = f"{b['kind']} {b['name'] or ''} {b['detail'] or ''}".strip() if b else "-"
        lines.append(f"  [red]{item['kind']:<11}[/] {escape(left[:120])} | {escape(right[:120])}")
    verdict = "[green]CONSISTENT[/]" if result["consistent"] else "[red]DIVERGENT[/]"
    lines.append(f"{verdict} {len(result['divergences'])} divergence(s)")
    return lines


__all__ = ["actions", "compare", "render"]
