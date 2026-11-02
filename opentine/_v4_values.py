"""Values format v4 cannot hold: refused on explicit writes, softened for recorders.

An explicit write (``Run.save``, ``put_run``, ``tine migrate``) refuses an
integer beyond 2**53-1 or a non-finite float, naming the field
(``_format_v4.refuse_unrepresentable``). A live recorder must not lose a run
over one value, so a run it built is marked :func:`mark_lenient`: such a value
is converted to its exact decimal string (never rounded) and the field path is
listed under ``metadata.warnings``.

Every walk here is iterative (an explicit stack, no recursion).
"""

from __future__ import annotations

import math
from typing import Any

from opentine._format_v4 import MAX_SAFE_INTEGER, refuse_unrepresentable, v4_requested

LENIENT = "_v4_lenient"
#: ``metadata.warnings`` entries one run keeps; the rest are counted, not listed.
MAX_WARNINGS = 64
_STEP_FIELDS = ("inputs", "outputs", "tool_info", "error", "usage", "billing")
_RUN_FIELDS = ("metadata", "manifest", "cache", "policies", "refs")


def _spelled(value: Any) -> str | None:
    """The exact text for a value v4 cannot hold, or ``None`` for one it can."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and abs(value) > MAX_SAFE_INTEGER:
        try:
            return str(value)
        except ValueError:  # past Python's int-to-str digit limit: json_safe's marker
            from opentine._jsonsafe import _string

            return _string(value)
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return None


def soften(value: Any, path: str, warnings: list[str]) -> Any:
    """*value* with every unrepresentable number replaced by its string, in place.

    Containers are mutated (lists and dicts), so a recorder's own objects are
    fixed; the returned value is the replacement for a top-level scalar.
    """
    top = _spelled(value)
    if top is not None:
        warnings.append(path)
        return top
    stack, seen = [(value, path)], set()
    while stack:
        item, where = stack.pop()
        if id(item) in seen:  # a cycle (the writer refuses it later, by name)
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            pairs = [(key, item[key], f"{where}.{key}") for key in list(item)]
        elif isinstance(item, list):
            pairs = [(index, entry, f"{where}[{index}]") for index, entry in enumerate(item)]
        else:
            continue
        for key, entry, child in pairs:
            text = _spelled(entry)
            if text is not None:
                item[key] = text
                warnings.append(child)
            elif isinstance(entry, (dict, list)):
                stack.append((entry, child))
    return value


def find_unrepresentable(value: Any, path: str) -> list[str]:
    """The field paths under *value* that v4 cannot hold, without changing it."""
    found: list[str] = []
    stack, seen = [(value, path)], set()
    while stack and len(found) < MAX_WARNINGS:
        item, where = stack.pop()
        if _spelled(item) is not None:
            found.append(where)
        elif isinstance(item, (dict, list)) and id(item) not in seen:
            seen.add(id(item))
            pairs = item.items() if isinstance(item, dict) else enumerate(item)
            for key, entry in pairs:
                child = f"{where}.{key}" if isinstance(item, dict) else f"{where}[{key}]"
                stack.append((entry, child))
    return found


def warning_text(path: str) -> str:
    return f"{path}: not representable in format v4; stored as a string"


def mark_lenient(run: Any) -> Any:
    """Mark a recorder's run: a v4 write softens it instead of refusing it."""
    run.__dict__[LENIENT] = True
    return run


def soften_run(run: Any) -> list[str]:
    """Stringify what v4 cannot hold across *run*, recording ``metadata.warnings``."""
    found: list[str] = []
    for step_id, step in run.graph.steps.items():
        for name in _STEP_FIELDS:
            soften(getattr(step, name), f"run.graph.steps.{step_id}.{name}", found)
        for name in ("timestamp", "duration", "cost"):
            text = _spelled(getattr(step, name))
            if text is not None:  # a typed number: zeroed, the original kept in the warning
                setattr(step, name, 0.0)
                found.append(f"run.graph.steps.{step_id}.{name} (was {text}, now 0)")
    for name in _RUN_FIELDS:
        soften(getattr(run, name), f"run.{name}", found)
    soften(run.transcript, "run.transcript", found)
    if found:
        listed = run.metadata.setdefault("warnings", [])
        if not isinstance(listed, list):
            listed = run.metadata["warnings"] = [str(listed)]
        for path in found[:MAX_WARNINGS]:
            listed.append(warning_text(path))
        if len(found) > MAX_WARNINGS:
            listed.append(
                f"{len(found) - MAX_WARNINGS} more unrepresentable values stored as strings"
            )
    return found


def prepare_run(run: Any, where: str = "run") -> None:
    """Before a v4 write: soften a recorder's run, refuse anyone else's."""
    try:
        if run.__dict__.get(LENIENT):
            soften_run(run)
        value = run.to_dict()
    except (AttributeError, TypeError):  # a malformed run: the writer names the field
        return
    refuse_unrepresentable(value, where)


def refuse_in_v4(value: Any, where: str) -> None:
    """The v4 repository writer refuses what the legacy one stringified."""
    if v4_requested():
        refuse_unrepresentable(value, where)


__all__ = ["mark_lenient", "prepare_run", "refuse_in_v4", "soften", "soften_run"]
