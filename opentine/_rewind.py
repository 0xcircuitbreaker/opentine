"""``tine rewind``: put the files a run changed back the way they were at a step.

Nothing is guessed. A recorded write step says exactly what it put in a file:
a ``Write`` carries the whole ``content``; an ``Edit`` carries ``old_string`` →
``new_string`` (``edits`` for MultiEdit, ``old_str``/``new_str`` for
str_replace). The per-file history (the same write actions ``tine blame``
reads) is replayed forward from the last whole-file write, and walked backward
from the run's last known state by undoing edits whose inserted text occurs
exactly once. When neither walk reaches the step, the file is unrecoverable and
listed with the reason: a shell redirect, a patch, a redacted value, a failed
edit, or a file the run created without saying what was there before.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentine._actions import extract_actions
from opentine._blame import _arguments

Edits = list[tuple[str, str, bool]]
_WHOLE = ("content", "file_text", "contents")


@dataclass
class Event:
    seq: int
    kind: str  # "write" (payload: str), "edit" (payload: Edits), "opaque" (payload: reason)
    payload: Any


@dataclass
class Plan:
    path: str
    target: str | None = None
    final: str | None = None  # the run's last recorded content, when known
    reverse_on_disk: Edits | None = None  # undo these on the current file instead
    reason: str = ""
    events: list[Event] = field(default_factory=list)


class RewindError(ValueError):
    pass


def _edits(arguments: dict[str, Any]) -> Edits | None:
    pairs = [arguments, *(arguments.get("edits") or [])] if "edits" in arguments else [arguments]
    out: Edits = []
    for item in pairs if isinstance(pairs, list) else []:
        if not isinstance(item, dict):
            return None
        old = item.get("old_string", item.get("old_str"))
        new = item.get("new_string", item.get("new_str"))
        if old is None and new is None and item is arguments:
            continue
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        out.append((old, new, bool(item.get("replace_all"))))
    return out or None


def _event(step: Any, seq: int, written: list[str]) -> Event:
    outputs = step.outputs if isinstance(step.outputs, dict) else {}
    if step.error or outputs.get("is_error"):
        return Event(seq, "skip", "")
    arguments = _arguments(step)
    if not isinstance(arguments, dict) or len(written) != 1:
        return Event(seq, "opaque", f"step {seq} changed it without recording the content")
    whole = next((arguments[k] for k in _WHOLE if isinstance(arguments.get(k), str)), None)
    if whole is not None:
        event = Event(seq, "write", whole)
        texts = [whole]
    elif (edits := _edits(arguments)) is not None:
        event = Event(seq, "edit", edits)
        texts = [part for edit in edits for part in edit[:2]]
    else:
        return Event(seq, "opaque", f"step {seq} changed it without recording the content")
    if any("[REDACTED" in text for text in texts):
        return Event(seq, "opaque", f"step {seq} recorded it redacted")
    return event


def forward(state: str | None, event: Event) -> str | None:
    if event.kind == "skip":
        return state
    if event.kind == "write":
        return event.payload
    if event.kind != "edit" or state is None:
        return None
    for old, new, every in event.payload:
        if not old or old not in state or (not every and state.count(old) != 1):
            return None
        state = state.replace(old, new) if every else state.replace(old, new, 1)
    return state


def backward(state: str, edits: Edits) -> str | None:
    """*state* with *edits* undone, or ``None`` when an undo would be a guess."""
    for old, new, every in reversed(edits):
        if every or not new or state.count(new) != 1:
            return None
        state = state.replace(new, old, 1)
    return state


def histories(run: Any, root: Path) -> dict[str, list[Event]]:
    """Recorded write events per root-relative path, in step order."""
    actions, _clipped = extract_actions(run)
    found: dict[str, list[Event]] = {}
    for action in actions:
        if not action.written:
            continue
        step = run.steps[action.seq]
        for written in action.written:
            key = relative_key(root, written)
            found.setdefault(key, []).append(_event(step, action.seq, action.written))
    return found


def relative_key(root: Path, written: str) -> str:
    text = os.path.expanduser(written.replace("\\", "/"))
    candidate = Path(text) if os.path.isabs(text) else root / text
    return Path(os.path.normpath(candidate)).as_posix()


def plan_file(path: str, events: list[Event], until: int) -> Plan:
    """What *path* held right after step *until* (``-1``: before the run)."""
    plan = Plan(path, events=events)
    plan.target = _at(events, until)
    plan.final = _at(events, events[-1].seq)
    if plan.target is not None:
        return plan
    later = [event for event in events if event.seq > until]
    plan.reason = _why(later)
    if plan.reason:
        return plan
    undo = [edit for event in later if event.kind == "edit" for edit in event.payload]
    if plan.final is None:
        plan.reverse_on_disk = undo  # only edits since the step: undo them on the file
        return plan
    plan.target = backward(plan.final, undo)
    if plan.target is None:
        plan.reason = "undoing an edit after the step would be a guess"
    return plan


def _at(events: list[Event], until: int) -> str | None:
    state: str | None = None
    for event in events:
        if event.seq > until:
            break
        state = forward(state, event)
    return state


def _why(later: list[Event]) -> str:
    """Why undoing *later* back to the step cannot work ("" when it can)."""
    for event in reversed(later):
        if event.kind == "opaque":
            return str(event.payload)
        if event.kind == "write":
            return f"step {event.seq} rewrote it whole and the earlier content is not recorded"
    return "" if later else "the run never recorded its content at that step"


def confined(root: Path, key: str) -> Path:
    """The file for *key*, refusing a path outside *root* or through a link."""
    candidate = Path(key)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise RewindError(f"{key} is outside {root}") from exc
    if ".." in relative.parts or not relative.parts:
        raise RewindError(f"{key} escapes {root}")
    walk = root
    for part in relative.parts:
        walk = walk / part
        if walk.is_symlink():
            raise RewindError(f"{relative.as_posix()} goes through a symbolic link")
    return candidate


__all__ = ["Event", "Plan", "RewindError", "confined", "histories", "plan_file"]
