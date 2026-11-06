"""The per-turn callback point of ``opentine-hook/1`` (see :mod:`opentine._hook_protocol`).

At every ``turn_end`` event the protocol calls each registered callback, in
registration order, *before* it appends the turn's step::

    callback(TurnContext) -> dict[str, Any] | None

A callback returns attributes for that step (for example the oid of a
workspace tree snapshot, under an ``opentine.*`` key) or ``None``. The step
and its attributes are then written durably together. A callback that raises
is skipped and named under ``opentine.hook.callback_errors``: one failing
callback never loses the step. Callbacks run inside the session's lock, after
every earlier step of the session has been persisted.

``tine hook capture`` is a fresh process per event, so a callback is registered
at import time by a module listed in :data:`BUILTIN` (the tree-snapshot module
adds itself there), or by code that calls :func:`register` in-process.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TurnContext:
    repo: Any
    recorder: Any  # opentine.trace.recorder.Recorder: run_id, ref, payload
    session: str
    agent: str
    cwd: str  # the agent's working directory from the payload ("" when absent)


TurnCallback = Callable[[TurnContext], "dict[str, Any] | None"]
_CALLBACKS: list[TurnCallback] = []
#: Modules imported before the first turn so they can :func:`register`.
BUILTIN: tuple[str, ...] = ()
_loaded = False


def register(callback: TurnCallback) -> TurnCallback:
    """Add *callback* (once); usable as a decorator."""
    if callback not in _CALLBACKS:
        _CALLBACKS.append(callback)
    return callback


def unregister(callback: TurnCallback) -> None:
    if callback in _CALLBACKS:
        _CALLBACKS.remove(callback)


def _load_builtin() -> None:
    global _loaded
    if not _loaded:
        _loaded = True
        for name in BUILTIN:
            importlib.import_module(name)


def run_turn_end(repo: Any, recorder: Any, event: dict[str, Any], agent: str) -> dict[str, Any]:
    """Every callback's attributes for the turn-end step, merged in order."""
    _load_builtin()
    context = TurnContext(repo, recorder, event["session"], agent, event.get("cwd") or "")
    merged: dict[str, Any] = {}
    errors: list[str] = []
    for callback in list(_CALLBACKS):
        try:
            result = callback(context)
        except Exception as exc:  # noqa: BLE001 - a callback never loses the step
            errors.append(f"{getattr(callback, '__name__', 'callback')}: {type(exc).__name__}")
            continue
        if isinstance(result, dict):
            merged.update({str(key): value for key, value in result.items()})
    if errors:
        merged["opentine.hook.callback_errors"] = errors
    return merged


__all__ = ["BUILTIN", "TurnCallback", "TurnContext", "register", "run_turn_end", "unregister"]
