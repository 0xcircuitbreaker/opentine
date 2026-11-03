"""``tine rewind``'s exact path: the stored original, replayed and verified.

A recorder that saw a file's full content before the run's first edit to it
(:mod:`opentine._file_originals`) makes rewinding a forward replay from known
text instead of a walk over diffs. Every step is checked: the stored text must
still hash to the digest taken before redaction, each edit must apply exactly,
and a step whose harness reported the resulting content must match it. Any
miss gives up the exact path, with the reason, so the caller falls back.
"""

from __future__ import annotations

from typing import Any

from opentine._file_originals import digest


def exact(events: list[Any], until: int, store: Any) -> tuple[str | None, str | None, str]:
    """``(content after step *until*, content after the run, why not)``.

    ``(None, None, "")`` when there is no stored original to use at all.
    """
    from opentine._rewind import forward

    first = events[0] if events else None
    if first is None or first.original is None:
        return None, None, ""
    text = store.get(first.original) if isinstance(store, dict) else None
    if not isinstance(text, str):
        return None, None, "the stored original is missing"
    if digest(text) != first.original:
        return None, None, "the stored original was altered by redaction"
    state: str | None = text
    target = text if until < first.seq else None
    for event in events:
        state = forward(state, event)
        if state is None:
            if event.seq <= until:
                return None, None, f"step {event.seq} does not replay exactly"
            break
        if event.post is not None and event.kind != "skip" and digest(state) != event.post:
            return None, None, f"step {event.seq} does not match its recorded result"
        if event.seq <= until:
            target = state
    return target, state, ""


__all__ = ["exact"]
