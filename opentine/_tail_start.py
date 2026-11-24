"""Where a follower starts on a ref it first sees after following began (``tine log -f``).

A ref listed only later (a new tag, a pulled branch, a ref missing from a resume
cursor) may point at an old run with thousands of events. Replaying all of them
would flood the stream, so only the events that predate the follower are cut to
the backlog, like a ref present at the start; events recorded since the follower
began are new and always shown, so a run created mid-follow is shown whole.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, ObjectEnvelope


def _recorded_before(repo: Any, oid: str, since: float) -> bool | None:
    """Whether event *oid* was recorded before *since*; ``None`` while its bytes are unreadable."""
    try:
        envelope = ObjectEnvelope.decode(repo.raw(oid), oid)
        when = envelope.payload().get("time_unix")
    except (KeyError, FileNotFoundError, LookupError):
        return None
    except (KernelError, ValueError, TypeError):
        return True
    return type(when) not in (int, float) or when < since


def late_start(repo: Any, events: list[str], since: float, backlog: int) -> int:
    """The first index to show of a ref first listed after the follower began at *since*.

    The run's events up to the last one recorded before *since* are history: of
    those only the last *backlog* are shown. Every later event is shown.
    """
    old = 0
    for index in range(len(events) - 1, -1, -1):
        if _recorded_before(repo, events[index], since):
            old = index + 1
            break
    return max(0, old - backlog)


__all__ = ["late_start"]
