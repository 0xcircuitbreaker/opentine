"""OpenTine's own sweep after a supervised tool command (Linux ``/proc``).

The supervisor kills everything left beneath it, but the command runs as the
same user and can kill the supervisor first. So OpenTine never relies on it
alone (re-audit round 2, #7): after every supervised command it kills each
process still carrying the run's scope marker in its environment, and when the
supervisor did not report a sweep it also kills the run's *hidden* processes --
same user, started after the launch, outside OpenTine's own process tree, with
an environment it cannot read because the process made itself non-dumpable
(``PR_SET_DUMPABLE 0`` closes ``/proc/<pid>/environ`` to its own user).
"""

from __future__ import annotations

import os
import signal

#: Environment marker every supervised command (and its descendants) inherits.
SCOPE_ENV = "OPENTINE_TOOL_SCOPE"


def boot_ticks() -> int:
    """Now, in the clock ticks ``/proc/<pid>/stat`` counts process start in."""
    try:
        with open("/proc/uptime") as handle:
            seconds = float(handle.read().split()[0])
        return int(seconds * os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, IndexError):
        return 0


def _pids() -> list[int]:
    try:
        return [int(entry) for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return []


def _status(pid: int) -> tuple[int, int] | None:
    """``(real uid, parent pid)`` from ``/proc/<pid>/status`` (world-readable)."""
    uid = ppid = None
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                elif line.startswith("PPid:"):
                    ppid = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None if uid is None or ppid is None else (uid, ppid)


def _started(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
        return int(fields[19])  # field 22 (starttime), counted after "pid (comm)"
    except (OSError, ValueError, IndexError):
        return None


def _environ(pid: int) -> bytes | None:
    """The process's environment, or ``None`` when it is closed to us."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as handle:
            return handle.read(1 << 20)
    except PermissionError:
        return None
    except OSError:
        return b""  # gone, or a kernel thread: nothing to find


def _kill(pid: int) -> bool:
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def kill_marked(token: str) -> int:
    """SIGKILL every readable process whose environment carries *token*."""
    needle = f"{SCOPE_ENV}={token}".encode()
    me = os.getpid()
    killed = 0
    for pid in _pids():
        if pid == me:
            continue
        environ = _environ(pid)
        if environ and needle in environ.split(b"\0") and _kill(pid):
            killed += 1
    return killed


def kill_hidden(since: int) -> int:
    """SIGKILL same-user processes started at or after *since* that hide from us.

    Only processes outside OpenTine's own tree (so a concurrent tool's supervisor
    and shim -- themselves non-dumpable -- are spared) and whose environment is
    unreadable. Called only when a supervisor vanished without reporting a sweep,
    which no command does unless it is escaping containment.
    """
    me, uid = os.getpid(), os.getuid()
    table = {pid: info for pid in _pids() if (info := _status(pid)) is not None}
    children: dict[int, list[int]] = {}
    for pid, (_, ppid) in table.items():
        children.setdefault(ppid, []).append(pid)
    ours = {me}
    frontier = [me]
    while frontier:
        for child in children.get(frontier.pop(), ()):
            if child not in ours:
                ours.add(child)
                frontier.append(child)
    killed = 0
    for pid, (owner, _) in table.items():
        if owner != uid or pid in ours:
            continue
        started = _started(pid)
        if started is None or started < since:
            continue
        if _environ(pid) is None and _kill(pid):
            killed += 1
    return killed


__all__ = ["SCOPE_ENV", "boot_ticks", "kill_hidden", "kill_marked"]
