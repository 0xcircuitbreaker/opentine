"""Exclusive lock files that record their owner, and safe stale-lock recovery.

A lock file holds ``"<pid> <host> <unix-time>\\n"``. A lock is broken only when
it is *provably* dead: it names this host and its process no longer exists.
Age alone never breaks a lock (a long gc, or a paused writer, is still live),
and a lock from another host, an unreadable lock, or a still-running pid is
left alone so the caller can raise a clear error naming the file.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from opentine.repository import _winretry

_MAX_STAMP = 512


def _host() -> str:
    name = socket.gethostname() or "localhost"
    return "".join(
        ch if ch.isascii() and ch.isprintable() and not ch.isspace() else "_" for ch in name
    )


def stamp() -> bytes:
    return f"{os.getpid()} {_host()} {int(time.time())}\n".encode("ascii")


def pid_alive(pid: int) -> bool:
    """True unless ``pid`` is provably gone on this host (unknown -> alive)."""
    if pid <= 0:
        return True
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return kernel32.GetLastError() != 87  # ERROR_INVALID_PARAMETER: no such pid
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def provably_dead(path: Path) -> bool:
    """Whether the lock at ``path`` was left by a dead process on this host.

    Legacy two-field stamps (``"<pid> <time>"``, gc locks before 0.12.1) carry
    no host; they were only ever written by a local gc, so they are judged as
    same-host.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_STAMP + 1)
        fields = raw.decode("ascii").split()
        if len(raw) > _MAX_STAMP or len(fields) not in (2, 3):
            return False
        pid = int(fields[0])
        int(fields[-1])
    except (OSError, ValueError, UnicodeDecodeError):
        return False  # being written right now, or unreadable: assume live
    if len(fields) == 3 and fields[1] != _host():
        return False
    return not pid_alive(pid)


def _break(path: Path) -> None:
    """Remove a dead lock without ever deleting a live one a racing breaker just
    created: move it aside, re-check what was moved, and put a live one back."""
    # "<lock>.stale-N-M..lock" ends in ".lock" (never a ref) and would be the
    # guard lock only of a ref ending in "." (never legal), so it collides with
    # nothing in a refs directory.
    aside = path.with_name(f"{path.name}.stale-{os.getpid()}-{time.monotonic_ns()}..lock")
    try:
        os.rename(path, aside)
    except (FileNotFoundError, PermissionError):
        return  # gone, or (Windows) open in a contender's check: acquire reports it
    try:
        if not provably_dead(aside):
            try:
                os.link(aside, path)  # never clobbers a lock taken meanwhile
            except OSError:
                pass
    finally:
        _winretry.unlink(aside)


def acquire(path: Path, mode: int = 0o644) -> int:
    """Create ``path`` exclusively, stamped with this owner; break a provably dead
    lock once. Raises ``FileExistsError`` while a live (or unknown) owner holds it.
    """
    for attempt in range(2):
        try:
            # Windows: a lock being deleted is briefly unopenable (delete pending).
            fd = _winretry.open_fd(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        except FileExistsError:
            if attempt or not provably_dead(path):
                raise
            _break(path)
            continue
        try:
            os.write(fd, stamp())
        except BaseException:
            os.close(fd)
            _winretry.unlink(path)
            raise
        return fd
    raise FileExistsError(str(path))  # pragma: no cover - loop always returns or raises
