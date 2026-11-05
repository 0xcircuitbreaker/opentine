"""Exclusive lock files that record their owner, and safe stale-lock recovery.

A lock file holds ``"<pid> <host> <unix-time> <boot-id> <pid-ns>\\n"``. A lock
is broken only when it is *provably* dead: it names this host, this boot and
this PID namespace (so a same-named container sharing the directory, or a pid
reused after a reboot, never counts), and its process no longer exists. Older
three-field stamps (``"<pid> <host> <unix-time>"``) are still judged as before.
Age alone never breaks a lock (a long gc, or a paused writer, is still live),
and a lock from another host, an unreadable lock, or a still-running pid is
left alone so the caller can raise a clear error naming the file.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path

from opentine.repository import _winretry

_MAX_STAMP = 512


def _host() -> str:
    name = socket.gethostname() or "localhost"
    return "".join(
        ch if ch.isascii() and ch.isprintable() and not ch.isspace() else "_" for ch in name
    )


def _proc_token(read: Callable[[], object]) -> str:
    """One stamp field from /proc, or ``-`` when unavailable (never provable)."""
    try:
        value = read()
    except (OSError, ValueError):
        return "-"
    token = "".join(ch for ch in str(value).strip() if ch.isascii() and ch.isalnum() or ch == "-")
    return token[:64] or "-"


def _boot_id() -> str:
    return _proc_token(lambda: Path("/proc/sys/kernel/random/boot_id").read_text("ascii"))


def _pid_ns() -> str:
    return _proc_token(lambda: os.stat("/proc/self/ns/pid").st_ino)


def stamp() -> bytes:
    fields = (os.getpid(), _host(), int(time.time()), _boot_id(), _pid_ns())
    return (" ".join(map(str, fields)) + "\n").encode("ascii")


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


def _dead_identity(path: Path) -> tuple[int, int] | None:
    """``(st_dev, st_ino)`` of the lock at ``path`` if it is provably dead.

    Legacy two-field stamps (``"<pid> <time>"``, gc locks before 0.12.1) carry
    no host; they were only ever written by a local gc, so they are judged as
    same-host. Five-field stamps must also match this boot and PID namespace.
    """
    try:
        with open(path, "rb") as handle:
            identity = os.fstat(handle.fileno())
            raw = handle.read(_MAX_STAMP + 1)
        fields = raw.decode("ascii").split()
        if len(raw) > _MAX_STAMP or len(fields) not in (2, 3, 5):
            return None
        pid = int(fields[0])
        int(fields[2 if len(fields) == 5 else -1])
    except (OSError, ValueError, UnicodeDecodeError):
        return None  # being written right now, or unreadable: assume live
    if len(fields) >= 3 and fields[1] != _host():
        return None
    if len(fields) == 5:
        boot, ns = _boot_id(), _pid_ns()
        # Off Linux there is no boot id or PID namespace ("- -" on both sides):
        # fall back to the host-only rule, or a crashed writer's lock would be
        # unrecoverable there. On Linux an unknowable field never proves death.
        unknowable = "-" in (boot, ns) and (sys.platform.startswith("linux") or boot != ns)
        if unknowable or fields[3:] != [boot, ns]:
            return None  # another boot, namespace, or unknowable: cannot prove
    if pid_alive(pid):
        return None
    return identity.st_dev, identity.st_ino


def provably_dead(path: Path) -> bool:
    """Whether the lock at ``path`` was left by a dead process on this host."""
    return _dead_identity(path) is not None


def _same(path: Path, identity: tuple[int, int]) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (info.st_dev, info.st_ino) == identity


def _break(path: Path, identity: tuple[int, int]) -> None:
    """Remove the dead lock ``identity`` without ever deleting a live one a racing
    breaker just created: confirm it is still the file judged dead, move it
    aside, re-check what was moved, and put anything else back. If it cannot be
    put back, keep it aside and fail rather than delete a possibly-live lock."""
    # "<lock>.stale-N-M..lock" ends in ".lock" (never a ref) and would be the
    # guard lock only of a ref ending in "." (never legal), so it collides with
    # nothing in a refs directory.
    aside = path.with_name(f"{path.name}.stale-{os.getpid()}-{time.monotonic_ns()}..lock")
    if not _same(path, identity):
        return  # replaced since it was judged: acquire re-judges it
    try:
        os.rename(path, aside)
    except (FileNotFoundError, PermissionError):
        return  # gone, or (Windows) open in a contender's check: acquire reports it
    if _dead_identity(aside) != identity:
        try:
            os.link(aside, path)  # never clobbers a lock taken meanwhile
        except OSError as exc:
            raise FileExistsError(
                f"{path}: a live lock was moved aside to {aside} by a racing stale-lock"
                " break and could not be restored; check for a running writer"
            ) from exc
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
            identity = None if attempt else _dead_identity(path)
            if identity is None:
                raise
            _break(path, identity)
            continue
        try:
            os.write(fd, stamp())
        except BaseException:
            os.close(fd)
            _winretry.unlink(path)
            raise
        return fd
    raise FileExistsError(str(path))  # pragma: no cover - loop always returns or raises
