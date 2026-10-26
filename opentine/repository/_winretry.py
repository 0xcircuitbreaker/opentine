"""Retry Windows sharing violations on repository control files.

On Windows a file cannot be renamed over, deleted, or (while delete-pending)
reopened while another handle has it open without ``FILE_SHARE_DELETE`` --
and Python's ``open``/``os.open`` never pass that flag. So an unlocked reader
of a ref (``read_ref``, prune's root scan, a lock owner check) makes a
concurrent ``os.replace``/``unlink`` fail with ``PermissionError`` (WinError
5/32), and the reader's own ``open`` can fail with Errno 13 on a ref that is
mid-replace. Those are transient: the other handle is held for microseconds.

:func:`retry` reruns such an operation with a bounded backoff (about two
seconds in all) and then re-raises, so a persistent denial still fails closed.
Correctness never rests on the wait: every caller is safe if the error does
surface (locks stay held, journals roll forward, prune deletes nothing).
Elsewhere ``PermissionError`` is a real denial and is raised at once.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

#: Whether sharing violations are expected (patched by tests to cover the logic).
WINDOWS = os.name == "nt"
ATTEMPTS = 40
_sleep = time.sleep


def retry(operation: Callable[[], T]) -> T:
    """``operation()``, retried on ``PermissionError`` on Windows, then re-raised."""
    for attempt in range(ATTEMPTS):
        try:
            return operation()
        except PermissionError:
            if not WINDOWS or attempt == ATTEMPTS - 1:
                raise
            _sleep(min(0.001 * 2**attempt, 0.05))
    raise AssertionError("unreachable")  # pragma: no cover


def replace(source: os.PathLike | str, target: os.PathLike | str) -> None:
    retry(lambda: os.replace(source, target))


def unlink(path: os.PathLike | str) -> None:
    """Remove ``path`` if present (``missing_ok``), outlasting transient readers."""

    def remove() -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    retry(remove)


def unlink_all(paths: list) -> None:
    """Unlink every path (e.g. release every held lock) even if one fails, then
    raise the first failure: one stuck lock must not strand the others."""
    error: OSError | None = None
    for path in paths:
        try:
            unlink(path)
        except OSError as exc:
            error = error or exc
    if error is not None:
        raise error


def open_fd(path: os.PathLike | str, flags: int, mode: int = 0o777) -> int:
    return retry(lambda: os.open(path, flags, mode))


def read_bytes(path: os.PathLike | str, limit: int) -> bytes:
    """Up to ``limit`` bytes of ``path``; ``FileNotFoundError`` passes through."""

    def read() -> bytes:
        with open(path, "rb") as handle:
            return handle.read(limit)

    return retry(read)
