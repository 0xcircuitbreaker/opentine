"""One writer at a time on a repository's budget ledgers (0.87).

:func:`locked` serialises ledger appends across threads and processes: a
reentrant in-process lock plus an OS file lock (``flock`` / ``msvcrt``) on
``budget-ledger.lock`` in the repository directory. Appends from ``tine budget``,
the hooks and the ``tine record`` proxy therefore chain one after another, and
the proxy's read-decide-reserve step is atomic, so concurrent requests cannot
both pass a cap that only one of them fits under.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_GUARD = threading.RLock()
_DEPTH = threading.local()


@contextmanager
def locked(repo: Any) -> Iterator[None]:
    from opentine.remote._audit import audit_file_lock
    from opentine.repository._paths import internal_path

    with _GUARD:
        depth = getattr(_DEPTH, "n", 0)
        if depth:
            _DEPTH.n = depth + 1
            try:
                yield
            finally:
                _DEPTH.n = depth
            return
        path = Path(internal_path(repo.path, "budget-ledger.lock"))
        with audit_file_lock(path):
            _DEPTH.n = 1
            try:
                yield
            finally:
                _DEPTH.n = 0


__all__ = ["locked"]
