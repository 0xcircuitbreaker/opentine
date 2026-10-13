"""Field names a run's own redaction policy adds to the write-side walk.

``RedactionPolicy.extra_secret_keys`` was recorded with a run and read by
nothing, so a field the host had named as secret reached the ``.tine`` file and
the repository verbatim. A run's writers now hold these names for the duration
of the write (``secret_keys``), and ``_canon_redact._redact`` treats them like
its own credential names. A leaf like ``_canon_redact``: standard library only.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_EXTRA: ContextVar[frozenset[str]] = ContextVar("opentine_extra_secret_keys", default=frozenset())


def extra_secret_names() -> frozenset[str]:
    return _EXTRA.get()


@contextmanager
def secret_keys(names: Iterable[str]) -> Iterator[None]:
    """Redact these normalized field names in every write inside the block."""
    token = _EXTRA.set(_EXTRA.get() | frozenset(names))
    try:
        yield
    finally:
        _EXTRA.reset(token)
