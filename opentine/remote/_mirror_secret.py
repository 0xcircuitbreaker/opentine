"""Where a mirror keeps an upstream credential: never in ``link.json`` (0.55).

An upstream URL may carry ``user:token@`` (the supported way to mirror a
private https upstream). :func:`split` takes that userinfo off: the bare URL is
what ``link.json`` stores and what any label or response may show, and the
credential goes to ``<mirror>/credential``, created ``0600`` with no window in
which it is readable by others. Only the fetch reads it back
(:mod:`opentine._mirror_fetch`, as an ``Authorization`` header). Unlinking the
mirror deletes it with the rest of the directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

NAME = "credential"


def split(url: str) -> tuple[str, str | None]:
    """``(url without userinfo, "user:password" or None)``."""
    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url, None
    host = parts.netloc.rpartition("@")[2]
    bare = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    return bare, f"{unquote(parts.username or '')}:{unquote(parts.password or '')}"


def strip(url: str) -> str:
    return split(url)[0]


def save(place: Path, credential: str | None) -> None:
    path = Path(place) / NAME
    path.unlink(missing_ok=True)
    if credential is None:
        return
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o600)  # fmt: skip
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(credential)


def load(place: Path) -> str | None:
    try:
        return (Path(place) / NAME).read_text("utf-8")
    except FileNotFoundError:
        return None


__all__ = ["NAME", "load", "save", "split", "strip"]
