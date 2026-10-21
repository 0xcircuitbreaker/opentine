"""Which action-index files this machine may trust, and how they are opened.

An index is a cache that can arrive with a cloned tree or an extracted archive.
Two things follow:

* Its rows are trusted only if this machine wrote them. Every index records a
  stamp keyed with a random per-user secret kept outside any repository
  (``$XDG_CONFIG_HOME/opentine/actions-index.key``); a shipped file carries some
  other stamp and is rebuilt from the runs, so planted rows cannot forge or hide
  attribution in ``who``, ``touched`` or ``find_actions``.
* Its path is never followed through a link. A symlinked, junctioned or
  non-regular ``actions.sqlite`` (or runs directory) is refused, the database
  is opened with SQLite's ``nofollow``, and a file that is not opentine's own
  index is replaced -- never altered in place -- so a link to some other
  database cannot have its tables emptied.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
from pathlib import Path
from urllib.parse import quote

KEY_NAME = "actions-index.key"


def _key_path() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", KEY_NAME)


def local_key() -> bytes:
    """This user's index secret, created on first use (0600)."""
    path = _key_path()
    try:
        data = path.read_bytes().strip()
        if len(data) >= 32:
            return data
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32).encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(token)
    return token


def keyed_stamp(stamp: str, location: str) -> str:
    """*stamp* bound to this machine's secret and the index location."""
    mac = hmac.new(local_key(), f"{stamp}\0{location}".encode(), hashlib.sha256)
    return f"{stamp}:{mac.hexdigest()}"


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    junction = getattr(path, "is_junction", None)
    return bool(junction and junction())


def check_location(path: Path) -> None:
    """Refuse an index path (or its directory) that is a link or not a regular file."""
    if _is_link(path.parent) or _is_link(path):
        raise ValueError(f"action index path {path.name!r} is a link; refusing to open it")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"action index path {path.name!r} is not a regular file")


def connect(path: Path) -> sqlite3.Connection:
    """Open *path* without following links (SQLite ``nofollow``)."""
    uri = f"file:{quote(str(path.absolute()))}?nofollow=1"
    return sqlite3.connect(uri, uri=True)


def discard(path: Path) -> None:
    """Remove a foreign or damaged index file (a regular file, checked first)."""
    check_location(path)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


__all__ = ["check_location", "connect", "discard", "keyed_stamp", "local_key"]
