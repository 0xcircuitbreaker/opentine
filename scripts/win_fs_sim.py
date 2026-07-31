"""Pytest plugin that makes a Linux run reject the paths Windows would reject.

Windows filesystem semantics differ from POSIX in ways that only surface on
windows-latest CI: several characters are illegal in a filename, a lone UTF-16
surrogate cannot be encoded, a component may not end in a dot or space, and a
handful of device names are reserved. A test that names a temp file or
directory after a hostile *subject* string passes on Linux and fails at the
filesystem layer on Windows, before the code under test runs.

Enable it with `-p win_fs_sim` (and put this file on sys.path, e.g. via
`PYTHONPATH=scripts`). It wraps the low-level filesystem entry points and
raises the same OSError family Windows raises, so the path-naming class of
Windows failures reproduces locally. It does NOT model POSIX file modes,
text-mode CRLF growth, or rename-onto-open-handle — reason about those.
"""

from __future__ import annotations

import os
import re

_ILLEGAL = set('<>:"|?*') | {chr(c) for c in range(32)}
_RESERVED = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def _lone_surrogate(part: str) -> bool:
    try:
        part.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def _check(path) -> None:
    if isinstance(path, int):
        return
    try:
        text = os.fspath(path)
    except TypeError:
        return
    if isinstance(text, bytes):
        return
    # Windows treats both separators; split on each so a literal backslash in a
    # Linux filename is judged the way Windows would read it.
    for part in re.split(r"[\\/]+", text):
        if not part or part in (".", ".."):
            continue
        if any(ch in _ILLEGAL for ch in part):
            raise OSError(22, "simulated-windows: invalid filename character", text)
        if _lone_surrogate(part):
            raise FileNotFoundError(3, "simulated-windows: path cannot be encoded", text)
        if part[-1] in {" ", "."}:
            raise OSError(123, "simulated-windows: trailing dot or space", text)
        if part.split(".", 1)[0].upper() in _RESERVED:
            raise OSError(22, "simulated-windows: reserved device name", text)


def pytest_configure(config) -> None:  # noqa: ARG001
    _install()


def _guard1(real):
    def wrapper(path, *a, **k):
        _check(path)
        return real(path, *a, **k)

    return wrapper


def _guard2(real):
    def wrapper(src, dst, *a, **k):
        _check(src)
        _check(dst)
        return real(src, dst, *a, **k)

    return wrapper


def _method1(real):
    def wrapper(self, *a, **k):
        _check(self)
        return real(self, *a, **k)

    return wrapper


def _install() -> None:
    import builtins
    import io
    import pathlib

    # Low-level (tempfile.mkstemp uses os.open directly).
    os.open = _guard1(os.open)
    os.mkdir = _guard1(os.mkdir)
    os.makedirs = _guard1(os.makedirs)
    os.rename = _guard2(os.rename)
    os.replace = _guard2(os.replace)

    # builtins.open and io.open are the same object but reached by different
    # names; patch both so open() and pathlib's io.open are covered.
    guarded_open = _guard1(builtins.open)
    builtins.open = guarded_open
    io.open = guarded_open

    # pathlib rewired its internals across 3.11-3.14, so guard the Path methods
    # the tests actually call rather than trusting they route through the above.
    for name in ("mkdir", "open", "write_text", "write_bytes", "touch"):
        setattr(pathlib.Path, name, _method1(getattr(pathlib.Path, name)))
