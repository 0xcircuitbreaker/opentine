"""Bounded shallow-boundary storage for local repositories."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from opentine.kernel import KernelError, parse_oid

MAX_SHALLOW_OBJECTS = 10_000
MAX_SHALLOW_BYTES = 1024 * 1024
Fingerprint = tuple[int, int, int, int, int]


def _fingerprint(info: os.stat_result) -> Fingerprint:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise KernelError("shallow boundary state must be a private regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def shallow_fingerprint(path: Path) -> Fingerprint | None:
    try:
        return _fingerprint(path.lstat())
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KernelError("shallow boundary state cannot be inspected") from exc


def _decode(data: bytes) -> frozenset[str]:
    if len(data) > MAX_SHALLOW_BYTES:
        raise KernelError("shallow boundary state exceeds its byte limit")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise KernelError("shallow boundary state must be ASCII") from exc
    if "\r" in text:
        raise KernelError("shallow boundary state has invalid line endings")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if any(not line for line in lines):
        raise KernelError("shallow boundary state contains an empty object id")
    if len(lines) > MAX_SHALLOW_OBJECTS:
        raise KernelError("shallow boundary state exceeds its object limit")
    for oid in lines:
        parse_oid(oid)
    if len(set(lines)) != len(lines):
        raise KernelError("shallow boundary state contains duplicate object ids")
    return frozenset(lines)


def read_shallow(path: Path) -> tuple[Fingerprint | None, frozenset[str]]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None, frozenset()
    except OSError as exc:
        raise KernelError("shallow boundary state cannot be safely read") from exc
    try:
        info = os.fstat(fd)
        fingerprint = _fingerprint(info)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(MAX_SHALLOW_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    return fingerprint, _decode(data)


def encode_shallow(values: Iterable[str]) -> bytes:
    unique: set[str] = set()
    for oid in values:
        parse_oid(oid)
        unique.add(oid)
        if len(unique) > MAX_SHALLOW_OBJECTS:
            raise KernelError("shallow boundary state exceeds its object limit")
    body = ("\n".join(sorted(unique)) + ("\n" if unique else "")).encode("ascii")
    if len(body) > MAX_SHALLOW_BYTES:
        raise KernelError("shallow boundary state exceeds its byte limit")
    return body


@contextmanager
def shallow_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise KernelError("shallow boundary state is locked by a concurrent import") from exc
    try:
        os.close(fd)
        yield
    finally:
        lock_path.unlink(missing_ok=True)
