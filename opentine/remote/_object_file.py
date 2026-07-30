"""Bounded no-follow reads for encrypted filesystem objects."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from opentine.repository.pack import MAX_PACK_BYTES

MAX_ENCRYPTED_OBJECT_BYTES = MAX_PACK_BYTES
_READ_CHUNK = 64 * 1024


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("object path is not a single-link regular file")
    # O_BINARY (Windows-only, 0 elsewhere): the fd is read with raw os.read, so
    # without it Windows opens text-mode and mangles the encrypted body — CRLF
    # translation and a 0x1A EOF truncation corrupt the AES-GCM ciphertext,
    # leaving decrypt with a short nonce. Local readers escape this by wrapping
    # in os.fdopen(fd, "rb"), which _setmode's the fd binary; this path does not.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError("object path cannot be opened safely") from exc
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
    ):
        os.close(fd)
        raise ValueError("object path is not a single-link regular file")
    return fd, info


def object_file_size(path: Path, limit: int = MAX_ENCRYPTED_OBJECT_BYTES) -> int:
    fd, info = _open_regular(path)
    try:
        if info.st_size > limit:
            raise ValueError("encrypted object exceeds its size limit")
        return info.st_size
    finally:
        os.close(fd)


def read_object_file(path: Path, limit: int = MAX_ENCRYPTED_OBJECT_BYTES) -> bytes:
    fd, info = _open_regular(path)
    try:
        if info.st_size > limit:
            raise ValueError("encrypted object exceeds its size limit")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(_READ_CHUNK, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError("encrypted object exceeds its size limit")
        return bytes(data)
    finally:
        os.close(fd)
