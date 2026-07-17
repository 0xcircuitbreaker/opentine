"""Authenticated framing for encrypted resumable-upload staging."""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

from opentine.remote.interfaces import KeyProvider

_LENGTH = struct.Struct(">I")
_OFFSET = struct.Struct(">Q")
_PLAIN_CHUNK = 1024 * 1024
_MAX_OVERHEAD = 4096
_MAX_CIPHER = _OFFSET.size + _PLAIN_CHUNK + _MAX_OVERHEAD


def spool_bound(declared_size: int) -> int:
    return declared_size * 2 + 64 * 1024


def _open_regular(path: Path, flags: int, mode: str):
    fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("encrypted upload spool is not a regular file")
    return os.fdopen(fd, mode)


def append_frames(
    path: Path,
    keys: KeyProvider,
    tenant: str,
    offset: int,
    chunk: bytes,
    declared_size: int,
) -> tuple[int, int]:
    """Append independently authenticated frames and return logical/file offsets."""
    if not 0 <= offset <= offset + len(chunk) <= declared_size:
        raise ValueError("encrypted upload append exceeds its declared size")
    with _open_regular(path, os.O_WRONLY | os.O_APPEND, "ab") as handle:
        for start in range(0, len(chunk), _PLAIN_CHUNK):
            piece = chunk[start : start + _PLAIN_CHUNK]
            ciphertext = keys.encrypt(tenant, _OFFSET.pack(offset) + piece)
            if (
                not isinstance(ciphertext, bytes)
                or not 0 < len(ciphertext) <= min(_MAX_CIPHER, len(piece) + 8 + _MAX_OVERHEAD)
                or handle.tell() + _LENGTH.size + len(ciphertext) > spool_bound(declared_size)
            ):
                raise ValueError("staging key provider returned an invalid ciphertext")
            handle.write(_LENGTH.pack(len(ciphertext)))
            handle.write(ciphertext)
            offset += len(piece)
        handle.flush()
        os.fsync(handle.fileno())
        return offset, handle.tell()


def read_frames(
    path: Path,
    keys: KeyProvider,
    tenant: str,
    declared_size: int,
    *,
    repair_tail: bool,
) -> tuple[bytes, int]:
    """Decrypt frames, optionally discarding an incomplete crash tail."""
    plaintext = bytearray()
    valid_end = 0
    incomplete = False
    with _open_regular(path, os.O_RDONLY, "rb") as handle:
        if os.fstat(handle.fileno()).st_size > spool_bound(declared_size):
            raise ValueError("encrypted upload spool exceeds its declared bound")
        while True:
            header = handle.read(_LENGTH.size)
            if not header:
                break
            if len(header) != _LENGTH.size:
                incomplete = True
                break
            length = _LENGTH.unpack(header)[0]
            if not 0 < length <= _MAX_CIPHER:
                raise ValueError("encrypted upload frame length is invalid")
            ciphertext = handle.read(length)
            if len(ciphertext) != length:
                incomplete = True
                break
            frame = keys.decrypt(tenant, ciphertext)
            if (
                not isinstance(frame, bytes)
                or not _OFFSET.size < len(frame) <= _OFFSET.size + _PLAIN_CHUNK
                or length > len(frame) + _MAX_OVERHEAD
            ):
                raise ValueError("encrypted upload frame is invalid")
            expected = _OFFSET.unpack(frame[: _OFFSET.size])[0]
            if expected != len(plaintext):
                raise ValueError("encrypted upload frame offset is invalid")
            plaintext.extend(frame[_OFFSET.size :])
            if len(plaintext) > declared_size:
                raise ValueError("encrypted upload exceeds its declared size")
            valid_end = handle.tell()
    if incomplete:
        if not repair_tail:
            raise ValueError("encrypted upload has an incomplete frame")
        with _open_regular(path, os.O_RDWR, "r+b") as handle:
            handle.truncate(valid_end)
            handle.flush()
            os.fsync(handle.fileno())
    return bytes(plaintext), valid_end
