"""Keyed audit chaining with an authenticated head outside SQLite."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

from opentine._canon import _fsync_dir, atomic_write_text
from opentine.kernel import canonical_json

#: All-zero hash that seeds an empty chain.
GENESIS = "0" * 64

#: Column order used for both writing and verifying a row's committed body.
FIELDS = ("action", "actor", "details", "event_id", "outcome", "tenant", "timestamp")


def chain(prev_hash: str, row: dict[str, str], key: bytes) -> str:
    """Return the keyed hash committing ``row`` to ``prev_hash``."""
    body = canonical_json({field: row[field] for field in FIELDS})
    return hmac.new(key, bytes.fromhex(prev_hash) + body, hashlib.sha256).hexdigest()


def _anchor_mac(head: str, key: bytes) -> str:
    return hmac.new(key, b"opentine.audit-anchor.v1\0" + head.encode(), hashlib.sha256).hexdigest()


def _read_small(path: Path, maximum: int, *, private: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError("stored audit sidecar cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("stored audit sidecar is not a regular file")
        if private and stat.S_IMODE(info.st_mode) != 0o600 and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
    finally:
        os.close(fd)
    if len(value) > maximum:
        raise RuntimeError(f"stored audit sidecar exceeds {maximum} bytes")
    return value


def load_key(path: Path, supplied: bytes | None) -> tuple[bytes, bool]:
    if supplied is not None:
        if not isinstance(supplied, bytes) or len(supplied) < 16:
            raise ValueError("audit HMAC key must contain at least 16 bytes")
        return supplied, False
    try:
        key = _read_small(path, 64, private=True)
        created = False
    except FileNotFoundError:
        key = os.urandom(32)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            key, created = _read_small(path, 64, private=True), False
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_dir(path.parent)
            created = True
    if len(key) < 16:
        raise RuntimeError("stored audit HMAC key is invalid")
    return key, created


def read_anchor(path: Path, key: bytes) -> str | None:
    try:
        value = json.loads(_read_small(path, 4096))
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("stored audit anchor is malformed") from exc
    algorithm = value.get("algorithm") if isinstance(value, dict) else None
    head = value.get("head") if isinstance(value, dict) else None
    mac = value.get("mac") if isinstance(value, dict) else None
    if (
        algorithm != "hmac-sha256"
        or not isinstance(head, str)
        or len(head) != 64
        or not isinstance(mac, str)
        or not hmac.compare_digest(mac, _anchor_mac(head, key))
    ):
        raise RuntimeError("stored audit anchor failed authentication")
    return head


def write_anchor(path: Path, head: str, key: bytes) -> None:
    value = {"algorithm": "hmac-sha256", "head": head, "mac": _anchor_mac(head, key)}
    atomic_write_text(path, json.dumps(value, sort_keys=True, separators=(",", ":")), fsync=True)
