"""Dependency-free canonicalization, integrity, redaction, and atomic IO.

This module is the shared base that ``graph``, ``migrations``, and ``signing``
all import *downward* from. It must not import any other ``opentine`` module, so
that the format/migration/signing layers can reuse canonical hashing without
creating import cycles.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import asdict, is_dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

#: Current on-disk ``.tine`` format version written by this build.
FORMAT_VERSION = 2

#: Versions this build can read. A file at an older supported version is
#: migrated in memory on load; a newer version is refused.
SUPPORTED_VERSIONS: tuple[int, ...] = (1, 2)


def _jsonable(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()


def _integrity_digest(data: dict[str, Any]) -> str:
    """SHA-256 over the canonical artifact body, excluding the ``metadata`` key.

    The exclusion of ``metadata`` is a deliberate, longstanding boundary: it lets
    the digest live *inside* ``metadata.integrity`` without self-reference. Every
    other top-level key (``format_version``, ``graph``, ``manifest``, ``draft``,
    ...) is covered.
    """
    digest_payload = {k: v for k, v in data.items() if k != "metadata"}
    return hashlib.sha256(_canonical_bytes(digest_payload)).hexdigest()


def _redact(value: Any) -> Any:
    """Replace values whose *key* name suggests a secret.

    NOTE: this matches dict *keys* by substring, so any serialized field whose
    key contains one of these words has its value blown away on save. Persisted
    numeric/structural fields must therefore avoid these substrings in their keys
    (e.g. use ``usage``/``max_usage`` rather than ``tokens``/``max_tokens``).
    """
    secret_words = ("key", "secret", "token", "password", "credential", "auth")
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if any(w in str(k).lower() for w in secret_words) else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def atomic_write_text(path: str | Path, text: str, *, fsync: bool = False) -> Path:
    """Write ``text`` to ``path`` atomically.

    A temp file is written in the target's own directory and ``os.replace``-d
    into place, so a crash mid-write never leaves a half-written ``.tine``. The
    text is written with ``newline=None`` text-mode semantics to stay byte-for-
    byte compatible with the previous ``Path.write_text`` call (matters for the
    golden-fixture round-trip on Windows CI). Mode is copied from an existing
    target so re-saves preserve permissions.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        # newline=None (the default) replicates Path.write_text's translation.
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            if fsync:
                handle.flush()
                os.fsync(handle.fileno())
        try:
            existing_mode = stat.S_IMODE(os.stat(p).st_mode)
            os.chmod(tmp, existing_mode)
        except FileNotFoundError:
            pass
        os.replace(tmp, p)
        if fsync:
            _fsync_dir(p.parent)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return p


def _fsync_dir(directory: Path) -> None:
    try:
        dir_fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)
