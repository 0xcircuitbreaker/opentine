"""Dependency-free canonicalization, integrity, redaction, and atomic IO.

This module is the shared base that ``graph``, ``migrations``, and ``signing``
all import *downward* from. It must not import any ``opentine`` module other than
its own stdlib-only leaf ``_canon_redact``, so that the format/migration/signing
layers can reuse canonical hashing without creating import cycles.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
from dataclasses import fields, is_dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from opentine._canon_redact import MAX_CANONICAL_DEPTH, _redact, _too_deep

#: Current on-disk ``.tine`` format version written by this build.
FORMAT_VERSION = 2

#: Versions this build can read. A file at an older supported version is
#: migrated in memory on load; a newer version is refused.
SUPPORTED_VERSIONS: tuple[int, ...] = (1, 2)

#: ``_redact`` and the bound it shares with ``_jsonable`` are re-exported: eight
#: modules import ``_redact`` from here, and this is the module the layering
#: docstring above names as the base.
__all__ = [
    "FORMAT_VERSION",
    "MAX_CANONICAL_DEPTH",
    "SUPPORTED_VERSIONS",
    "_canonical_bytes",
    "_integrity_digest",
    "_jsonable",
    "_redact",
    "atomic_write_text",
]


def _jsonable(value: Any, _depth: int = 0) -> Any:
    if _depth > MAX_CANONICAL_DEPTH:
        raise _too_deep()
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        # Field by field rather than asdict(): through 3.12 asdict deep-copies
        # every nested container, and deepcopy's own unbounded recursion died at
        # ~495 levels — before this bound could be reached, on 3.12 where the walk
        # below is fine, and not on 3.13+ where asdict stopped copying them, so
        # this branch had a third boundary of its own. Nested dataclasses, tuples
        # and mappings are converted one level down instead, for the same JSON;
        # the one shift is that a frozen dataclass used as a *key* now stringifies
        # the same way inside a dataclass as it already did inside a plain dict.
        # Fields are walked here rather than handed back to the dict branch so a
        # *chain* of nested dataclasses costs one frame and one depth level like
        # every other container: re-entering cost two frames per level while
        # counting one, so the bound below could never be reached and the chain
        # died with RecursionError at ~495 levels on every interpreter instead.
        # Sorted by name to keep the key order the dict branch produced.
        coerced_fields: dict[str, Any] = {}
        for item in sorted(fields(value), key=lambda field: field.name):
            coerced_fields[item.name] = _jsonable(getattr(value, item.name), _depth + 1)
        return coerced_fields
    if isinstance(value, dict):
        # Explicit loops, not comprehensions: before 3.12 a comprehension costs a
        # second frame per level, which is what made the depth at which this walk
        # failed differ 2x between the oldest supported interpreter and the rest.
        coerced: dict[str, Any] = {}
        for key, item in sorted(value.items(), key=lambda kv: str(kv[0])):
            coerced[str(key)] = _jsonable(item, _depth + 1)
        return coerced
    if isinstance(value, (list, tuple)):
        items: list[Any] = []
        for item in value:
            items.append(_jsonable(item, _depth + 1))
        return items
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("canonical JSON forbids NaN and infinity")
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

    That boundary is a *known* one: metadata can be rewritten and this digest
    still matches. It is not a hole in authenticity, because this digest never
    provided authenticity — it is unkeyed, so any editor can recompute it, and it
    means "consistent", not "genuine". Authenticity of metadata comes from the
    ``tine-sig/2`` signature (``opentine.signing``), which signs every metadata
    key but ``integrity``. Narrowing the exclusion here would change the stored
    digest of every artifact ever written and break the backwards-compat gate, so
    it is deferred to a future ``FORMAT_VERSION`` bump.
    """
    digest_payload = {k: v for k, v in data.items() if k != "metadata"}
    return hashlib.sha256(_canonical_bytes(digest_payload)).hexdigest()


def atomic_write_text(
    path: str | Path, text: str, *, fsync: bool = False, mode: int | None = None
) -> Path:
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
        if mode is not None:
            os.chmod(tmp, mode)
        else:
            try:
                os.chmod(tmp, stat.S_IMODE(os.stat(p).st_mode))
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
