"""Dependency-free canonicalization, integrity, redaction, and atomic IO.

This module is the shared base that ``graph``, ``migrations``, and ``signing``
all import *downward* from. It must not import any other ``opentine`` module, so
that the format/migration/signing layers can reuse canonical hashing without
creating import cycles.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
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
    """
    digest_payload = {k: v for k, v in data.items() if k != "metadata"}
    return hashlib.sha256(_canonical_bytes(digest_payload)).hexdigest()


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _field_name(value: Any) -> str:
    # Quotes stripped so a JSON fragment in free text ('"api_key": "sk-…"') names
    # the same field as the bare form; v3 handles it, v2 stored the secret.
    return _CAMEL_BOUNDARY.sub("_", str(value).strip().strip("\"'")).lower().replace("-", "_")


def _secret_field(name: str, credential_names: set[str], suffixes: tuple[str, ...]) -> bool:
    candidates = (name, name[:-1]) if name.endswith("s") else (name,)
    compact_suffixes = tuple(suffix.replace("_", "") for suffix in suffixes)
    return any(
        item in credential_names
        or item.endswith(suffixes)
        or item.replace("_", "").endswith(compact_suffixes)
        for item in candidates
    )


def _split_assignment(text: str) -> tuple[str, str, str]:
    """Split on whichever of ``:``/``=`` comes *first*, not on whichever exists.

    A value may contain the other (``api_key=sk-proj:abc``); splitting on the later
    one buries the credential name in the label and leaks the secret.
    """
    at = min((i for i in (text.find(":"), text.find("=")) if i >= 0), default=-1)
    if at < 0:
        return text, "", ""
    return text[:at], text[at], text[at + 1 :]


def _redact(value: Any) -> Any:
    """Redact credential fields without deleting numeric usage dimensions."""
    credential_names = set(
        (
            "api_key apikey api_token access_key secret_access_key secret_key access_token "
            "refresh_token auth_token bearer_token id_token session_token password passwd "
            "passphrase secret client_secret private_key credential credentials authorization "
            "proxy_authorization cookie set_cookie"
        ).split()
    )
    suffixes = (
        "_api_key",
        "_api_token",
        "_access_key",
        "_access_token",
        "_authorization",
        "_auth_token",
        "_bearer_token",
        "_client_secret",
        "_cookie",
        "_credential",
        "_credentials",
        "_id_token",
        "_passphrase",
        "_password",
        "_passwd",
        "_private_key",
        "_proxy_authorization",
        "_refresh_token",
        "_secret",
        "_session_token",
        "_secret_key",
        "_set_cookie",
    )
    if isinstance(value, dict):
        header_names = [item for key, item in value.items() if _field_name(key) == "name"]
        header_values = {key for key in value if _field_name(key) == "value"}
        secret_header = any(
            isinstance(item, str)
            and (
                _field_name(item) == "token"
                or _secret_field(_field_name(item), credential_names, suffixes)
            )
            for item in header_names
        )
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            name = _field_name(key)
            is_secret = _secret_field(name, credential_names, suffixes) or (
                key in header_values and secret_header
            )
            if name == "token" and not isinstance(item, (int, float)):
                is_secret = True
            redacted[key] = "[REDACTED]" if is_secret else _redact(item)
        return redacted
    if isinstance(value, (list, tuple)):
        items = list(value)
        headers = {"authorization", "proxy_authorization", "cookie", "set_cookie"}
        if len(items) == 2 and isinstance(items[0], str):
            name = _field_name(items[0])
            if (
                name == "token"
                or name in headers
                or _secret_field(name, credential_names, suffixes)
            ):
                return [items[0], "[REDACTED]"]
        redacted = []
        for item in items:
            if isinstance(item, str) and (":" in item or "=" in item):
                name, separator, _ = _split_assignment(item)
                if _field_name(name) in headers | {"token"}:
                    redacted.append(name + separator + " [REDACTED]")
                    continue
            redacted.append(_redact(item))
        return redacted
    if isinstance(value, str) and (":" in value or "=" in value):
        label, separator, candidate = _split_assignment(value)
        name = _field_name(label)
        headers = {"authorization", "proxy_authorization", "cookie", "set_cookie"}
        words = candidate.strip().casefold().split()
        questions = {"can", "could", "how", "should", "what", "when", "where", "which", "why"}
        articles = {"a", "an", "the", "this"}
        header_nouns = {"field", "header", "label", "setting", "value"}
        prose = bool(words) and (
            words[0] in questions
            or (len(words) > 1 and words[0] in articles and words[1] in header_nouns)
        )
        # Bare "token" is not a credential name (counters must survive), but a
        # *quoted* value is no counter — same rule the dict branch applies.
        if name in headers or (name == "token" and candidate.strip()[:1] in {'"', "'"}):
            return label + separator + " [REDACTED]"
        if _secret_field(name, credential_names, suffixes) and not prose:
            return label + separator + " [REDACTED]"
    return value


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
