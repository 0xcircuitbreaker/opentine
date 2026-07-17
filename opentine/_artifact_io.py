"""Bounded reads for portable ``.tine`` artifacts."""

from __future__ import annotations

import json
import math
import stat
from pathlib import Path
from typing import Any

MAX_TINE_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TINE_JSON_DEPTH = 512
MAX_TINE_INTEGER_DIGITS = 4096


def _reject_excessive_nesting(raw: bytes | str) -> None:
    """Bound JSON container depth before version-dependent decoders run."""
    if isinstance(raw, bytes):
        if b"\0" in raw:
            raise ValueError(".tine artifacts must use UTF-8 JSON")
        quote, slash, opening, closing = 0x22, 0x5C, (0x5B, 0x7B), (0x5D, 0x7D)
    else:
        quote, slash, opening, closing = '"', "\\", ("[", "{"), ("]", "}")
    depth = 0
    in_string = False
    escaped = False
    for token in raw:
        if in_string:
            if escaped:
                escaped = False
            elif token == slash:
                escaped = True
            elif token == quote:
                in_string = False
        elif token == quote:
            in_string = True
        elif token in opening:
            depth += 1
            if depth > MAX_TINE_JSON_DEPTH:
                raise ValueError(".tine artifact nesting exceeds the parser limit")
        elif token in closing:
            depth -= 1


def artifact_integrity(data: dict[str, Any]) -> dict[str, Any] | None:
    """Return a structurally valid integrity block, otherwise ``None``."""
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return None
    integrity = metadata.get("integrity")
    return integrity if isinstance(integrity, dict) else None


def artifact_digest(data: dict[str, Any]) -> str | None:
    """Compute a legacy digest without propagating malformed in-memory values."""
    from opentine._canon import _integrity_digest

    try:
        return _integrity_digest(data)
    except (AttributeError, RecursionError, TypeError, ValueError):
        return None


def read_artifact_bytes(path: str | Path) -> bytes:
    """Read one regular artifact without allowing unbounded client memory use."""
    source = Path(path)
    info = source.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(".tine artifact must be a regular file")
    if info.st_size > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(".tine artifact exceeds the 256 MiB size limit")
    with source.open("rb") as handle:
        raw = handle.read(MAX_TINE_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(".tine artifact exceeds the 256 MiB size limit")
    return raw


def parse_artifact_json(raw: bytes | str) -> Any:
    """Decode portable JSON while refusing parser-differential constructs."""

    _reject_excessive_nesting(raw)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate .tine object key: {key[:80]!r}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError(f"non-finite number in .tine artifact: {value}")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            constant(value)
        return number

    def bounded_int(value: str) -> int:
        if len(value.removeprefix("-")) > MAX_TINE_INTEGER_DIGITS:
            raise ValueError("integer in .tine artifact exceeds the parser limit")
        return int(value)

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=finite_float,
            parse_int=bounded_int,
        )
    except RecursionError as exc:
        raise ValueError(".tine artifact nesting exceeds the parser limit") from exc


def read_artifact_json(path: str | Path) -> Any:
    """Decode a bounded portable artifact as JSON."""
    return parse_artifact_json(read_artifact_bytes(path))
