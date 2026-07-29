"""Bounded reads for portable ``.tine`` artifacts."""

from __future__ import annotations

import json
import math
import re
import stat
from pathlib import Path
from typing import Any

from opentine.kernel import KernelError, validate_json_shape

MAX_TINE_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TINE_INTEGER_DIGITS = 4096

#: Structural tokens permitted per byte of artifact. A container costs ~2 bytes on
#: disk but ~64 bytes once materialized, so a dense all-``{}`` payload amplifies
#: roughly 32x; capping density is what makes that attack unprofitable. Real runs
#: sit at ~0.06 tokens/byte regardless of length, so this leaves ~4x headroom.
_MAX_TOKEN_DENSITY = 4

#: Floor for small artifacts, and absolute ceiling so that even a maximally dense
#: 256 MiB artifact cannot be materialized without bound.
_MIN_STRUCTURAL_TOKENS = 200_000
_MAX_STRUCTURAL_TOKENS = 16_000_000


def _structural_token_budget(length: int) -> int:
    """Bound structure relative to size, so writable runs stay readable.

    A single fixed cap cannot do both jobs: set low enough to stop amplification
    it also rejects long-but-ordinary runs, which is worse than the attack it
    prevents — ``Run.save()`` would persist a ~20k-step artifact that no longer
    loads, silently destroying the run.
    """
    return min(_MAX_STRUCTURAL_TOKENS, max(_MIN_STRUCTURAL_TOKENS, length // _MAX_TOKEN_DENSITY))


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


_OVERSIZED_INTEGER = re.compile(rb"(?<![\w.])-?\d{%d,}" % (MAX_TINE_INTEGER_DIGITS + 1))


def assert_loadable(serialized: str) -> None:
    """Refuse to persist an artifact this build could never read back.

    The reader bounds nesting depth and integer width and the writer did not, so a
    deeply nested tool result or a large integer produced a file that saved
    cleanly and then failed every later load, verify and migrate — destroying the
    run it was written to preserve. Failing at save leaves the run in memory,
    where the caller can still do something about it.
    """
    encoded = serialized.encode()
    try:
        validate_json_shape(encoded, max_tokens=_structural_token_budget(len(encoded)))
    except KernelError as exc:
        raise ValueError(
            "run nesting or structure exceeds what a .tine artifact can hold; "
            "flatten the offending step input before saving"
        ) from exc
    if _OVERSIZED_INTEGER.search(encoded):
        raise ValueError(
            f"integer exceeds the {MAX_TINE_INTEGER_DIGITS}-digit .tine limit; store it as a string"
        )


def parse_artifact_json(raw: bytes | str) -> Any:
    """Decode portable JSON while refusing parser-differential constructs."""

    if isinstance(raw, bytes) and b"\0" in raw:
        raise ValueError(".tine artifacts must use UTF-8 JSON")
    try:
        validate_json_shape(raw, max_tokens=_structural_token_budget(len(raw)))
    except KernelError as exc:
        raise ValueError(
            ".tine artifact nesting exceeds the parser limit or structure is excessive"
        ) from exc

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
