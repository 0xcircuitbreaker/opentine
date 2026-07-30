"""Bounded reads for portable ``.tine`` artifacts."""

from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any

import opentine._artifact_shapes as artifact_shapes
from opentine._canon import SUPPORTED_VERSIONS
from opentine._unicode_text import SURROGATE_TEXT, assert_unicode_text, surrogate_suspect
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


def _structural_token_budget(length: int, *, density: int = _MAX_TOKEN_DENSITY) -> int:
    """Bound structure relative to size, so writable runs stay readable.

    A single fixed cap cannot do both jobs: set low enough to stop amplification
    it also rejects long-but-ordinary runs, which is worse than the attack it
    prevents — ``Run.save()`` would persist a ~20k-step artifact that no longer
    loads, silently destroying the run.
    """
    return min(_MAX_STRUCTURAL_TOKENS, max(_MIN_STRUCTURAL_TOKENS, length // density))


def compact_token_budget(length: int) -> int:
    """Structural-token budget for *compact* canonical JSON (repository blobs).

    One formula, both sides: ``guarded_blob_body`` (writer) and ``blob_json``
    (reader) must call this on the same body bytes, or a run wide enough to save
    is no longer narrow enough to load — round 8 fixed that asymmetry with a
    fixed 200k cap and thereby made ``tine migrate-v3`` refuse healthy ``.tine``
    artifacts this build round-trips (a ~590 KB structured tool result).

    Compact canonical JSON has no padding: every structural token is exactly one
    byte, so tokens can never exceed bytes and any density divisor above 1
    refuses legal payloads (a matrix of small integers runs ~0.5-0.8
    tokens/byte). Bytes are therefore the honest density bound, and what stops
    container amplification is the same absolute ceiling and floor the ``.tine``
    reader enforces above.
    """
    return _structural_token_budget(length, density=1)


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


def _bounded_int(value: str) -> int:
    if len(value.removeprefix("-")) > MAX_TINE_INTEGER_DIGITS:
        raise ValueError("integer in .tine artifact exceeds the parser limit")
    return int(value)


def assert_loadable(serialized: str) -> None:
    """Refuse to persist an artifact this build could never read back.

    Every reader bound must hold at write, not just some: size (256 MiB),
    nesting depth and structural tokens, integer width, well-formed Unicode text,
    format version, and the run/step record shapes ``load_run`` validates. Each
    rule enforced on read but not on write produced a file that saved cleanly and
    then failed every later load, verify and migrate — destroying the run it was
    written to preserve. Failing at save leaves the run in memory, where the caller
    can still do something about it. (Duplicate keys, NaN/Infinity, and raw NUL
    bytes are unproducible by construction: ``json.dumps(sort_keys=True,
    allow_nan=False)`` raises on the first two and escapes control characters.)
    """
    # surrogatepass only so the byte accounting below cannot itself raise a bare
    # codec error: an unencodable str is refused after the parse, with its path.
    encoded = serialized.encode(errors="surrogatepass")
    # atomic_write_text writes in text mode, so every newline becomes
    # os.linesep on disk; budget what the reader will stat, not what the
    # writer holds in memory.
    on_disk = len(encoded) + serialized.count("\n") * (len(os.linesep) - 1)
    if on_disk > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(
            ".tine artifact would exceed the size limit every reader enforces "
            f"({MAX_TINE_ARTIFACT_BYTES} bytes); split the run or save it into "
            "a v3 repository instead"
        )
    try:
        validate_json_shape(encoded, max_tokens=_structural_token_budget(len(encoded)))
    except KernelError as exc:
        raise ValueError(
            "run nesting or structure exceeds what a .tine artifact can hold; "
            "flatten the offending step input before saving"
        ) from exc
    # Bound integers with the reader's own parse hook, which only sees number
    # *literals*: a long digit run inside a JSON string — json_safe's own big-int
    # representation — must save, and a byte-level regex cannot tell the two
    # apart, so it rejected runs this build reads back verbatim.
    try:
        parsed = json.loads(serialized, parse_int=_bounded_int)
    except ValueError as exc:
        raise ValueError(
            f"integer exceeds the {MAX_TINE_INTEGER_DIGITS}-digit .tine limit; store it as a string"
        ) from exc
    # ``json.dumps`` escapes a lone surrogate back to ASCII, so the encode above
    # never sees it: only a walk of the parsed values can catch what would later
    # break canonicalization, the search index, and every non-Python reader.
    if SURROGATE_TEXT.search(serialized):
        assert_unicode_text(parsed, where="this run")
    # Run the reader's own record validation: a list-valued step output or a
    # non-string tag wrote cleanly and then failed every later load with the
    # exact messages raised below.
    record = artifact_shapes.validate_run_record(parsed)
    artifact_shapes.ordered_step_records(record.get("graph", {}))
    version = record.get("format_version")
    if type(version) is not int or version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f".tine format_version must be one of {SUPPORTED_VERSIONS} to load back; "
            f"got {version!r}"
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

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=finite_float,
            parse_int=_bounded_int,
        )
    except RecursionError as exc:
        raise ValueError(".tine artifact nesting exceeds the parser limit") from exc
    # An unpaired surrogate is a parser differential like the three above: this
    # reader would hand back a str no other implementation reconstructs, and that
    # neither the digest nor the v3 canonical form can be computed over. A file
    # holding one is refused here so the failure is typed and contained — the index
    # marks that one archive unreadable instead of the whole directory failing, and
    # the bytes stay on disk, repairable, with the field path named.
    if surrogate_suspect(raw):
        assert_unicode_text(parsed, where=".tine artifact")
    return parsed


def read_artifact_json(path: str | Path) -> Any:
    """Decode a bounded portable artifact as JSON."""
    return parse_artifact_json(read_artifact_bytes(path))
