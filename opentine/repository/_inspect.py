"""Bounded verified rendering for repository object inspection."""

from __future__ import annotations

import base64
import json
import math
from typing import TYPE_CHECKING, Any

from opentine._artifact_io import compact_token_budget
from opentine.kernel import _parse_int, parse_oid, validate_json_shape
from opentine.redaction import redact_blob
from opentine.repository._blob_io import read_verified_blob_prefix, stored_object_size

if TYPE_CHECKING:
    from opentine.repository.store import Repo

MAX_INSPECT_BLOB_BYTES = 512 * 1024
MAX_INSPECT_SOURCE_BYTES = 256 * 1024 * 1024
MAX_INSPECT_RESOLVED_BYTES = 1024 * 1024
MAX_INSPECT_RESOLVED_BLOBS = 64
MAX_INSPECT_STRUCTURED_BYTES = 4 * 1024 * 1024


def _direct_blob(repo: Repo, oid: str) -> dict[str, Any]:
    raw, size, schema = read_verified_blob_prefix(
        repo,
        oid,
        prefix_limit=MAX_INSPECT_BLOB_BYTES,
        source_limit=MAX_INSPECT_SOURCE_BYTES,
    )
    truncated = size > len(raw)
    # Scrubbed, not served verbatim. The v2 migration blob below is stored with
    # ``redact=False`` and is the one body in the store that may still hold
    # credentials, and this path renders whatever id it is handed:
    # ``inspect_object`` and the ``tine-object://`` resource take that id straight
    # from a model, so "fetched by its own object id" stopped being the explicit
    # operator act _UNREDACTED_BLOB_FIELDS assumes. Nothing reachable from an oid
    # alone says which blob that is — only a run payload names it, and finding the
    # run means reading every run (and every event each one validates) in the
    # repository — so every rendered body goes through the pass instead. For the
    # bodies the writer already redacted it is idempotent, and the byte-exact
    # legacy artifact stays reachable through ``Repo.raw`` for review.
    raw = redact_blob(raw)
    try:
        payload = {"encoding": "utf-8", "text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        payload = {
            "data": base64.b64encode(raw).decode("ascii"),
            "encoding": "base64",
        }
    payload.update({"size_bytes": size, "truncated": truncated})
    return {"id": oid, "payload": payload, "schema": schema, "type": "blob"}


#: Never auto-resolved. V2 migration stores this one with ``redact=False`` to keep
#: the legacy bytes verifiable, so it is the only blob in the store that may still
#: hold credentials — SECURITY_MODEL.md requires it be reviewed before it leaves a
#: trusted boundary. Bulk resolution is not review: ``inspect_object`` defaults to
#: ``resolve_blobs=True`` and hands its result straight to an MCP model client.
#: Fetching it by its own object id still renders it, scrubbed by ``_direct_blob``;
#: the byte-exact bytes come from ``Repo.raw``, which no MCP tool exposes.
_UNREDACTED_BLOB_FIELDS = frozenset({"legacy_blob"})


def _finite(number: int | float) -> int | float:
    # json.dumps writes inf/nan as the bare words Infinity/NaN, which no strict JSON
    # reader accepts: rendering one made `tine object --resolve-blobs` emit output its
    # own MCP client could not parse. The loader refuses these bodies too (its
    # canonical re-encode rejects a non-finite number), so refusing keeps them agreed.
    if isinstance(number, float) and not math.isfinite(number):
        raise ValueError("blob body holds a number no JSON reader can round-trip")
    return number


def _rendered_json(raw: bytes) -> Any:
    """Parse a blob body for display exactly as ``load_run`` reads the same bytes.

    ``parse_int`` is the kernel's own hook, not the default ``int``: canonical_json
    writes an integral float >= 2**53 as a bare digit run, so a hookless parse
    rendered an OTel timestamp as 1700000000000000000 where ``load_run`` returned
    1.7e+18 -- one response disagreeing with the loader, and with the hooked
    ``payload`` beside it. Every raise here is a ValueError (``KernelError`` is one
    too), so ``_resolved`` still falls back to its text rendering.
    """
    return json.loads(
        raw,
        parse_constant=lambda literal: _finite(float(literal)),
        parse_float=lambda literal: _finite(float(literal)),
        parse_int=lambda literal: _finite(_parse_int(literal)),
    )


def _resolved(repo: Repo, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    blobs: dict[str, Any] = {}
    cache: dict[str, tuple[bytes, int]] = {}
    remaining = MAX_INSPECT_RESOLVED_BYTES
    source_remaining = MAX_INSPECT_SOURCE_BYTES
    truncated = False
    count = 0
    for field, value in payload.items():
        if not (
            field.endswith("_blob")
            and field not in _UNREDACTED_BLOB_FIELDS
            and isinstance(value, str)
            # Prefix test before parse_oid: the kernel never validates arbitrary
            # *_blob keys, so a peer's pack can carry one holding any string.
            # parse_oid raised on it, and inspect then failed permanently for that
            # object even though fsck called the repository healthy.
            and value.startswith("blob:")
            and parse_oid(value)[0] == "blob"
            and repo.has(value)
        ):
            continue
        if count >= MAX_INSPECT_RESOLVED_BLOBS or remaining <= 0:
            truncated = True
            break
        maximum = min(MAX_INSPECT_BLOB_BYTES, remaining)
        cached = cache.get(value)
        if cached is None:
            raw, size, _ = read_verified_blob_prefix(
                repo,
                value,
                prefix_limit=MAX_INSPECT_BLOB_BYTES,
                source_limit=source_remaining,
            )
            source_remaining -= size
            cache[value] = (raw, size)
        else:
            raw, size = cached
        raw = raw[:maximum]
        remaining -= len(raw)
        count += 1
        body_truncated = size > len(raw)
        # The same scrub _direct_blob applies: only ``legacy_blob`` itself is skipped
        # above, so a run aliasing the unredacted v2 migration bytes under any other
        # ``*_blob`` key resolved them verbatim to an MCP client. Redacting after the
        # length/budget checks keeps their accounting on the stored bytes; it is a
        # no-op for the bodies the writer already redacted.
        raw = redact_blob(raw)
        if body_truncated:
            blobs[field] = {
                "encoding": "utf-8",
                "text": raw.decode(errors="replace"),
                "size_bytes": size,
                "truncated": True,
            }
            truncated = True
            continue
        try:
            # The writer's own budget on the same bytes (guarded_blob_body calls this
            # formula, and blob_json repeats it at load). A fixed 100_000 made this
            # reader stricter than both, so a wide-but-legal step blob -- 240 KB of
            # small integers, saved and loaded fine -- was displayed as an unparsed
            # text dump. Bodies above the prefix limit already left through the
            # truncation branch above, so ``raw`` here is the complete body.
            validate_json_shape(raw, max_tokens=compact_token_budget(len(raw)))
            blobs[field] = _rendered_json(raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            blobs[field] = raw.decode(errors="replace")
    return blobs, truncated


def inspect(repo: Repo, oid: str, *, resolve_blobs: bool = False) -> dict[str, Any]:
    object_type, _ = parse_oid(oid)
    if object_type == "blob":
        return _direct_blob(repo, oid)
    if stored_object_size(repo, oid) > MAX_INSPECT_STRUCTURED_BYTES:
        raise ValueError("structured object exceeds the 4 MiB inspection limit")
    envelope = repo.get(oid)
    payload = envelope.payload()
    result = {
        "id": oid,
        "payload": payload,
        "schema": envelope.schema,
        "type": envelope.object_type,
    }
    if resolve_blobs and isinstance(payload, dict):
        blobs, truncated = _resolved(repo, payload)
        result["resolved_blobs"] = blobs
        if truncated:
            result["resolved_blobs_truncated"] = True
    return result
