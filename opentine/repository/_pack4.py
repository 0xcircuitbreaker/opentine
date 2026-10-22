"""``TINEPACK4``: a binary, compressed transfer pack, and choosing it per peer.

``TINEPACK3`` stores every object base64-encoded inside a JSON manifest that is
zlib-compressed as a whole, so a transfer carries a third more than it holds and
a reader inflates the whole manifest before it can check anything. ``TINEPACK4``
carries the same objects and shallow boundaries as raw bytes:

    b"TINEPACK4\\0" | sha256(payload) | payload
    payload = uvarint(len(header)) | header | body
    header  = canonical JSON {"codec", "objects": [[oid, length], ...],
                              "shallow": [...], "version": 1}
    body    = the objects' bytes, concatenated in header order, in one
              ``_codec`` wrapper (zlib, or zstd when both ends have it)

A reader checks the checksum, then the header, then that the lengths add up to
the body's declared size -- all before inflating anything -- and inflates with
exactly that size as the limit, so a crafted pack cannot make it allocate more
than :data:`MAX_PACK_BODY_BYTES`. The pack id is the checksum, as for v3.

A peer that does not list ``TINEPACK4`` in its capabilities is sent and asked
for v3, so 0.11 and older peers keep working in both directions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from opentine import _codec
from opentine.kernel import (
    KernelError,
    ObjectEnvelope,
    _parse_int,
    canonical_json,
    parse_oid,
    validate_json_shape,
)

MAGIC4 = b"TINEPACK4\0"
V3, V4 = "TINEPACK3", "TINEPACK4"
#: Response/request header naming the format of the pack it carries.
FORMAT_HEADER = "Opentine-Pack-Format"
#: The header lists each object id and length: generous for the object cap.
MAX_HEADER_BYTES = 16 * 1024 * 1024


def local_codecs() -> list[str]:
    """Pack codecs this install can read, preferred first."""
    return ["zstd", "zlib"] if _codec.available("zstd") else ["zlib"]


def choose(offered_formats: Any, offered_codecs: Any) -> tuple[str, str | None]:
    """The format (and v4 codec) to use with a peer that offered these lists."""
    formats = offered_formats if isinstance(offered_formats, list) else []
    if V4 not in formats:
        return V3, None
    codecs = offered_codecs if isinstance(offered_codecs, list) else ["zlib"]
    for codec in local_codecs():
        if codec in codecs:
            return V4, codec
    return V3, None


def build(objects: list[tuple[str, bytes]], shallow: list[str], codec: str) -> bytes:
    """A v4 pack of *objects* (``(oid, raw)``) and *shallow* boundaries."""
    if codec not in ("zlib", "zstd"):
        raise KernelError(f"unsupported pack codec {codec!r}")
    ordered = sorted(objects)
    header = canonical_json(
        {
            "codec": codec,
            "objects": [[oid, len(raw)] for oid, raw in ordered],
            "shallow": sorted(shallow),
            "version": 1,
        }
    )
    body = _codec.wrap(b"".join(raw for _, raw in ordered), codec, level=9, force=True)
    assert body is not None  # force=True always wraps
    payload = _codec._uvarint(len(header)) + header + body
    return MAGIC4 + hashlib.sha256(payload).digest() + payload


def _header(payload: bytes) -> tuple[dict[str, Any], int]:
    try:
        length, start = _codec._read_uvarint(payload, 0)
    except _codec.CodecError as exc:
        raise KernelError("invalid pack header") from exc
    if length > MAX_HEADER_BYTES or start + length > len(payload):
        raise KernelError("invalid pack header")
    raw = payload[start : start + length]
    validate_json_shape(raw)
    try:
        header = json.loads(raw, parse_int=_parse_int)
        canonical = canonical_json(header)
    except (ValueError, RecursionError, UnicodeDecodeError, KernelError) as exc:
        raise KernelError("invalid pack header") from exc
    if canonical != raw or not isinstance(header, dict):
        raise KernelError("non-canonical or unsupported pack")
    if set(header) != {"codec", "objects", "shallow", "version"} or header["version"] != 1:
        raise KernelError("non-canonical or unsupported pack")
    if header["codec"] not in ("zlib", "zstd"):
        raise KernelError("unsupported pack codec")
    if not isinstance(header["objects"], list) or not isinstance(header["shallow"], list):
        raise KernelError("invalid pack manifest")
    return header, start + length


def inspect(
    data: bytes, *, max_body: int, max_objects: int
) -> tuple[str, list[tuple[str, bytes]], list[str]]:
    """``(pack_id, objects, shallow)`` of a v4 pack, every limit checked first."""
    if len(data) < len(MAGIC4) + 32 or not data.startswith(MAGIC4):
        raise KernelError("invalid pack header")
    expected, payload = data[len(MAGIC4) : len(MAGIC4) + 32], data[len(MAGIC4) + 32 :]
    actual = hashlib.sha256(payload).digest()
    if actual != expected:
        raise KernelError("pack checksum mismatch")
    header, offset = _header(payload)
    entries, shallow = header["objects"], header["shallow"]
    if len(entries) > max_objects or len(shallow) > max_objects:
        raise KernelError("pack exceeds maximum object count")
    lengths: list[tuple[str, int]] = []
    for entry in entries:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or type(entry[1]) is not int
            or entry[1] < 0
        ):
            raise KernelError("invalid pack manifest")
        lengths.append((entry[0], entry[1]))
    total = sum(length for _, length in lengths)
    if total > max_body:
        raise KernelError("pack exceeds maximum decompressed size")
    body = payload[offset:]
    if not _codec.is_wrapped(body) or _codec.declared_size(body) != total:
        raise KernelError("pack body does not match its manifest")
    try:
        raw = _codec.unwrap(body, limit=total)
    except _codec.CodecError as exc:
        raise KernelError("invalid compressed pack") from exc
    objects: list[tuple[str, bytes]] = []
    cursor = 0
    for oid, length in lengths:
        chunk = raw[cursor : cursor + length]
        cursor += length
        try:
            ObjectEnvelope.decode(chunk, oid)
        except (KeyError, TypeError, ValueError) as exc:
            raise KernelError("invalid packed object") from exc
        objects.append((oid, chunk))
    ids = [oid for oid, _ in objects]
    if not isinstance(shallow, list) or not all(isinstance(oid, str) for oid in shallow):
        raise KernelError("invalid pack shallow list")
    if ids != sorted(set(ids)) or shallow != sorted(set(shallow)):
        raise KernelError("pack objects must be sorted and unique")
    if set(ids) & set(shallow):
        raise KernelError("packed objects cannot also be shallow boundaries")
    for oid in shallow:
        parse_oid(oid)
    return f"sha256:{actual.hex()}", objects, shallow


def from_v3(data: bytes, codec: str) -> bytes:
    """The v4 form of a v3 pack: same objects, same boundaries."""
    from opentine.repository.pack import inspect_pack

    _, objects, shallow = inspect_pack(data)
    return build(objects, shallow, codec)


def request_fields(capabilities: dict[str, Any]) -> dict[str, list[str]]:
    """Fetch-body fields offering v4, only to a server that advertises it.

    A 0.11 server refuses unknown request keys, so nothing is added for it.
    """
    if V4 not in (capabilities.get("pack_formats") or []):
        return {}
    return {"pack_codecs": local_codecs(), "pack_formats": [V4, V3]}


def for_peer(data: bytes, capabilities: dict[str, Any]) -> bytes:
    """*data* (a v3 pack) in the best format a peer with these capabilities reads."""
    fmt, codec = choose(capabilities.get("pack_formats"), capabilities.get("pack_codecs"))
    return from_v3(data, codec) if fmt == V4 and codec else data


def pack_digest(data: bytes) -> str:
    """The pack id a peer reports for *data*, read from its header."""
    return "sha256:" + data[len(MAGIC4) : len(MAGIC4) + 32].hex()


__all__ = [
    "FORMAT_HEADER",
    "MAGIC4",
    "V3",
    "V4",
    "build",
    "choose",
    "from_v3",
    "inspect",
    "local_codecs",
    "pack_digest",
]
