"""``TINEPACK5``: a recording-order, long-window transfer pack (0.37).

``TINEPACK4`` sorts objects by id, lists every id in a plain header and
compresses with a window far smaller than a repository's history, so the
hundredth snapshot of a run cannot find the ninety-nine before it.
``TINEPACK5`` stores objects in recording order (``_pack_v3.stored_forms``:
each run's blobs and events as they were recorded, then each session's
snapshots in append order), may store them in the ``EVENT_SLIM`` and
``RUN_DELTA`` forms of ``_run_delta``, and compresses everything as one zstd
long-distance frame (``_codec_long``, window 2**27) flushed into blocks:

    b"TINEPACK5\\0" | sha256(payload) | payload
    payload  = uvarint(len(header)) | header | block 0 | block 1 | ...
    header   = canonical JSON {"blocks": [[stored, raw], ...],
                               "version": 1, "window_log": 27}
    block 0  = manifest, canonical JSON {"objects": [[encoding, stored, size], ...],
                                         "shallow": [...]}
    block 1+ = the objects' stored bytes in pack order, cut every BLOCK_BYTES

Ids are not listed: each is the hash of the canonical bytes the reader
rebuilds, so a forged id cannot exist. A reader checks the checksum and the
header and that the blocks stay within its limits, inflates the manifest (at
most ``MAX_HEADER_BYTES``) and checks that the object sizes match the blocks --
before inflating the body -- then inflates the blocks in order, each to exactly
its declared size, with the window capped at 27 (X17). A ``RUN_DELTA`` applies
to the run just before it, its chain depth bounded. The pack id is the checksum.

Only a peer that lists ``TINEPACK5`` (0.37+) is sent one (``_pack_peer``).
"""

from __future__ import annotations

import hashlib
import json

from opentine import _codec, _codec_long
from opentine.kernel import KernelError, ObjectEnvelope, _parse_int, canonical_json
from opentine.kernel import validate_json_shape as _shape
from opentine.repository import _pack4
from opentine.repository import _run_delta as forms
from opentine.repository._pack_v3 import stored_forms

MAGIC5 = b"TINEPACK5\0"
V5 = "TINEPACK5"
BLOCK_BYTES = 4 * 1024 * 1024
_KEYS = {"blocks", "version", "window_log"}


def available() -> bool:
    return _codec_long.available()


def build(objects: list[tuple[str, bytes]], shallow: list[str], *, slim: bool = False) -> bytes:
    """A v5 pack of *objects* (``(oid, raw)``) and *shallow* boundaries.

    *slim* also stores the ``EVENT_SLIM`` and ``RUN_DELTA`` forms: a little
    smaller, several times slower to write, so the wire leaves it off.
    """
    entries: list[list[int]] = []
    blocks: list[bytes] = []
    pending = bytearray()
    previous = ""
    for oid, stored, encoding, raw in stored_forms(sorted(objects), slim=slim):
        if encoding == forms.RUN_DELTA and not previous.startswith("run:"):
            stored, encoding = raw, forms.FULL  # a delta's base is the object before it
        if pending and len(pending) + len(stored) > BLOCK_BYTES:
            blocks.append(bytes(pending))
            pending.clear()
        pending.extend(stored)
        entries.append([encoding, len(stored), len(raw)])
        previous = oid
    if pending:
        blocks.append(bytes(pending))
    manifest = canonical_json({"objects": entries, "shallow": sorted(shallow)})
    frames = _codec_long.compress_blocks([manifest, *blocks])
    sizes = [[len(frame), len(block)] for frame, block in zip(frames, [manifest, *blocks])]
    header = canonical_json({"blocks": sizes, "version": 1, "window_log": _codec_long.WINDOW_LOG})
    payload = _codec._uvarint(len(header)) + header + b"".join(frames)
    return MAGIC5 + hashlib.sha256(payload).digest() + payload


def _ints(value: object, width: int) -> list[list[int]]:
    if not isinstance(value, list) or not all(
        isinstance(item, list)
        and len(item) == width
        and all(type(n) is int and n >= 0 for n in item)
        for item in value
    ):
        raise KernelError("invalid pack manifest")
    return value


def _manifest(raw: bytes) -> tuple[list[list[int]], list]:
    try:
        _shape(raw)
        manifest = json.loads(raw, parse_int=_parse_int)
        canonical = canonical_json(manifest)
    except (ValueError, RecursionError, UnicodeDecodeError, KernelError) as exc:
        raise KernelError("invalid pack manifest") from exc
    if (
        canonical != raw
        or not isinstance(manifest, dict)
        or set(manifest) != {"objects", "shallow"}
    ):
        raise KernelError("non-canonical or unsupported pack")
    return _ints(manifest["objects"], 3), manifest["shallow"]


def _rebuild(stored: bytes, encoding: int, base: bytes | None) -> bytes:
    if encoding == forms.FULL:
        return stored
    if encoding == forms.EVENT_SLIM:
        return forms.unslim_event(stored)
    if encoding == forms.RUN_DELTA and base is not None:
        return forms.apply_delta(base, forms.parse_delta(stored))
    raise KernelError("invalid stored form in pack")


def inspect(
    data: bytes, *, max_body: int, max_objects: int
) -> tuple[str, list[tuple[str, bytes]], list[str]]:
    """``(pack_id, objects, shallow)`` of a v5 pack, every limit checked first."""
    from opentine.repository._packs import oid_of

    if len(data) < len(MAGIC5) + 32 or not data.startswith(MAGIC5):
        raise KernelError("invalid pack header")
    expected, payload = data[len(MAGIC5) : len(MAGIC5) + 32], data[len(MAGIC5) + 32 :]
    actual = hashlib.sha256(payload).digest()
    if actual != expected:
        raise KernelError("pack checksum mismatch")
    header, offset = _pack4._header(payload, _KEYS)
    if header["window_log"] != _codec_long.WINDOW_LOG:
        raise KernelError("unsupported pack window")
    blocks = _ints(header["blocks"], 2)
    if not blocks or len(blocks) > max_objects + 1 or blocks[0][1] > _pack4.MAX_HEADER_BYTES:
        raise KernelError("invalid pack manifest")
    if sum(raw for _, raw in blocks[1:]) > max_body:
        raise KernelError("pack exceeds maximum decompressed size")
    if offset + sum(frame for frame, _ in blocks) != len(payload):
        raise KernelError("pack body does not match its manifest")
    frames, cursor = [], offset
    for frame, raw in blocks:
        frames.append((payload[cursor : cursor + frame], raw))
        cursor += frame
    try:
        stream = _codec_long.decompress_blocks(frames)
        entries, shallow = _manifest(next(stream))
        if len(entries) > max_objects or len(shallow) > max_objects:
            raise KernelError("pack exceeds maximum object count")
        if sum(size for *_, size in entries) > max_body:
            raise KernelError("pack exceeds maximum decompressed size")
        if sum(stored for _, stored, _ in entries) != sum(raw for _, raw in blocks[1:]):
            raise KernelError("pack body does not match its manifest")
        body = b"".join(stream)
    except _codec.CodecError as exc:
        raise KernelError(f"invalid compressed pack: {exc}") from exc
    objects: list[tuple[str, bytes]] = []
    base: bytes | None = None
    depth = cursor = 0
    for encoding, stored, size in entries:
        chunk = body[cursor : cursor + stored]
        cursor += stored
        depth = depth + 1 if encoding == forms.RUN_DELTA else 0
        if depth > forms.MAX_DELTA_DEPTH:
            raise KernelError("packed run delta chain is too deep")
        try:
            raw = _rebuild(chunk, encoding, base)
            oid = oid_of(raw)
            kind = {forms.RUN_DELTA: "run:", forms.EVENT_SLIM: "event:"}.get(encoding, "")
            if len(raw) != size or not oid.startswith(kind):
                raise ValueError("stored form does not match its object")
            ObjectEnvelope.decode(raw, oid)
        except (KeyError, TypeError, ValueError, KernelError) as exc:
            raise KernelError("invalid packed object") from exc
        objects.append((oid, raw))
        base = raw if oid.startswith("run:") else None
    return f"sha256:{actual.hex()}", _pack4.check_ids(objects, shallow), shallow


def from_v3(data: bytes, *, slim: bool = False) -> bytes:
    """The v5 form of a v3 pack: same objects, same boundaries."""
    from opentine.repository.pack import inspect_pack

    _, objects, shallow = inspect_pack(data)
    return build(objects, shallow, slim=slim)


__all__ = ["BLOCK_BYTES", "MAGIC5", "V5", "available", "build", "from_v3", "inspect"]
