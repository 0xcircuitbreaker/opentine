"""``TINEPACK6``: a Hash-Elision Coding (HEC) transfer pack (0.81, opt-in).

The frame is the ``TINEPACK5`` frame with a different payload::

    b"TINEPACK6\\0" | sha256(payload) | payload
    payload = uvarint(len(header)) | header | hec | plain block 0 | plain block 1 | ...
    header  = canonical JSON {"grammar": "opentine-1", "hec": "HEC1", "hec_bytes": N,
                              "plain_blocks": [[stored, raw], ...],
                              "shallow": [...], "version": 1}
    plain block 0  = canonical JSON {"objects": [size, ...]}
    plain block 1+ = the plain objects' bytes, cut every 4 MiB

``hec`` is one self-contained ``HEC1`` pack (``opentine._hec``, grammar
``opentine-1``): no object id is carried, every id is recomputed from the
rebuilt bytes, so decoding is verification. The plain section holds the
objects HEC does not code well (binary or sealed bodies), whole, as one zstd
long-mode frame like ``TINEPACK5``'s (no blocks when there are none). The writer
(``_pack6_build``) keeps whichever split is smallest, so a ``TINEPACK6`` is
never larger than the plain zstd form of the same objects by more than its
frame.

A reader checks the checksum, the header and every declared size against its
output budget before inflating anything, decodes all or nothing (a refusal
names one HEC reason code, ``Pack6Error.code``), then runs the same id,
envelope and boundary checks as for every pack. Pack bytes are malleable:
they are never a cache key and never signed; the pack id is a transport id.
Thin packs (``HECS``) are not supported.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading

from opentine import _codec, _codec_long, _hec
from opentine.kernel import KernelError, ObjectEnvelope, _parse_int, canonical_json
from opentine.repository import _pack4
from opentine.repository._pack4 import MAX_HEADER_BYTES

MAGIC6 = b"TINEPACK6\0"
V6 = "TINEPACK6"
GRAMMAR = "opentine-1"
_KEYS = {"grammar", "hec", "hec_bytes", "plain_blocks", "shallow", "version"}
#: Output budget of a pack decoded by ``tine serve`` (64 MiB per pack).
SERVE_MAX_OUTPUT = 64 * 1024 * 1024
#: Decodes ``tine serve`` runs at once; more wait (a decode peaks near 4x its budget).
SERVE_DECODES = 2
_SERVE_SLOTS = threading.BoundedSemaphore(SERVE_DECODES)
#: Opt-in switch: an install advertises (and so is sent) TINEPACK6 only with it set.
OPT_IN_ENV = "OPENTINE_TINEPACK6"


class Pack6Error(KernelError):
    """A refused ``TINEPACK6``; ``code`` is the HEC reason code (SPEC "TINEPACK6")."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"TINEPACK6 decode refused ({code}){': ' + detail if detail else ''}")
        self.code = code


def available() -> bool:
    """Whether this install reads and writes TINEPACK6 (needs zstd)."""
    return _codec_long.available()


def opted_in() -> bool:
    """Whether this install advertises TINEPACK6 to peers (``OPENTINE_TINEPACK6=1``)."""
    return available() and os.environ.get(OPT_IN_ENV, "").strip() == "1"


def _header(payload: bytes) -> tuple[dict, int]:
    header, offset = _pack4._header(payload, _KEYS)
    if header["grammar"] != GRAMMAR or header["hec"] != "HEC1":
        raise KernelError("unsupported TINEPACK6 body (only HEC1, grammar opentine-1)")
    if type(header["hec_bytes"]) is not int or header["hec_bytes"] < 0:
        raise KernelError("invalid pack manifest")
    if not isinstance(header["shallow"], list):
        raise KernelError("invalid pack shallow list")
    return header, offset


def _plain(frames: list[tuple[bytes, int]], budget: int, max_objects: int) -> list[bytes]:
    """The plain objects: the size list (block 0) is checked before the body is inflated."""
    if not frames:
        return []
    try:
        stream = _codec_long.decompress_blocks(frames)
        sizes = _manifest(next(stream))
        if len(sizes) > max_objects:
            raise KernelError("pack exceeds maximum object count")
        if sum(sizes) != sum(raw for _, raw in frames[1:]) or sum(sizes) > budget:
            raise KernelError("pack body does not match its manifest")
        body = b"".join(stream)
    except _codec.CodecError as exc:
        raise KernelError(f"invalid compressed pack: {exc}") from exc
    out, cursor = [], 0
    for size in sizes:
        out.append(body[cursor : cursor + size])
        cursor += size
    return out


def _manifest(raw: bytes) -> list[int]:
    try:
        value = json.loads(raw, parse_int=_parse_int) if len(raw) <= MAX_HEADER_BYTES else None
        ok = isinstance(value, dict) and canonical_json(value) == raw and set(value) == {"objects"}
    except (ValueError, RecursionError, UnicodeDecodeError, KernelError):
        ok = False
    sizes = value["objects"] if ok else None
    if not isinstance(sizes, list) or not all(type(n) is int and n >= 0 for n in sizes):
        raise KernelError("invalid pack manifest")
    return sizes


def _decode_hec(data: bytes, budget: int, max_objects: int) -> list[tuple[str, bytes]]:
    # Unit bookkeeping is charged length + 32 per unit; tie its cap to the budget so many
    # tiny units cannot hold several times the budget in object overhead (the engine
    # default, 256 MiB, is far above a serve budget).
    limits = _hec.Limits(
        max_output_bytes=budget, max_objects=max_objects, max_unit_bytes=max(budget, 1 << 20)
    )
    try:
        decoded = _hec.decode(data, _hec.OPENTINE, _hec.ANY, limits)
    except _hec.HecError as exc:
        raise Pack6Error(exc.code, str(exc)) from None
    return [(o.id.decode("ascii"), o.type.desc + b"\n" + o.body) for o in decoded.objects]


def inspect(
    data: bytes, *, max_body: int, max_objects: int, serve: bool = False
) -> tuple[str, list[tuple[str, bytes]], list[str]]:
    """``(pack_id, objects, shallow)`` of a v6 pack; *serve* applies the server budget."""
    from opentine.repository._packs import oid_of

    if len(data) < len(MAGIC6) + 32 or not data.startswith(MAGIC6):
        raise KernelError("invalid pack header")
    expected, payload = data[len(MAGIC6) : len(MAGIC6) + 32], data[len(MAGIC6) + 32 :]
    actual = hashlib.sha256(payload).digest()
    if actual != expected:
        raise KernelError("pack checksum mismatch")
    budget = min(max_body, SERVE_MAX_OUTPUT) if serve else max_body
    header, offset = _header(payload)
    blocks, shallow = _blocks(header["plain_blocks"]), header["shallow"]
    if len(shallow) > max_objects or len(blocks) > max_objects + 1:
        raise KernelError("pack exceeds maximum object count")
    if blocks and blocks[0][1] > MAX_HEADER_BYTES:
        raise KernelError("invalid pack manifest")
    plain_total = sum(raw for _, raw in blocks[1:])
    if plain_total > budget:
        raise Pack6Error("budget", "plain section exceeds the output budget")
    end = offset + header["hec_bytes"]
    if end + sum(frame for frame, _ in blocks) != len(payload):
        raise KernelError("pack body does not match its manifest")
    if not _codec_long.available():
        raise KernelError("TINEPACK6 needs zstd; install opentine[zstd]")
    slots = _SERVE_SLOTS if serve else None
    if slots is not None:
        slots.acquire()
    try:
        objects = _decode_hec(payload[offset:end], budget - plain_total, max_objects)
        frames, cursor = [], end
        for frame, raw in blocks:
            frames.append((payload[cursor : cursor + frame], raw))
            cursor += frame
        for raw in _plain(frames, plain_total, max_objects):
            try:
                oid = oid_of(raw)
            except (KernelError, ValueError) as exc:
                raise KernelError("invalid packed object") from exc
            objects.append((oid, raw))
    finally:
        if slots is not None:
            slots.release()
    if len(objects) > max_objects:
        raise KernelError("pack exceeds maximum object count")
    for oid, raw in objects:
        try:
            ObjectEnvelope.decode(raw, oid)
        except (KeyError, TypeError, ValueError, KernelError) as exc:
            raise KernelError("invalid packed object") from exc
    return f"sha256:{actual.hex()}", _pack4.check_ids(objects, shallow), shallow


def _blocks(value: object) -> list[list[int]]:
    if not isinstance(value, list) or not all(
        isinstance(item, list) and len(item) == 2 and all(type(n) is int and n >= 0 for n in item)
        for item in value
    ):
        raise KernelError("invalid pack manifest")
    return value


def frame(hec: bytes, plain: list[bytes], shallow: list[str]) -> bytes:
    """The TINEPACK6 bytes of an HEC1 pack and the plain objects (``_pack6_build``)."""
    blocks: list[bytes] = []
    pending = bytearray()
    for raw in plain:
        if pending and len(pending) + len(raw) > _BLOCK_BYTES:
            blocks.append(bytes(pending))
            pending.clear()
        pending.extend(raw)
    if pending:
        blocks.append(bytes(pending))
    if plain:
        blocks.insert(0, canonical_json({"objects": [len(raw) for raw in plain]}))
    frames = _codec_long.compress_blocks(blocks) if blocks else []
    header = {
        "grammar": GRAMMAR,
        "hec": "HEC1",
        "hec_bytes": len(hec),
        "plain_blocks": [[len(f), len(b)] for f, b in zip(frames, blocks)],
        "shallow": sorted(shallow),
        "version": 1,
    }
    encoded = canonical_json(header)
    if len(encoded) > MAX_HEADER_BYTES:
        raise KernelError("pack header too large")
    payload = _codec._uvarint(len(encoded)) + encoded + hec + b"".join(frames)
    return MAGIC6 + hashlib.sha256(payload).digest() + payload


_BLOCK_BYTES = 4 * 1024 * 1024

__all__ = [
    "MAGIC6",
    "OPT_IN_ENV",
    "SERVE_DECODES",
    "SERVE_MAX_OUTPUT",
    "V6",
    "Pack6Error",
    "available",
    "frame",
    "inspect",
    "opted_in",
]
