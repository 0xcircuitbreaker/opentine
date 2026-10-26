"""SPEC 2.8 "Pack v3": the storage-v3 local pack and its binary index (0.13+).

Each input is a ``.tidx`` (the case's bytes) over a ``.tpk`` (``pack_b64``).
The packs are built here with zlib so a runner needs no zstd; a reader must
treat the codec byte exactly as for any TINEZ1 frame.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import zlib

from opentine.kernel import canonical_json
from opentine.repository import _pack_v3_index as ix
from opentine.repository._pack_v3 import build_pack_v3
from tests.conformance.builders import (
    CHILD_EVENT,
    HELLO_BLOB,
    ROOT_EVENT,
    json_object,
    oid_of,
)
from tests.conformance.cases import ACCEPT, REJECT, B, Case, Family

RUN_A = {"events": [], "session_id": "s", "status": "running", "tips": []}
RUN_B = {**RUN_A, "events": [oid_of(ROOT_EVENT)], "tips": [oid_of(ROOT_EVENT)]}
RUN_C = {**RUN_B, "events": [oid_of(ROOT_EVENT), oid_of(CHILD_EVENT)], "status": "completed"}
RUNS = [json_object("run", body) for body in (RUN_A, RUN_B, RUN_C)]
SLIM_EVENT = json_object(
    "event",
    {
        "actor": "",
        "attributes": {},
        "billing": {},
        "causal_ids": [],
        "cost": 0,
        "duration": 0,
        "kind": "tool",
        "parent_ids": [],
        "usage": {},
    },
)
RUN_HEADER = json_object("run", {}).split(b"\n", 1)[0]


def _pack(objects: list[bytes]) -> tuple[bytes, bytes]:
    _, body, index = build_pack_v3([(oid_of(raw), raw) for raw in objects], "zlib", 9)
    return index, body


def _frame(raw: bytes) -> bytes:
    from opentine import _codec

    return _codec.MAGIC + bytes([_codec.ZLIB]) + _codec._uvarint(len(raw)) + zlib.compress(raw, 9)


def _crafted(items: list[tuple[str, bytes, int, int]]):
    """One block of (oid, stored, encoding, canonical size), indexed as given."""
    block = b"".join(stored for _, stored, _, _ in items)
    frame = _frame(block)
    body = ix.PACK3_MAGIC + frame
    digest = hashlib.sha256(body).hexdigest()
    entries, start = [], 0
    for oid, stored, encoding, size in items:
        entries.append((oid, 0, start, len(stored), size, encoding))
        start += len(stored)
    kind = ix.KINDS.index(items[0][0].split(":")[0])
    rows = [(len(frame), len(block), kind)]
    return ix.encode_index(digest, rows, entries), body


def _oversized() -> tuple[bytes, bytes]:
    """Two blobs declared to tile a block 1 byte past the cap; nothing is inflated."""
    frame = _frame(HELLO_BLOB)
    body = ix.PACK3_MAGIC + frame
    digest = hashlib.sha256(body).hexdigest()
    first, rest = len(HELLO_BLOB), ix.MAX_BLOCK_BYTES + 1 - len(HELLO_BLOB)
    entries = [
        (oid_of(HELLO_BLOB), 0, 0, first, first, 0),
        (f"blob:sha256:{'f' * 64}", 0, first, rest, rest, 0),
    ]
    rows = [(len(frame), ix.MAX_BLOCK_BYTES + 1, ix.KINDS.index("blob"))]
    return ix.encode_index(digest, rows, entries), body


def _resign(index: bytes) -> bytes:
    return index[:-32] + hashlib.sha256(index[:-32]).digest()


def _delta(append: dict, changed: dict | None = None) -> bytes:
    body = {"append": append, "drop": [], "set": changed or {}}
    return RUN_HEADER + b"\n" + canonical_json(body)


def _case(name, expect, intent, pair, reason=None) -> Case:
    index, body = pair
    return Case(
        id=f"localpack.{name}",
        section="2.8",
        checklist=(6,),
        op="localpack.read",
        profile="reader",
        expect=expect,
        intent=intent,
        input=B(index),
        args={"pack_b64": base64.b64encode(body).decode("ascii")},
        reason=reason,
        requires=("zlib",),
    )


_MIXED = _pack([HELLO_BLOB, ROOT_EVENT, CHILD_EVENT, SLIM_EVENT, *RUNS])
_RUN_ID = oid_of(RUNS[1])
_UNSORTED = bytearray(_MIXED[0])
_FIRST = struct.calcsize(">8s32sII") + struct.calcsize(">IIB") * 3
_ENTRY = struct.calcsize(">B32sIIIIB")
_UNSORTED[_FIRST : _FIRST + 2 * _ENTRY] = (
    _MIXED[0][_FIRST + _ENTRY : _FIRST + 2 * _ENTRY] + _MIXED[0][_FIRST : _FIRST + _ENTRY]
)
_CHAIN = [json_object("run", {**RUN_A, "status": f"s{n}"}) for n in range(67)]
_DEEP = [(oid_of(_CHAIN[0]), _CHAIN[0], 0, len(_CHAIN[0]))] + [
    (oid_of(raw), _delta({}, {"status": f"s{n}"}), 1, len(raw)) for n, raw in enumerate(_CHAIN)
][1:]

LOCALPACK = Family(
    "29-localpack.json",
    "2.8",
    "localpack",
    (
        _case(
            "read.blob-events-run-snapshots",
            ACCEPT,
            "the reference writer's pack: one block per kind, run snapshots of a session "
            "as deltas against the snapshot stored just before them, a default-free event",
            _MIXED,
        ),
        _case(
            "read.single-object",
            ACCEPT,
            "the smallest pack: one full object in one block",
            _pack([HELLO_BLOB]),
        ),
        _case(
            "index.checksum",
            REJECT,
            "the index's trailing SHA-256 covers every byte before it",
            (_MIXED[0][:-1] + bytes([_MIXED[0][-1] ^ 1]), _MIXED[1]),
            "localpack.index-checksum",
        ),
        _case(
            "index.truncated",
            REJECT,
            "the length is exactly header + 9 per block + 50 per object + 32",
            (_resign(_MIXED[0][:-33] + _MIXED[0][-32:]), _MIXED[1]),
            "localpack.index-length",
        ),
        _case(
            "index.unsorted",
            REJECT,
            "objects are sorted by id with no duplicates",
            (_resign(bytes(_UNSORTED)), _MIXED[1]),
            "localpack.index-order",
        ),
        _case(
            "block.oversized",
            REJECT,
            "a block of several objects inflates to at most 16 MiB, checked before inflating",
            _oversized(),
            "localpack.block-size",
        ),
        _case(
            "delta.at-block-start",
            REJECT,
            "a run delta's base is the object stored before it in its block, so none may lead",
            _crafted([(_RUN_ID, _delta({"events": ["x"]}), 1, len(RUNS[1]))]),
            "localpack.delta-no-base",
        ),
        _case(
            "delta.too-deep",
            REJECT,
            "a reader resolves at most 64 deltas for one object, iteratively: every object "
            "here is genuine, and the first 64 deltas read back before the 65th is refused",
            _crafted(_DEEP),
            "localpack.delta-too-deep",
        ),
        _case(
            "delta.rebuilds-other-bytes",
            REJECT,
            "every rebuilt object is checked against its id; a delta that rebuilds other "
            "bytes is refused, never returned",
            _crafted(
                [
                    (oid_of(RUNS[0]), RUNS[0], 0, len(RUNS[0])),
                    (_RUN_ID, _delta({}, {"status": "y"}), 1, len(RUNS[1])),
                ]
            ),
            "localpack.object-id-mismatch",
        ),
        _case(
            "encoding.not-for-kind",
            REJECT,
            "run deltas are for runs and slim forms for events; a blob holds its bytes",
            _crafted([(oid_of(HELLO_BLOB), HELLO_BLOB, 2, len(HELLO_BLOB))]),
            "localpack.encoding-kind",
        ),
        _case(
            "slim.stores-a-default",
            REJECT,
            "a slim event leaves every default-valued field out; storing one is refused",
            _crafted([(oid_of(SLIM_EVENT), SLIM_EVENT, 2, len(SLIM_EVENT))]),
            "localpack.slim-default",
        ),
    ),
)

FAMILIES = (LOCALPACK,)
