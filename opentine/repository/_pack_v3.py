"""Version-3 local packs: large kind-grouped blocks and smaller stored forms.

A v3 ``.tpk`` is ``"TINELP3\\n"`` followed by independently compressed blocks
(TINEZ1 frames). Unlike a v1 pack, blocks are large (``DEFAULT_BLOCK_BYTES``,
at most ``MAX_BLOCK_BYTES``) and each holds a single object kind, ordered so
similar objects sit together (run snapshots of one session in append order),
which is where the codec finds its repetition. Objects may use the stored
forms of ``_run_delta``; the ``.tidx`` is binary (``_pack_v3_index``).

Ids, digests and signatures are unchanged: they are over canonical bytes, which
every read rebuilds and checks against the id (``resolve``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository import _run_delta as forms
from opentine.repository._pack_v3_index import (
    KINDS,
    MAX_BLOCK_BYTES,
    PACK3_MAGIC,
    encode_index,
)

DEFAULT_BLOCK_BYTES = 16 * 1024 * 1024
_ORDER = {"blob": 0, "event": 1, "run": 2, "annotation": 3, "attestation": 4}


def _parsed(raw: bytes) -> dict | None:
    try:
        return forms._object(forms.split(raw)[1])
    except KernelError:
        return None


def _body(raw: bytes) -> dict:
    return _parsed(raw) or {}


def _ranks(runs: list[tuple[tuple, dict]], raws: dict[str, bytes]) -> dict[str, int]:
    """Recording order of blobs and events, walked from the run snapshots.

    Ordering by id would scatter one run's growing message history across a
    block; in recording order consecutive histories sit together, which is
    where a large block finds its matches.
    """
    ranks: dict[str, int] = {}

    def visit(value: object) -> None:
        if isinstance(value, str) and value in raws and value not in ranks:
            ranks[value] = len(ranks)
            if value.startswith("event:"):
                for item in _body(raws[value]).values():
                    visit(item)

    for _, body in runs:
        for key in ("prompt_blob", "system_blob"):
            visit(body.get(key))
        events = body.get("events")
        for event in events if isinstance(events, list) else ():
            visit(event)
    return ranks


def stored_forms(objects: list[tuple[str, bytes]]) -> list[tuple[str, bytes, int, bytes]]:
    """(oid, stored bytes, encoding, canonical bytes) in pack order (see ``_ranks``).

    A ``RUN_DELTA`` is against the object just before it, which ``build_pack_v3``
    keeps in the same block (or stores the snapshot in full).
    """
    raws = dict(objects)
    runs = []
    parsed: dict[str, dict | None] = {}  # each snapshot body parsed once
    for oid, raw in objects:
        if oid.startswith("run:"):
            parsed[oid] = _parsed(raw)
            body = parsed[oid] or {}
            events = body.get("events")
            count = len(events) if isinstance(events, list) else 0
            runs.append(((_ORDER["run"], str(body.get("session_id", "")), count, oid), body))
    runs.sort(key=lambda item: item[0])
    ranks = _ranks(runs, raws)
    keyed = [(key, key[3], raws[key[3]]) for key, _ in runs]
    for oid, raw in objects:
        kind = oid.split(":", 1)[0]
        if kind != "run":
            keyed.append(((_ORDER[kind], ranks.get(oid, len(raws)), "", oid), oid, raw))
    keyed.sort(key=lambda item: item[0])
    out: list[tuple[str, bytes, int, bytes]] = []
    previous: tuple[str, str, bytes, int] | None = None  # (session, oid, raw, depth)
    for (_, session, _, _), oid, raw in keyed:
        kind = oid.split(":", 1)[0]
        stored, encoding, depth = raw, forms.FULL, 0
        if kind == "event":
            slim = forms.slim_event(raw)
            if slim is not None:
                stored, encoding = slim, forms.EVENT_SLIM
        elif kind == "run" and previous and previous[0] == session and session:
            if previous[3] < forms.KEYFRAME_INTERVAL:
                delta = forms.run_delta(raw, previous[2], parsed[oid], parsed[previous[1]])
                if delta is not None:
                    stored, encoding, depth = delta, forms.RUN_DELTA, previous[3] + 1
        if kind == "run":
            previous = (session, oid, raw, depth)
        out.append((oid, stored, encoding, raw))
    return out


def build_pack_v3(
    objects: list[tuple[str, bytes]],
    codec: str,
    level: int | None,
    block_bytes: int = DEFAULT_BLOCK_BYTES,
) -> tuple[str, bytes, bytes]:
    """Pack *objects*: return (digest, ``.tpk`` bytes, ``.tidx`` bytes)."""
    block_bytes = max(1, min(block_bytes, MAX_BLOCK_BYTES))
    sizes = {oid: len(raw) for oid, raw in objects}
    body = bytearray(PACK3_MAGIC)
    blocks: list[tuple[int, int, int]] = []
    entries: list[tuple] = []
    pending: list[tuple[str, bytes, int]] = []

    def flush() -> None:
        if not pending:
            return
        offset = 0
        for oid, stored, encoding in pending:
            entries.append((oid, len(blocks), offset, len(stored), sizes[oid], encoding))
            offset += len(stored)
        raw = b"".join(stored for _, stored, _ in pending)
        frame = _codec.wrap(raw, codec, level=level, force=True)
        kind = KINDS.index(pending[0][0].split(":", 1)[0])
        blocks.append((len(frame), len(raw), kind))
        body.extend(frame)
        pending.clear()

    size, kind = 0, ""
    for oid, stored, encoding, raw in stored_forms(objects):
        this = oid.split(":", 1)[0]
        if pending and (this != kind or size + len(stored) > block_bytes):
            flush()
            size = 0
        if encoding == forms.RUN_DELTA and not pending:  # its base is in the last block
            stored, encoding = raw, forms.FULL
        pending.append((oid, stored, encoding))
        size, kind = size + len(stored), this
    flush()
    digest = hashlib.sha256(body).hexdigest()
    return digest, bytes(body), encode_index(digest, blocks, entries)


def resolve(
    oid: str,
    stored: Callable[[str], tuple[bytes, int, int, str | None]],
    known: dict[str, tuple[bytes, int]] | None = None,
) -> bytes:
    """The canonical bytes of *oid*, rebuilt from its stored form and checked.

    *stored* returns ``(bytes, encoding, canonical size, predecessor)`` for an
    object of the pack, the predecessor being the object stored just before it
    in its block (``None`` at a block's start). A ``RUN_DELTA``'s base is its
    predecessor, so a chain only moves towards its block's start and cannot
    loop; it is walked iteratively and refused past ``MAX_DELTA_DEPTH``. Every
    object rebuilt on the way, the base included, must match its id and size.

    *known* maps oids of this same pack to (bytes, delta depth) already rebuilt
    and checked against their id (0.14.1): a chain stops at the first such base
    instead of re-applying every delta back to its block's start, which made
    reading a whole pack in order quadratic in the chain length. The depth
    limit still counts every delta down to the block's full snapshot. The
    rebuilt object is added to it; the caller bounds its size.
    """
    from opentine.repository._packs import oid_of

    chain: list[tuple[str, dict, bytes, int]] = []
    known = {} if known is None else known
    current = oid
    while current not in known:
        data, encoding, size, base = stored(current)
        if encoding != forms.RUN_DELTA:
            break
        if len(chain) >= forms.MAX_DELTA_DEPTH:
            raise KernelError(f"packed run delta chain is too deep: {oid}")
        if base is None:
            raise KernelError(f"packed run delta starts its block: {current}")
        chain.append((current, forms.parse_delta(data), forms.split(data)[0], size))
        current = base
    depth = len(chain)
    if current in known:
        raw, below = known[current]  # rebuilt and checked against its id before
        depth += below
        if depth > forms.MAX_DELTA_DEPTH:
            raise KernelError(f"packed run delta chain is too deep: {oid}")
    else:
        raw = forms.unslim_event(data) if encoding == forms.EVENT_SLIM else data
        _check(current, raw, size, oid_of)
    for target, delta, header, target_size in reversed(chain):
        if forms.split(raw)[0] != header:
            raise KernelError(f"packed run delta header differs from its base: {target}")
        raw = forms.apply_delta(raw, delta)
        _check(target, raw, target_size, oid_of)
    if oid.startswith("run:"):
        known[oid] = (raw, depth)
    return raw


def _check(oid: str, raw: bytes, size: int, oid_of) -> None:
    if len(raw) != size:
        raise KernelError(f"packed object size does not match its index: {oid}")
    if oid_of(raw) != oid:
        raise KernelError(f"packed object does not match its id: {oid}")
