"""Version-3 local packs: large kind-grouped blocks and smaller stored forms.

A v3 ``.tpk`` is ``"TINELP3\\n"`` followed by independently compressed blocks
(TINEZ1 frames; codec 3, a per-kind dictionary, where opted in: ``_pack_dicts``).
Blocks are large (at most ``MAX_BLOCK_BYTES``) and each holds one object kind,
ordered so similar objects sit together (run snapshots of one session in append
order), where the codec finds its repetition. Objects may use the stored forms
of ``_run_delta``; the ``.tidx`` is binary (``_pack_v3_index``).

Ids, digests and signatures are unchanged: they are over canonical bytes, which
every read rebuilds and checks against the id (``resolve``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository import _blob_delta
from opentine.repository import _run_delta as forms
from opentine.repository._pack_v3_index import (
    KINDS,
    MAX_BLOCK_BYTES,
    PACK3_MAGIC,
    encode_index,
)

DEFAULT_BLOCK_BYTES = 16 * 1024 * 1024
_ORDER = {"blob": 0, "event": 1, "run": 2, "annotation": 3, "attestation": 4}


def _parsed(raw: bytes, shaped: bool = True) -> dict | None:
    """The body, or ``None``; ``shaped=False`` skips the shape limits (order only)."""
    try:
        if shaped:
            return forms._object(forms.split(raw)[1])
        value = json.loads(raw.split(b"\n", 1)[1])
        return value if isinstance(value, dict) else None
    except (KernelError, ValueError, RecursionError, IndexError):
        return None


def _ranks(
    runs: list[tuple[tuple, dict]], raws: dict[str, bytes], shaped: bool = True
) -> dict[str, int]:
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
                for item in (_parsed(raws[value], shaped) or {}).values():
                    visit(item)

    for _, body in runs:
        for key in ("prompt_blob", "system_blob"):
            visit(body.get(key))
        events = body.get("events")
        for event in events if isinstance(events, list) else ():
            visit(event)
        manifests = body.get("manifests")  # the transcript a run grows (0.40)
        for value in manifests.values() if isinstance(manifests, dict) else ():
            visit(value)
    return ranks


def stored_forms(
    objects: list[tuple[str, bytes]], *, slim: bool = True, blob_deltas: bool = False
) -> list[tuple[str, bytes, int, bytes]]:
    """(oid, stored bytes, encoding, canonical bytes) in pack order (see ``_ranks``).

    ``slim=False`` keeps every object ``FULL``: recording order alone.
    *blob_deltas* also stores blobs as ``BLOB_DELTA`` (``_blob_delta``, 0.40).

    A ``RUN_DELTA`` is against the object just before it, which ``build_pack_v3``
    keeps in the same block (or stores the snapshot in full).
    """
    raws = dict(objects)
    runs = []
    parsed: dict[str, dict | None] = {}  # each snapshot body parsed once
    for oid, raw in objects:
        if oid.startswith("run:"):
            parsed[oid] = _parsed(raw, slim)
            body = parsed[oid] or {}
            events = body.get("events")
            count = len(events) if isinstance(events, list) else 0
            runs.append(((_ORDER["run"], str(body.get("session_id", "")), count, oid), body))
    runs.sort(key=lambda item: item[0])
    ranks = _ranks(runs, raws, slim)
    keyed = [(key, key[3], raws[key[3]]) for key, _ in runs]
    for oid, raw in objects:
        kind = oid.split(":", 1)[0]
        if kind != "run":
            keyed.append(((_ORDER[kind], ranks.get(oid, len(raws)), "", oid), oid, raw))
    keyed.sort(key=lambda item: item[0])
    out: list[tuple[str, bytes, int, bytes]] = []
    deltas = _blob_delta.choose([(o, r) for _, o, r in keyed]) if blob_deltas and slim else {}
    previous: tuple[str, str, bytes, int] | None = None  # (session, oid, raw, depth)
    for (_, session, _, _), oid, raw in keyed:
        kind = oid.split(":", 1)[0]
        stored, encoding, depth = raw, forms.FULL, 0
        if oid in deltas:
            stored, encoding = deltas[oid][1], forms.BLOB_DELTA
        elif kind == "event" and slim:
            slimmed = forms.slim_event(raw)
            if slimmed is not None:
                stored, encoding = slimmed, forms.EVENT_SLIM
        elif kind == "run" and slim and previous and previous[0] == session and session:
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
    blob_deltas: bool = False,
    train: Callable[[list], dict[str, bytes]] | None = None,
) -> tuple[str, bytes, bytes]:
    """Pack *objects*: (digest, ``.tpk``, ``.tidx``); *train* maps kinds to dictionaries."""
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
        kind = KINDS.index(pending[0][0].split(":", 1)[0])
        frame = _codec.wrap(raw, codec, level=level, force=True, dictionary=chosen.get(KINDS[kind]))
        blocks.append((len(frame), len(raw), kind))
        body.extend(frame)
        pending.clear()

    size, kind, found = 0, "", stored_forms(objects, blob_deltas=blob_deltas)
    chosen = train(found) if train and codec == "zstd" else {}
    for oid, stored, encoding, raw in found:
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
    loop. A ``BLOB_DELTA`` names its base by id (any blob of the pack), so the
    walk refuses an id it already visited (a cycle). Chains are walked
    iteratively and refused past ``MAX_DELTA_DEPTH``. Every
    object rebuilt on the way, the base included, must match its id and size.

    *known* maps oids of this same pack to (bytes, delta depth) already rebuilt
    and checked against their id (0.14.1): a chain stops at the first such base
    instead of re-applying every delta back to its block's start, which made
    reading a whole pack in order quadratic in the chain length. The depth
    limit still counts every delta down to the block's full snapshot. The
    rebuilt object is added to it; the caller bounds its size.
    """
    from opentine.repository._packs import oid_of

    chain: list[tuple[str, int, object, int]] = []
    known = {} if known is None else known
    current, seen = oid, set()
    while current not in known:
        if current in seen:
            raise KernelError(f"packed delta chain loops back to {current}: {oid}")
        seen.add(current)
        try:
            data, encoding, size, base = stored(current)
        except TypeError:  # no entry: a blob delta's base outside its pack
            raise KernelError(f"packed delta base is not in its pack: {current}") from None
        if encoding not in (forms.RUN_DELTA, forms.BLOB_DELTA):
            break
        if len(chain) >= forms.MAX_DELTA_DEPTH:
            raise KernelError(f"packed {oid.split(':')[0]} delta chain is too deep: {oid}")
        if encoding == forms.BLOB_DELTA:
            payload: object = _blob_delta.parse(data)
            base = payload[1]  # named by id (``_blob_delta``)
        else:
            payload = (forms.parse_delta(data), forms.split(data)[0])
        if base is None:
            raise KernelError(f"packed run delta starts its block: {current}")
        chain.append((current, encoding, payload, size))
        current = base
    depth = len(chain)
    if current in known:
        raw, below = known[current]  # rebuilt and checked against its id before
        depth += below
        if depth > forms.MAX_DELTA_DEPTH:
            raise KernelError(f"packed {oid.split(':')[0]} delta chain is too deep: {oid}")
    else:
        raw = forms.unslim_event(data) if encoding == forms.EVENT_SLIM else data
        _check(current, raw, size, oid_of)
    for target, encoding, payload, target_size in reversed(chain):
        if encoding == forms.BLOB_DELTA:
            raw = _blob_delta.apply(payload, raw)
        else:
            delta, header = payload
            if forms.split(raw)[0] != header:
                raise KernelError(f"packed run delta header differs from its base: {target}")
            raw = forms.apply_delta(raw, delta)
        _check(target, raw, target_size, oid_of)
    if oid.startswith(("run:", "blob:")):
        known[oid] = (raw, depth)
    return raw


def _check(oid: str, raw: bytes, size: int, oid_of) -> None:
    if len(raw) != size:
        raise KernelError(f"packed object size does not match its index: {oid}")
    if oid_of(raw) != oid:
        raise KernelError(f"packed object does not match its id: {oid}")
