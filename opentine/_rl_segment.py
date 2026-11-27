"""Sealed episode segments for RL-scale capture (0.84): ``opentine.ingest-segment/1``.

``tine ingest seal --stream S --key RUNNER`` seals every batch appended since
the stream's previous segment (or through ``--through BATCH``) into one
segment: an RFC 6962 Merkle root over the captured episodes, signed once for
the whole segment instead of once per episode. The leaf of an episode is
``SHA-256(0x00 || line)``, where ``line`` is the episode's stored line
``{"e": EVENT, "i": INDEX, "k": KIND}`` exactly as its batch holds it (no
trailing newline). Leaves are in stream-index order.

The segment is a claim convention on an existing ``annotation`` on the stream's
anchor blob (no new kind)::

    {"convention": "opentine.ingest-segment/1", "stream": S, "seq": N,
     "previous": SEGMENT-ID | null, "batches": [BATCH-ID, ...],
     "first_index": I, "next_index": J, "episodes": E, "root": "sha256:...",
     "log": {"origin": "opentine.local/log/op", "index": K}, "sealed_at": RFC3339}

Before the segment is written its root is logged in the repository's op log
(an ``opentine-op/1`` note entry ``ingest seal S #N ROOT through BATCH`` at
index ``K``): that entry is the commitment a later audit's seed must follow
(:mod:`opentine._rl_audit`). The signer must hold the pinned ``runner`` role
and no ``optimizer`` role; roles come from the owner-pinned trust bundle only,
so sealing fails closed without one. The newest segment is held as
``ingest-segment:S``; segments chain through ``previous``.
"""

from __future__ import annotations

from typing import Any

from opentine import _ingest_holds, _ingest_policy
from opentine._ingest_batch import CONVENTION as BATCH
from opentine._ingest_policy import IngestError
from opentine._rl_merkle import Tree, episode_leaf
from opentine._utc import rfc3339_utc
from opentine.repository._holds import INGEST_SEGMENT

CONVENTION = "opentine.ingest-segment/1"
MAX_BATCHES = 65_536
MAX_EPISODES = 1 << 26


def note_text(stream: str, seq: int, root: str, last: str) -> str:
    return f"ingest seal {stream} #{seq} {root} through {last}"


def _signer_ok(repo: Any, key: Any) -> None:
    from opentine._key_roles_pin import resolve
    from opentine._signing_pins import key_fingerprint

    signer = key_fingerprint(key.public_key().public_bytes_raw())
    code = _ingest_policy.judge_writer(signer, resolve(repo.path))
    if code:
        raise IngestError(f"this key may not seal segments ({code}): a pinned runner key, "
                          "never an optimizer key")  # fmt: skip


def batch_range(repo: Any, stream: str, through: str, stop: str | None) -> list[str]:
    """Batch ids after *stop* up to *through*, oldest first (a broken chain raises)."""
    ids: list[str] = []
    cursor: str | None = through
    while cursor != stop:
        if cursor is None:
            raise IngestError(f"{through} does not follow the previous segment's last batch")
        if len(ids) >= MAX_BATCHES:
            raise IngestError(f"a segment holds at most {MAX_BATCHES} batches")
        row = _ingest_holds.read(repo, cursor, BATCH)
        if row is None or not row["signed"] or row["claim"].get("stream") != stream:
            raise IngestError(f"{cursor} is not a signed batch of stream {stream}")
        ids.append(cursor)
        cursor = row["claim"].get("previous")
    return ids[::-1]


def episodes(repo: Any, stream: str, batch_ids: list[str]) -> dict[str, Any]:
    """``{"leaves", "indexes", "first_index", "next_index", "problems"}`` of the batches."""
    from opentine import _json_shallow

    leaves: list[bytes] = []
    indexes: list[int] = []
    problems: list[str] = []
    first = expect = None
    for oid in batch_ids:
        row = _ingest_holds.read(repo, oid, BATCH)
        if row is None or not row["signed"] or row["claim"].get("stream") != stream:
            problems.append(f"{oid} is not a signed batch of stream {stream}")
            continue
        claim = row["claim"]
        if expect is not None and claim.get("first_index") != expect:
            problems.append(f"{oid} does not continue the index range at {expect}")
        first = claim.get("first_index") if first is None else first
        expect = claim.get("next_index")
        text = claim.get("events")
        for line in text.split("\n") if isinstance(text, str) else ():
            if not line:
                continue
            try:
                index = _json_shallow.loads(line).get("i")
            except (ValueError, RecursionError, AttributeError):
                index = None
            if isinstance(index, bool) or not isinstance(index, int):
                problems.append(f"{oid} stores a line without an integer index")
                continue
            leaves.append(episode_leaf(line.encode("utf-8")))
            indexes.append(index)
            if len(leaves) > MAX_EPISODES:
                raise IngestError(f"a segment holds at most {MAX_EPISODES} episodes")
    return {"leaves": leaves, "indexes": indexes, "first_index": first,
            "next_index": expect, "problems": problems}  # fmt: skip


def committed_in(entries: list[bytes], claim: dict[str, Any]) -> bool:
    """Whether op log *entries* hold the seal note of the segment *claim* at its index."""
    from opentine import _json_shallow

    log = claim.get("log") if isinstance(claim.get("log"), dict) else {}
    index, batches = log.get("index"), claim.get("batches")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(entries):
        return False
    if not isinstance(batches, list) or not batches:
        return False
    try:
        entry = _json_shallow.loads(entries[index].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    want = note_text(claim.get("stream"), claim.get("seq"), claim.get("root"), batches[-1])
    return isinstance(entry, dict) and entry.get("note") == want


def read(repo: Any, oid: str) -> dict[str, Any] | None:
    return _ingest_holds.read(repo, oid, CONVENTION)


def seal(repo: Any, stream: str, key: Any, *, at_ms: int,
         through: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Seal the batches since the previous segment; the segment's ``id`` and claim."""
    from opentine.repository import _oplog, _write_batch

    _ingest_policy.stream_name(stream)
    _signer_ok(repo, key)
    previous = _ingest_holds.head(repo, stream, prefix=INGEST_SEGMENT)
    prior = read(repo, previous) if previous else None
    if previous and (prior is None or not prior["signed"]):
        raise IngestError(f"stream {stream} segment head {previous} is unreadable")
    stop = prior["claim"]["batches"][-1] if prior else None
    through = through or _ingest_holds.head(repo, stream)
    if through is None or through == stop:
        raise IngestError(f"stream {stream} has no batch to seal since its last segment")
    ids = batch_range(repo, stream, through, stop)
    found = episodes(repo, stream, ids)
    if found["problems"]:
        raise IngestError(found["problems"][0])
    if not found["leaves"]:
        raise IngestError("the batches to seal hold no captured episode")
    root = "sha256:" + Tree(found["leaves"]).root().hex()
    seq = prior["claim"]["seq"] + 1 if prior else 0
    entry = _oplog._Op("tine ingest seal", None)
    entry.note = note_text(stream, seq, root, ids[-1])
    index = _oplog.record(repo.path, entry, [])  # the commitment, before the segment exists
    at = rfc3339_utc(at_ms / 1000)
    claim = {"convention": CONVENTION, "stream": stream, "seq": seq, "previous": previous,
             "batches": ids, "first_index": found["first_index"],
             "next_index": found["next_index"], "episodes": len(found["leaves"]),
             "root": root, "log": {"origin": _oplog.ORIGIN, "index": index},
             "sealed_at": at}  # fmt: skip
    with _write_batch.batched(repo):
        target = _ingest_policy.anchor(repo, stream)
        oid = _ingest_holds.write(repo, target, claim, key, previous=previous, signed_at=at)
    _ingest_holds.move_head(repo, stream, previous, oid, prefix=INGEST_SEGMENT)
    return {"id": oid, **claim}


def chain(repo: Any, stream: str) -> tuple[list[str], str | None]:
    """Segment ids oldest first, and the id where the walk broke (``None``: intact)."""
    ids: list[str] = []
    cursor = _ingest_holds.head(repo, stream, prefix=INGEST_SEGMENT)
    while cursor is not None:
        row = read(repo, cursor)
        if cursor in ids or row is None or row["claim"].get("stream") != stream:
            return ids[::-1], cursor
        ids.append(cursor)
        cursor = row["claim"].get("previous")
    return ids[::-1], None


__all__ = ["CONVENTION", "MAX_BATCHES", "batch_range", "chain", "committed_in", "episodes",
           "note_text", "read", "seal"]  # fmt: skip
