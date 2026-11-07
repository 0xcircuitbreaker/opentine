"""``BLOB_DELTA``: a blob stored as the middle that differs from a base blob (0.40).

The fourth stored form of a version-3 pack (``_run_delta`` holds the other
three). It is the shipped half of the 0.40 CDC bake-off
(``docs/bench/0.40-cdc-bakeoff.md``): a "middle-out" delta keeps the body
bytes a blob shares with a base at its start and at its end and stores only
what lies between, so a transcript that grows by one turn per save costs one
turn, not the whole history again. The block codec then compresses the
middles. Stored bytes::

    <target header line> "\\n" <base oid> " " <prefix> " " <suffix> "\\n" <middle>

where *prefix* and *suffix* count body bytes (the part after the header line)
taken from the base. The base is any other blob of the **same pack**, named by
id, so a reader follows ids: it refuses a chain that revisits an id (a cycle)
or is longer than ``MAX_DELTA_DEPTH``, and checks every object it rebuilds,
each base included, against its own id (``_pack_v3.resolve``).

Ids, digests and signatures never see this form: they are over the rebuilt
canonical bytes. Packs holding it are written only in a repository that opted
in (``min_reader`` 0.40.0, ``_gc_deltas``), and transfer (wire packs, bundles)
always sends canonical objects, so an older reader never meets it.
"""

from __future__ import annotations

import re

from opentine.kernel import KernelError
from opentine.repository._run_delta import KEYFRAME_INTERVAL, split

#: How many earlier blobs (in pack order) a writer scores as bases.
WINDOW = 16
#: A delta is kept only if it stores this many fewer bytes than the blob.
MIN_SAVING = 256
_LINE = re.compile(rb"blob:sha256:([0-9a-f]{64}) (0|[1-9][0-9]{0,9}) (0|[1-9][0-9]{0,9})")


def _common_prefix(a: bytes, b: bytes) -> int:
    """Length of the shared prefix, by bisection over slice compares (C speed)."""
    low, high = 0, min(len(a), len(b))
    while low < high:
        mid = (low + high + 1) // 2
        if a[:mid] == b[:mid]:
            low = mid
        else:
            high = mid - 1
    return low


def _common_suffix(a: bytes, b: bytes, limit: int) -> int:
    low, high = 0, limit
    while low < high:
        mid = (low + high + 1) // 2
        if a[len(a) - mid :] == b[len(b) - mid :]:
            low = mid
        else:
            high = mid - 1
    return low


def shared(body: bytes, base_body: bytes) -> tuple[int, int]:
    """(prefix, suffix) body bytes *body* shares with *base_body*, never overlapping."""
    prefix = _common_prefix(body, base_body)
    room = min(len(body), len(base_body)) - prefix
    return prefix, _common_suffix(body, base_body, room)


def encode(raw: bytes, base_oid: str, base_raw: bytes) -> bytes | None:
    """*raw* as a ``BLOB_DELTA`` against *base_raw*, or ``None`` when it would not pay."""
    try:
        header, body = split(raw)
        _, base_body = split(base_raw)
    except KernelError:
        return None
    prefix, suffix = shared(body, base_body)
    middle = body[prefix : len(body) - suffix]
    line = f"{base_oid} {prefix} {suffix}".encode()
    stored = header + b"\n" + line + b"\n" + middle
    if len(stored) + MIN_SAVING > len(raw) or not _LINE.fullmatch(line):
        return None
    return stored if apply(parse(stored), base_raw) == raw else None


def parse(stored: bytes) -> tuple[bytes, str, int, int, bytes]:
    """(target header, base oid, prefix, suffix, middle), its shape checked."""
    header, rest = split(stored)
    line, sep, middle = rest.partition(b"\n")
    match = _LINE.fullmatch(line) if sep else None
    if match is None:
        raise KernelError("blob delta is malformed")
    base = "blob:sha256:" + match.group(1).decode()
    return header, base, int(match.group(2)), int(match.group(3)), middle


def base_of(stored: bytes) -> str:
    return parse(stored)[1]


def apply(delta: tuple[bytes, str, int, int, bytes], base_raw: bytes) -> bytes:
    """The bytes *delta* rebuilds from *base_raw* (the caller checks them against the id)."""
    header, _, prefix, suffix, middle = delta
    _, base_body = split(base_raw)
    if prefix + suffix > len(base_body):
        raise KernelError("blob delta takes more bytes than its base has")
    return header + b"\n" + base_body[:prefix] + middle + base_body[len(base_body) - suffix :]


def choose(
    order: list[tuple[str, bytes]], window: int = WINDOW, max_depth: int = KEYFRAME_INTERVAL
) -> dict[str, tuple[str, bytes]]:
    """oid -> (base oid, stored delta) for blobs of *order* worth storing as deltas.

    Bases are picked "middle-out": among the last *window* blobs before it in
    *order* (pack order keeps one run's blobs together), the one sharing the
    longest prefix plus suffix. A blob is never a base past depth *max_depth*,
    so writer chains stay well inside the reader's ``MAX_DELTA_DEPTH``.
    """
    chosen: dict[str, tuple[str, bytes]] = {}
    depth: dict[str, int] = {}
    recent: list[tuple[str, bytes, bytes]] = []  # (oid, raw, body)
    for oid, raw in order:
        if not oid.startswith("blob:"):
            continue
        try:
            body = split(raw)[1]
        except KernelError:
            continue
        best, score = None, MIN_SAVING
        for base_oid, base_raw, base_body in recent:
            if depth.get(base_oid, 0) >= max_depth:
                continue
            got = sum(shared(body, base_body))
            if got > score:
                best, score = (base_oid, base_raw), got
        if best is not None:
            stored = encode(raw, *best)
            if stored is not None:
                chosen[oid] = (best[0], stored)
                depth[oid] = depth.get(best[0], 0) + 1
        recent = (recent + [(oid, raw, body)])[-window:]
    return chosen
