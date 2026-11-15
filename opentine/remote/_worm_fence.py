"""Chunk fences: an upload that reuses a chunk never loses it to a delete (0.52).

A chunked object's ``chunked/`` record names its chunk digests (one per line)
and is written *before* the chunks are checked or uploaded. Removing a chunk
(``delete`` of its last object, or ``tine gc --sweep-expired``) is fenced:

1. the reaper writes ``<tenant>/chunk-fences/<digest>/<token>`` (no retention);
2. it then reads every ``chunked/`` record and keeps any chunk one names;
3. it deletes the rest (never inside retention or a legal hold), then removes
   its fences.

An upload writes its record, then waits while a fence for a chunk exists, and
only then checks that the chunk is there (uploading it again if not). Either
the reaper's step 2 sees the upload's record (the chunk is kept), or the upload
sees the fence (and re-checks after the reaper has finished): a concurrent
upload of a chunk being deleted is never lost. Records written by 0.49-0.51
are empty; their object's manifest is read instead.

A reaper that has held its fences longer than ``FENCE_STALE / 2`` stops
deleting, so an upload may treat a fence older than ``FENCE_STALE`` as left by
a crashed reaper. Fences, like the records, are server bookkeeping inside the
bucket, not a wire format.
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Iterable
from typing import Any

FENCES = "chunk-fences"
FENCE_STALE = 120.0
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def record_body(digests: Iterable[str]) -> bytes:
    return "".join(f"{d}\n" for d in digests).encode("ascii")


def record_digests(body: bytes) -> list[str] | None:
    """The digests a record names, or None for a 0.49-0.51 (empty) record."""
    lines = body.decode("ascii", "replace").split()
    if not lines:
        return None
    if not all(_DIGEST.match(line) for line in lines):
        raise ValueError("malformed chunk record")
    return lines


class WormFenceMixin:
    client: Any
    prefix: str
    fence_poll = 0.05
    fence_wait = 60.0

    def _fences(self, tenant: str, digest: str) -> str:
        return f"{self.prefix}{tenant}/{FENCES}/{digest}/"

    def _fence_stale(self, key: str) -> bool:
        try:
            return time.time() - float(self.client.get(key).decode("ascii")) > FENCE_STALE
        except (KeyError, ValueError):
            return False  # gone (or unreadable): the next listing decides

    def await_unfenced(self, tenant: str, digest: str) -> None:
        """Return once no live reaper fences *digest*; ``OSError`` if one outlasts the wait."""
        deadline = time.monotonic() + self.fence_wait
        while True:
            live = [k for k in self.client.keys(self._fences(tenant, digest))
                    if not self._fence_stale(k)]  # fmt: skip
            if not live:
                return
            if time.monotonic() > deadline:
                raise OSError(f"chunk {digest} is being deleted; retry the upload")
            time.sleep(self.fence_poll)

    def chunks_in_use(self, tenant: str) -> set[str]:
        """Every chunk a ``chunked/`` record names, finished upload or not."""
        base = f"{self.prefix}{tenant}/chunked/"
        used: set[str] = set()
        for key in self.client.keys(base):
            try:
                digests = record_digests(self.client.get(key))
            except KeyError:
                continue  # deleted while listing
            if digests is None:  # a 0.49-0.51 record: its object's manifest names them
                object_type, _, digest = key[len(base) :].partition("/")
                oid = f"{object_type}:sha256:{digest}"
                if self.has(tenant, oid):  # type: ignore[attr-defined]
                    digests = self._chunk_digests(tenant, oid)  # type: ignore[attr-defined]
            used.update(digests or ())
        return used

    def reap_chunks(self, tenant: str, digests: Iterable[str]) -> dict[str, int]:
        """Delete the chunks among *digests* that nothing uses and nothing retains."""
        token = uuid.uuid4().hex
        counts = {"swept": 0, "retained": 0, "live": 0}
        fenced: list[str] = []
        started = time.monotonic()
        try:
            for digest in sorted(set(digests)):
                self.client.put(self._fences(tenant, digest) + token,
                                f"{time.time():.3f}".encode("ascii"),
                                mode=None, until=None, legal_hold=False)  # fmt: skip
                fenced.append(digest)
            in_use = self.chunks_in_use(tenant)
            for digest in fenced:
                if digest in in_use:
                    counts["live"] += 1
                    continue
                if time.monotonic() - started > FENCE_STALE / 2:
                    break  # an upload may now take our fences for stale: stop deleting
                key = self._chunk_key(tenant, digest)  # type: ignore[attr-defined]
                try:
                    if self.client.retention(key).locked():
                        counts["retained"] += 1
                        continue
                    self.client.delete(key)
                    counts["swept"] += 1
                except KeyError:
                    pass  # already gone
                except PermissionError:
                    counts["retained"] += 1  # the cloud keeps it: a later sweep's job
        finally:
            for digest in fenced:
                try:
                    self.client.delete(self._fences(tenant, digest) + token)
                except (KeyError, PermissionError):
                    pass
        return counts

    def sweep_expired(self, tenant: str) -> dict[str, Any]:
        """``tine gc --sweep-expired``: remove the tenant's orphan chunks whose
        retention has ended. A chunk any record names is never touched."""
        base = f"{self.prefix}{tenant}/chunks/"
        stored = [k[len(base) :] for k in self.client.keys(base)]
        orphans = [d for d in stored if _DIGEST.match(d)]
        orphans = sorted(set(orphans) - self.chunks_in_use(tenant))
        counts = self.reap_chunks(tenant, orphans) if orphans else {
            "swept": 0, "retained": 0, "live": 0}  # fmt: skip
        return {"tenant": tenant, "chunks": len(stored), **counts}


__all__ = ["FENCES", "FENCE_STALE", "WormFenceMixin", "record_body", "record_digests"]
