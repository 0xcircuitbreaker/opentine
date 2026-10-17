"""How much one pack's association phase may read, in total.

Each run's associations are tried, and a set that does not fit is rolled back:
its objects leave the pack and its charge against the body and source budgets is
returned, so the next run starts from what the graph left. Rolling back the
charge cannot return the work: every object the failed walk read was still read,
decrypted, decoded and hash-checked. With the body budget alone limiting each
attempt, a writer could attach the same body-sized set of evidence to every run
of a history, and one fetch of that history read the set again for each run --
thousands of times over, while holding one of the server's few pack slots.

:class:`WorkBudget` is the total, and it is never rolled back. Every object the
association phase reads is charged *before* it is read, at its stored size, and
once the total reaches a small multiple of the body budget no further object is
read: the remaining runs keep their graph and are reported as omitted.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError

#: Total association work, as a multiple of the pack body budget. A pack whose
#: associations fit reads them about once; the rest is room for sets that are
#: tried and do not fit.
WORK_FACTOR = 2

#: Room left in the pack body for the shallow list and the JSON framing that
#: ``create_pack`` adds around the objects themselves.
FRAMING_RESERVE = 1024 * 1024
_ENTRY_OVERHEAD = 96


class WorkExhausted(KernelError):
    """The association phase has read all it may for this pack."""


class Sizes:
    """Each object's encoded pack size, looked up once (``raw_size`` does not decrypt)."""

    def __init__(self, repo: Any):
        self.repo = repo
        self.known: dict[str, int] = {}

    def __call__(self, oid: str) -> int:
        size = self.known.get(oid)
        if size is None:
            reader = getattr(self.repo, "raw_size", None)
            raw = reader(oid) if callable(reader) else len(self.repo.raw(oid))
            size = 4 * ((int(raw) + 2) // 3) + len(oid) + _ENTRY_OVERHEAD
            self.known[oid] = size
        return size


class WorkBudget:
    """Bytes the association phase has read (charged before each read), never returned."""

    def __init__(self, sizes: Sizes, max_body: int | None):
        self.sizes = sizes
        self.limit = None if max_body is None else WORK_FACTOR * max_body
        self.spent = 0

    def spend(self, oid: str) -> None:
        if self.limit is None:
            return
        size = self.sizes(oid)
        if self.spent + size > self.limit:
            self.spent = self.limit
            raise WorkExhausted("pack association work budget exhausted")
        self.spent += size


__all__ = ["FRAMING_RESERVE", "WORK_FACTOR", "Sizes", "WorkBudget", "WorkExhausted"]
