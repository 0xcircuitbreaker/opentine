"""Tombstones over ``opentine-remote/1``: what ``tine push`` and ``fetch`` carry (0.46).

A purged blob is a shallow boundary of any pack that would have carried it. A
remote that lists ``caps.tombstones`` accepts such a pack only once it has the
blob's tombstone, so :func:`send` ``PUT``\\ s the tombstone of every purged
boundary before the pack is uploaded; a remote that does not list it is not
sent any (the push then fails there exactly as it did before 0.46, naming the
unresolved boundary). After a fetch, :func:`receive` asks for the tombstone of
each blob boundary the pack left out and this repository does not hold, and
stores the well-formed ones (``_tombstones.install``): a ``404`` means the
remote has none, which is a plain shallow boundary. Nothing is signed here.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from opentine.repository import _tombstones
from opentine.repository.pack import inspect_pack

#: The most tombstones one fetch asks for; the rest stay plain boundaries.
MAX_FETCHED = 1_000


def boundaries(pack: bytes) -> list[str]:
    """The blob oids a pack leaves out (its shallow list)."""
    return [oid for oid in inspect_pack(pack)[2] if oid.startswith("blob:")]


def send(repo: Any, client: Any, request_json: Any, prefix: str, caps: dict, pack: bytes,
         timeout: float) -> int:  # fmt: skip
    """PUT the tombstone of every purged boundary of *pack*; return how many were sent."""
    if not caps.get("tombstones"):
        return 0
    records = _tombstones.carried(repo, boundaries(pack))
    for record in records:
        path = f"{prefix}/tombstones/{quote(record['oid'], safe='')}"
        request_json(client, "PUT", path, json=record, allowed=(201,), max_seconds=timeout)
    return len(records)


def receive(repo: Any, client: Any, request_json: Any, prefix: str, caps: dict, pack: bytes,
            timeout: float) -> int:  # fmt: skip
    """Fetch and store the tombstones of *pack*'s missing blob boundaries; return the count."""
    if not caps.get("tombstones"):
        return 0
    wanted = [oid for oid in boundaries(pack) if not repo.has(oid)]
    wanted = [oid for oid in wanted if _tombstones.read(repo, oid) is None][:MAX_FETCHED]
    found = []
    for oid in wanted:
        path = f"{prefix}/tombstones/{quote(oid, safe='')}"
        status, body = request_json(client, "GET", path, allowed=(200, 404), max_seconds=timeout)
        record = body.get("tombstone") if status == 200 and isinstance(body, dict) else None
        if isinstance(record, dict) and record.get("oid") == oid:
            found.append(record)
    return _tombstones.install(repo, found)


__all__ = ["MAX_FETCHED", "boundaries", "receive", "send"]
