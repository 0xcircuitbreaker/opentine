"""Close a pack install against a concurrent purge (``tine serve ... purge``).

Purge runs beside a live server and removes old objects no ref reaches. An
install skips an object the store already has, and links to objects it does not
carry, so an orphaned run pushed again -- or a new run sharing an old blob --
relied on exactly the objects a purge could be removing: a batch landing between
the install and its ref update left the ref on a run with missing objects.

After writing, the install re-checks every object it wrote or links to inside
the index's write transaction, which purge also takes for each batch, and
refreshes each one's age. Either the fence runs first, and purge's in-lock age
check then keeps those objects, or the batch runs first, and the fence restores
what the pack carries and refuses a pack whose links are gone.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

_ROUNDS = 3


def install_objects(
    objects: Any,
    index: Any,
    tenant: str,
    order: list[tuple[str, bytes]],
    targets: dict[str, str | None],
    linked: list[str],
) -> None:
    """Write *order* (dependency order) and record it, then fence it against purge."""

    def write(oid: str, raw: bytes) -> None:
        objects.put(tenant, oid, raw)
        index.record_object(tenant, oid, len(raw), targets[oid])

    for oid, raw in order:
        write(oid, raw)
    fence_install(objects, index, tenant, order, linked, write)


def fence_install(
    objects: Any,
    index: Any,
    tenant: str,
    written: list[tuple[str, bytes]],
    linked: list[str],
    restore: Callable[[str, bytes], None],
) -> None:
    touch = getattr(objects, "touch", None)
    exclusive = getattr(index, "exclusive", None)
    if not callable(touch) or not callable(exclusive):
        return  # only the reference SQLite + filesystem storage is ever purged
    for _ in range(_ROUNDS):
        with exclusive():
            gone = [oid for oid in linked if not touch(tenant, oid)]
            missing = [(oid, raw) for oid, raw in written if not touch(tenant, oid)]
        if gone:
            raise ValueError(f"pack links to an object removed while it installed: {gone[0]}")
        if not missing:
            return
        for oid, raw in missing:  # dependency order, as written
            restore(oid, raw)
    raise ValueError("objects kept being removed while the pack installed; retry the push")
