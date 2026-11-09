"""Link verification and dependency-ordered write plan for pushed packs."""

from __future__ import annotations

from opentine.kernel import validate_links
from opentine.remote._tenant_repo import PackedTenantRepo
from opentine.remote._tombstone_store import tombstoned
from opentine.remote.interfaces import ObjectStore
from opentine.repository._pack_install import _dependency_order


def verified_write_order(
    tenant: str,
    objects: ObjectStore,
    packed: list[tuple[str, bytes]],
    shallow: list[str],
) -> list[tuple[str, bytes]]:
    """Validate a pushed pack's links and return its dependency-safe write order.

    Materializing in manifest (sorted-oid) order meant an interrupted install —
    ENOSPC, OOM, a server restart mid-loop — could durably store an annotation
    or run whose targets were never written; every semantic read of that object
    (get, fetch_pack, negotiate) then failed with "missing linked object" until
    a client re-pushed the full closure. Writing dependencies before dependents
    (the ordering the local installer adopted in _pack_install) keeps every
    prefix of the write sequence link-closed, so a retried install converges.
    """
    packed_ids = {oid for oid, _ in packed}
    view = PackedTenantRepo(tenant, objects, dict(packed))
    internal: dict[str, set[str]] = {}
    external: set[str] = set()
    for oid, _ in packed:
        links = validate_links(view.get(oid))
        internal[oid] = {link for link in links if link in packed_ids}
        for link in links:
            if link in packed_ids:
                continue
            external.add(link)
            if not objects.has(tenant, link) and not tombstoned(objects, tenant, link):
                raise ValueError(f"pack has unresolved link: {link}")
    if set(shallow) != external:
        raise ValueError("pack shallow boundaries do not match its external links")
    # 0.46: a purged blob stays purged. A writer that still holds its bytes
    # cannot restore them by pushing them again; the tombstone keeps every link
    # to it resolved, so the blob is dropped from the write plan.
    kept = [(oid, raw) for oid, raw in packed if not tombstoned(objects, tenant, oid)]
    return _dependency_order(kept, internal)
