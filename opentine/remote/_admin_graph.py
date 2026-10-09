"""A tenant's object graph as purge sees it: links plus reverse associations."""

from __future__ import annotations

from collections.abc import Iterable

from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend

_ASSOCIATION_TYPES = ("annotation", "attestation")


class ObjectGraph:
    """Decoded links and reverse associations of a tenant's objects, loaded on demand."""

    def __init__(self, objects: FilesystemObjectStore, tenant: str):
        self.objects, self.tenant = objects, tenant
        self.links: dict[str, tuple[str, ...]] = {}
        self.associations: dict[str, set[str]] = {}
        self.unreadable: set[str] = set()
        #: The tenant's stored objects when scanned, and the index clock just before.
        #: An object recorded since then but not listed was installed after the scan;
        #: one already listed is covered by purge's grace window instead (the clock
        #: has one-second resolution, so ``since`` cannot tell the two apart).
        self.listed: set[str] = set()
        self.since = ""

    def load(self, oid: str) -> None:
        if oid in self.links or oid in self.unreadable:
            return
        try:
            envelope = ObjectEnvelope.decode(self.objects.get(self.tenant, oid), oid)
            links = validate_links(envelope)
            payload = envelope.payload() if envelope.object_type in _ASSOCIATION_TYPES else None
        except (KeyError, KernelError, ValueError):
            self.unreadable.add(oid)
            return
        self.links[oid] = links
        target = payload.get("target_id") if isinstance(payload, dict) else None
        if isinstance(target, str):
            self.associations.setdefault(target, set()).add(oid)

    def live(self, roots: Iterable[str], excluded: set[str] | frozenset = frozenset()) -> set[str]:
        """What *roots* reach by links and by associations not in *excluded*."""
        live: set[str] = set()
        stack = list(roots)
        while stack:
            oid = stack.pop()
            if oid in live:
                continue
            live.add(oid)
            self.load(oid)
            stack.extend(self.links.get(oid, ()))
            stack.extend(self.associations.get(oid, set()) - excluded)
        return live


def scan(objects: FilesystemObjectStore, index: SQLiteBackend, tenant: str) -> ObjectGraph:
    """Decode every stored object; anything the index records from now on is newer."""
    graph = ObjectGraph(objects, tenant)
    graph.since = index.clock()
    graph.listed = set(objects.list(tenant))
    for oid in sorted(graph.listed):
        graph.load(oid)
    return graph
