"""Tenant-scoped repository adapter used for pack negotiation."""

from opentine.kernel import ObjectEnvelope, validate_links
from opentine.remote.backend import valid_tenant
from opentine.remote.interfaces import ObjectStore
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph


class TenantRepo:
    def __init__(self, tenant: str, objects: ObjectStore):
        self.tenant = valid_tenant(tenant)
        self.objects = objects

    def has(self, oid: str) -> bool:
        return self.objects.has(self.tenant, oid)

    def raw(self, oid: str) -> bytes:
        return self.objects.get(self.tenant, oid)

    def get(self, oid: str) -> ObjectEnvelope:
        envelope = ObjectEnvelope.decode(self.raw(oid), oid)
        validate_links(envelope, self.has)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return envelope

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        return self.objects.list(self.tenant, limit=limit, truncate=truncate)


class PackedTenantRepo(TenantRepo):
    """Read-through view used to validate a pack before storing any object."""

    def __init__(self, tenant: str, objects: ObjectStore, packed: dict[str, bytes]):
        super().__init__(tenant, objects)
        self.packed = packed

    def has(self, oid: str) -> bool:
        return oid in self.packed or super().has(oid)

    def raw(self, oid: str) -> bytes:
        return self.packed.get(oid) or super().raw(oid)
