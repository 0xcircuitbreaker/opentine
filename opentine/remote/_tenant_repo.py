"""Tenant-scoped repository adapter used for pack negotiation."""

from opentine.kernel import ObjectEnvelope, validate_links
from opentine.remote.backend import valid_tenant
from opentine.remote.interfaces import ObjectStore


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
        return envelope

    def iter_oids(self) -> list[str]:
        return self.objects.list(self.tenant)
