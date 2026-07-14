"""Transport-independent remote protocol and authorization logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from opentine.kernel import ObjectEnvelope, validate_links
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend, TenantRepo, valid_tenant
from opentine.remote.interfaces import (
    AdmissionPolicy,
    AuditEvent,
    AuthorizationPolicy,
    Identity,
    IdentityProvider,
)
from opentine.repository.pack import create_pack, inspect_pack, negotiate


class AllowAdmission:
    def admit(self, identity: Identity, operation: str, facts: dict[str, Any]) -> None:
        return None


class RemoteService:
    def __init__(
        self,
        objects: FilesystemObjectStore,
        index: SQLiteBackend,
        identities: IdentityProvider,
        authorization: AuthorizationPolicy,
        *,
        admission: AdmissionPolicy | None = None,
    ):
        self.objects = objects
        self.index = index
        self.identities = identities
        self.authorization = authorization
        self.admission = admission or AllowAdmission()

    @staticmethod
    def capabilities() -> dict[str, Any]:
        return {
            "authentication": ["bearer", "oidc"],
            "filters": ["depth", "run", "object_type"],
            "object_format": "opentine-v3",
            "pack_format": "TINEPACK3",
            "protocol": "opentine-remote/1",
            "resumable_upload": True,
            "roles": ["reader", "writer", "admin"],
        }

    def authenticate(self, headers: dict[str, str]) -> Identity:
        return self.identities.authenticate({key.lower(): value for key, value in headers.items()})

    def _authorize(self, identity: Identity, action: str, tenant: str) -> None:
        valid_tenant(tenant)
        if not self.authorization.authorize(identity, action, tenant):
            self._audit(identity, tenant, action, "denied", {})
            raise PermissionError(f"not authorized for {action} in {tenant}")

    def _audit(
        self,
        identity: Identity,
        tenant: str,
        action: str,
        outcome: str,
        details: dict[str, Any],
    ) -> None:
        self.index.append(
            AuditEvent(
                str(uuid.uuid4()),
                datetime.now(UTC).isoformat(),
                tenant,
                identity.subject,
                action,
                outcome,
                details,
            )
        )

    def list_refs(self, identity: Identity, tenant: str) -> dict[str, str]:
        self._authorize(identity, "read_ref", tenant)
        refs = self.index.list_refs(tenant)
        self._audit(identity, tenant, "read_ref", "ok", {"refs": len(refs)})
        return refs

    def verify_audit_chain(self, identity: Identity, tenant: str) -> dict[str, Any]:
        self._authorize(identity, "audit", tenant)
        self._audit(identity, tenant, "audit", "requested", {})
        return {"ok": self.index.verify_audit_chain(), "head": self.index.audit_head()}

    def negotiate(
        self,
        identity: Identity,
        tenant: str,
        wants: list[str],
        haves: list[str],
        *,
        depth: int | None = None,
    ) -> list[str]:
        self._authorize(identity, "negotiate", tenant)
        missing = negotiate(TenantRepo(tenant, self.objects), wants, haves, depth=depth)
        self._audit(identity, tenant, "negotiate", "ok", {"missing": len(missing)})
        return missing

    def fetch_pack(
        self,
        identity: Identity,
        tenant: str,
        wants: list[str],
        haves: list[str],
        *,
        depth: int | None = None,
        object_types: set[str] | None = None,
    ) -> bytes:
        self._authorize(identity, "fetch", tenant)
        repo = TenantRepo(tenant, self.objects)
        missing = negotiate(repo, wants, haves, depth=depth)
        if object_types:
            selected = {oid for oid in missing if oid.split(":", 1)[0] in object_types}
            # Dependencies are retained even when the requested roots are filtered.
            selected.update(
                link
                for oid in tuple(selected)
                for link in validate_links(repo.get(oid))
                if link in missing
            )
            missing = sorted(selected)
        data = create_pack(repo, missing)
        self._audit(identity, tenant, "fetch", "ok", {"objects": len(missing)})
        return data

    def install_pack(self, identity: Identity, tenant: str, data: bytes) -> tuple[str, int]:
        self._authorize(identity, "upload", tenant)
        pack_id, packed, shallow = inspect_pack(data)
        unresolved = [oid for oid in shallow if not self.objects.has(tenant, oid)]
        if unresolved:
            raise ValueError("remote upload has unresolved shallow boundaries")
        self.admission.admit(
            identity,
            "upload",
            {
                "bytes": len(data),
                "objects": len(packed),
                "phase": "install",
                "tenant": tenant,
            },
        )
        packed_ids = {oid for oid, _ in packed}
        for oid, raw in packed:
            envelope = ObjectEnvelope.decode(raw, oid)
            for link in validate_links(envelope):
                if link not in packed_ids and not self.objects.has(tenant, link):
                    raise ValueError(f"pack has unresolved link: {link}")
        for oid, raw in packed:
            self.objects.put(tenant, oid, raw)
            self.index.record_object(tenant, oid, len(raw))
        self._audit(identity, tenant, "upload", "ok", {"objects": len(packed), "pack": pack_id})
        return pack_id, len(packed)

    def update_ref(
        self,
        identity: Identity,
        tenant: str,
        name: str,
        new_oid: str,
        expected_old: str | None,
    ) -> bool:
        self._authorize(identity, "update_ref", tenant)
        if not self.objects.has(tenant, new_oid):
            raise KeyError(new_oid)
        self.admission.admit(
            identity, "update_ref", {"name": name, "new": new_oid, "tenant": tenant}
        )
        changed = self.index.update_ref(tenant, name, new_oid, expected_old)
        self._audit(
            identity,
            tenant,
            "update_ref",
            "ok" if changed else "conflict",
            {"expected_old": expected_old, "name": name, "new": new_oid},
        )
        return changed

    def search(self, identity: Identity, tenant: str, query: dict[str, Any]) -> list[str]:
        self._authorize(identity, "search", tenant)
        results = self.index.search(tenant, query)
        self._audit(identity, tenant, "search", "ok", {"results": len(results)})
        return results
