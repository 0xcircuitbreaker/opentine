"""Transport-independent remote protocol and authorization logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from opentine.kernel import parse_oid, validate_links
from opentine.remote._admission import AllowAdmission
from opentine.remote._association_budget import admitted_associations
from opentine.remote._audit_verify import audit_report
from opentine.remote._install_fence import install_objects
from opentine.remote._pack_ingest import verified_write_order
from opentine.remote._ref_policy import ref_permission
from opentine.remote._request_audit import AuthorizationDenied, audit_tenant
from opentine.remote._tenant_repo import TenantRepo, admit_annotation_ref, validate_ref_listing
from opentine.remote.backend import MAX_CONTROL_RESULTS, valid_tenant
from opentine.remote.interfaces import (
    AdmissionPolicy,
    AuditEvent,
    AuditSink,
    AuthorizationPolicy,
    Identity,
    IdentityProvider,
    IndexBackend,
    ObjectStore,
)
from opentine.repository._refs import normalize_ref, validate_ref_target
from opentine.repository._semantic_view import SemanticView
from opentine.repository.pack import MAX_PACK_BODY_BYTES, create_pack, inspect_pack, negotiate


class RemoteService:
    def __init__(
        self,
        objects: ObjectStore,
        index: IndexBackend,
        identities: IdentityProvider,
        authorization: AuthorizationPolicy,
        *,
        admission: AdmissionPolicy | None = None,
        audit: AuditSink | None = None,
    ):
        self.objects = objects
        self.index = index
        self.identities = identities
        self.authorization = authorization
        self.admission = admission or AllowAdmission()
        self.audit = audit or index
        if not callable(getattr(self.audit, "append", None)):
            raise TypeError("remote service requires an AuditSink")

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
            # Under the identity's tenant when it names one, else the one it asked
            # for: an invalid tenant claim used to make the denial unwritable.
            where = audit_tenant(identity.tenant, tenant)
            self._audit(identity, where, action, "denied", {"requested_tenant": tenant})
            raise AuthorizationDenied(f"not authorized for {action} in {tenant}")

    def _audit(
        self,
        identity: Identity,
        tenant: str,
        action: str,
        outcome: str,
        details: dict[str, Any],
    ) -> None:
        self.audit.append(
            AuditEvent(
                str(uuid.uuid4()),
                datetime.now(UTC).isoformat(),
                tenant,
                identity.subject,
                action,
                outcome,
                details,
            )  # fmt: skip
        )

    def list_refs(self, identity: Identity, tenant: str) -> dict[str, str]:
        self._authorize(identity, "read_ref", tenant)
        refs = self.index.list_refs(tenant)
        validate_ref_listing(tenant, self.objects, self.index, refs)
        self._audit(identity, tenant, "read_ref", "ok", {"refs": len(refs)})
        return refs

    def verify_audit_chain(self, identity: Identity, tenant: str) -> dict[str, Any]:
        self._authorize(identity, "audit", tenant)
        return audit_report(self.audit)

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
        missing = negotiate(TenantRepo(tenant, self.objects, self.index), wants, haves, depth=depth)
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
        omitted: list[str] | None = None,
    ) -> bytes:
        """A pack for *wants*; runs whose associations did not fit go to *omitted*."""
        self._authorize(identity, "fetch", tenant)
        repo = SemanticView(
            TenantRepo(tenant, self.objects, self.index), max_source_bytes=MAX_PACK_BODY_BYTES
        )
        short: list[str] = []
        missing = negotiate(repo, wants, haves, depth=depth, omitted=short)
        if object_types:
            selected = {oid for oid in missing if oid.split(":", 1)[0] in object_types}
            selected.update(
                link
                for oid in tuple(selected)
                for link in validate_links(repo.get(oid))
                if link in missing
            )
            missing = sorted(selected)
        data = create_pack(repo, missing)
        details: dict[str, Any] = {"objects": len(missing)}
        if short:
            details["associations_omitted"] = len(short)
            if omitted is not None:
                omitted.extend(short)
        self._audit(identity, tenant, "fetch", "ok", details)
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
        # Dependency order, not manifest order: any interrupted write prefix
        # must stay link-closed so already-durable objects remain readable.
        order = verified_write_order(tenant, self.objects, packed, shallow)
        with admitted_associations(tenant, self.index, order) as targets:
            install_objects(self.objects, self.index, tenant, order, targets, list(shallow))
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
        name = normalize_ref(name)
        extra = ref_permission(name, expected_old)
        if extra:  # promotions/*, or moving an existing tags/* ref (_ref_policy)
            self._authorize(identity, extra, tenant)
        parse_oid(new_oid)
        if expected_old is not None:
            parse_oid(expected_old)
        if not self.objects.has(tenant, new_oid):
            raise KeyError(new_oid)
        target = TenantRepo(tenant, self.objects, self.index).get(new_oid)
        validate_ref_target(name, target.object_type, target.payload())
        if target.object_type == "annotation":
            admit_annotation_ref(tenant, self.objects, self.index, name, target)
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

    def search(
        self, identity: Identity, tenant: str, query: dict[str, Any], *, truncated=None
    ) -> list[str]:
        """Newest first, at most ``MAX_CONTROL_RESULTS``; *truncated* gets ``True`` if cut."""
        self._authorize(identity, "search", tenant)
        results = list(self.index.search(tenant, query))
        cut = len(results) > MAX_CONTROL_RESULTS
        results = results[:MAX_CONTROL_RESULTS]
        if cut and truncated is not None:
            truncated.append(True)
        self._audit(identity, tenant, "search", "ok", {"results": len(results), "truncated": cut})
        return results
