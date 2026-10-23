"""Transport-independent remote protocol and authorization logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from opentine.kernel import parse_oid
from opentine.remote._admission import AllowAdmission
from opentine.remote._association_budget import admitted_associations
from opentine.remote._audit_verify import audit_report
from opentine.remote._install_fence import install_objects
from opentine.remote._pack_ingest import verified_write_order
from opentine.remote._ref_policy import FORCE, fast_forward_violation, ref_permission
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
from opentine.repository import _pack4
from opentine.repository._pack_fit import fitted_pack, typed_selection
from opentine.repository._refs import normalize_ref, validate_ref_target
from opentine.repository._semantic_view import SemanticView
from opentine.repository.pack import MAX_PACK_BODY_BYTES, inspect_pack, negotiate


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
        fast_forward_heads: bool = False,
    ):
        self.fast_forward_heads = fast_forward_heads
        self.objects = objects
        self.index = index
        self.identities = identities
        self.authorization = authorization
        self.admission = admission or AllowAdmission()
        self.audit = audit or index
        if not callable(getattr(self.audit, "append", None)):
            raise TypeError("remote service requires an AuditSink")

    def capabilities(self) -> dict[str, Any]:
        return {
            "authentication": ["bearer", "oidc"],
            "filters": ["depth", "run", "object_type"],
            "heads_fast_forward": bool(getattr(self, "fast_forward_heads", False)),
            "object_format": "opentine-v3",
            # ``pack_format`` stays what 0.11 clients read; newer ones choose from
            # ``pack_formats`` (``repository._pack4``).
            "pack_codecs": _pack4.local_codecs(),
            "pack_format": "TINEPACK3",
            "pack_formats": [_pack4.V4, _pack4.V3],
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
        data, missing = fitted_pack(
            repo,
            wants,
            haves,
            depth=depth,
            omitted=short,
            select=typed_selection(object_types) if object_types else None,
        )
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
        *,
        force: bool = False,
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
        repo = TenantRepo(tenant, self.objects, self.index)
        rewrite = fast_forward_violation(
            repo, name, expected_old, new_oid, enabled=self.fast_forward_heads
        )
        if rewrite:  # a fast-forward-only head moved to an unrelated run (_ref_policy)
            if not force:
                self._audit(identity, tenant, "update_ref", "non-fast-forward", {"name": name})
                raise PermissionError("non-fast-forward update of a protected head")
            self._authorize(identity, FORCE, tenant)
        self.admission.admit(
            identity, "update_ref", {"name": name, "new": new_oid, "tenant": tenant}
        )
        changed = self.index.update_ref(tenant, name, new_oid, expected_old)
        self._audit(
            identity,
            tenant,
            "update_ref",
            ("forced" if rewrite else "ok") if changed else "conflict",
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
