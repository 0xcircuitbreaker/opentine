"""Transport-independent remote protocol and authorization logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from opentine.remote._admission import AllowAdmission
from opentine.remote._association_budget import admitted_associations
from opentine.remote._audit_verify import audit_report
from opentine.remote._hosted_reads import match_text
from opentine.remote._install_fence import install_objects
from opentine.remote._pack_ingest import verified_write_order
from opentine.remote._ref_txn import check_move
from opentine.remote._request_audit import AuthorizationDenied, audit_tenant
from opentine.remote._service_caps import service_capabilities
from opentine.remote._tenant_repo import TenantRepo, validate_ref_listing
from opentine.remote._token_roles import note_authors
from opentine.remote._token_scope import SCOPE_CLAIM, check_wants, scoped_action, visible_refs
from opentine.remote._tombstone_store import tombstoned
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
from opentine.repository._pack_fit import fitted_pack, typed_selection
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
        self.events: Any = None  # 0.45.1: an ``_events.EventHub`` (SSE, webhooks)
        self.authorship: Any = None  # 0.90: ``(tenant, run oids, agent)``, ``_token_roles``
        self.authors_of: Any = None  # 0.90: ``(tenant, oid) -> set of agent ids``
        self.webhooks: Any = None
        if not callable(getattr(self.audit, "append", None)):
            raise TypeError("remote service requires an AuditSink")

    def capabilities(self) -> dict[str, Any]:
        return service_capabilities(self)  # _service_caps

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

    def _authorize_scoped(self, identity: Identity, action: str, tenant: str) -> None:
        """A route a namespace-limited token may use (``_token_scope``)."""
        self._authorize(identity, scoped_action(identity, action), tenant)

    def _audit(
        self,
        identity: Identity,
        tenant: str,
        action: str,
        outcome: str,
        details: dict[str, Any],
    ) -> None:
        scope = (identity.claims or {}).get(SCOPE_CLAIM)
        if isinstance(scope, dict):  # 0.90: a scoped token's scope is in every audit row
            details = {**details, "token_scope": scope}
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
        if self.events is not None:
            self.events.audited(tenant, self.audit)

    def list_refs(self, identity: Identity, tenant: str) -> dict[str, str]:
        self._authorize_scoped(identity, "read_ref", tenant)
        refs = visible_refs(identity, self.index.list_refs(tenant))
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
        self._authorize_scoped(identity, "negotiate", tenant)
        check_wants(self, identity, tenant, wants)
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
        tips: list[str] | None = None,
    ) -> bytes:
        """A pack for *wants*; runs whose associations did not fit go to *omitted*."""
        self._authorize_scoped(identity, "fetch", tenant)
        check_wants(self, identity, tenant, wants)
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
            tips=tips,
        )
        details: dict[str, Any] = {"objects": len(missing)}
        if short:
            details["associations_omitted"] = len(short)
            if omitted is not None:
                omitted.extend(short)
        self._audit(identity, tenant, "fetch", "ok", details)
        return data

    def _resolves(self, tenant: str, oid: str) -> bool:
        """A pushed shallow boundary the tenant holds, or purged (a tombstone, 0.46)."""
        return self.objects.has(tenant, oid) or tombstoned(self.objects, tenant, oid)

    def install_pack(self, identity: Identity, tenant: str, data: bytes) -> tuple[str, int]:
        self._authorize_scoped(identity, "upload", tenant)
        pack_id, packed, shallow = inspect_pack(data, serve=True)
        unresolved = [oid for oid in shallow if not self._resolves(tenant, oid)]
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
            held = [oid for oid in shallow if not tombstoned(self.objects, tenant, oid)]
            install_objects(self.objects, self.index, tenant, order, targets, held)
        self._audit(identity, tenant, "upload", "ok", {"objects": len(packed), "pack": pack_id})
        note_authors(self, identity, tenant, [oid for oid, _ in packed])
        if self.events is not None:
            self.events.runs_installed(tenant, [oid for oid, _ in packed])
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
        self._authorize_scoped(identity, "update_ref", tenant)
        name, rewrite = check_move(self, identity, tenant, name, new_oid, expected_old, force)
        changed = self.index.update_ref(tenant, name, new_oid, expected_old)
        self._audit(
            identity,
            tenant,
            "update_ref",
            ("forced" if rewrite else "ok") if changed else "conflict",
            {"expected_old": expected_old, "name": name, "new": new_oid},
        )
        if changed:
            note_authors(self, identity, tenant, [new_oid])
        if changed and self.events is not None:
            self.events.ref_moved(tenant, name, expected_old, new_oid, rewrite)
        return changed

    def search(
        self, identity: Identity, tenant: str, query: dict[str, Any], *, truncated=None
    ) -> list[str]:
        """Newest first, at most ``MAX_CONTROL_RESULTS``; *truncated* gets ``True`` if cut."""
        self._authorize(identity, "search", tenant)
        text = query.get("text")  # 0.46 (caps.search): runs whose stored record holds it
        if text is not None and (not isinstance(text, str) or not 0 < len(text) <= 256):
            raise ValueError("search text must be 1-256 characters")
        results = list(self.index.search(tenant, {**query, "type": "run"} if text else query))
        if text:
            results = [oid for oid in results if match_text(self.objects, tenant, oid, text)]
        cut = len(results) > MAX_CONTROL_RESULTS
        results = results[:MAX_CONTROL_RESULTS]
        if cut and truncated is not None:
            truncated.append(True)
        self._audit(identity, tenant, "search", "ok", {"results": len(results), "truncated": cut})
        return results
