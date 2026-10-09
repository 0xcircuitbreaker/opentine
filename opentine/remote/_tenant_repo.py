"""Tenant-scoped repository adapter used for pack negotiation."""

from typing import Any

from opentine.kernel import ObjectEnvelope, parse_oid, validate_links
from opentine.remote._association_budget import recorded_targets
from opentine.remote.backend import MAX_CONTROL_RESULTS, valid_tenant
from opentine.remote.interfaces import IndexBackend, ObjectStore
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._refs import normalize_ref, validate_ref_target
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph
from opentine.repository._semantic_view import SemanticView
from opentine.repository.pack import MAX_PACK_BODY_BYTES

MAX_REF_ANNOTATION_BYTES = 1024 * 1024
MAX_REF_ANNOTATION_TOTAL_BYTES = 8 * MAX_REF_ANNOTATION_BYTES


class TenantRepo:
    def __init__(self, tenant: str, objects: ObjectStore, index: IndexBackend | None = None):
        self.tenant = valid_tenant(tenant)
        self.objects = objects
        self.index = index

    def has(self, oid: str) -> bool:
        return self.objects.has(self.tenant, oid)

    def raw(self, oid: str) -> bytes:
        return self.objects.get(self.tenant, oid)

    def get(self, oid: str) -> ObjectEnvelope:
        envelope = ObjectEnvelope.decode(self.raw(oid), oid)
        validate_links(envelope, self.has)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return envelope

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        return self.objects.list(self.tenant, limit=limit, truncate=truncate)

    def associated_oids(self, target_id: str, *, limit: int) -> list[str]:
        if self.index is None:
            raise ValueError("tenant repository requires an association index")
        return self.index.associated_objects(self.tenant, target_id, limit)


class PackedTenantRepo(TenantRepo):
    """Read-through view used to validate a pack before storing any object."""

    def __init__(self, tenant: str, objects: ObjectStore, packed: dict[str, bytes]):
        super().__init__(tenant, objects)
        self.packed = packed
        self._semantic = SemanticView(
            self,
            check_link_existence=False,
            max_source_bytes=MAX_PACK_BODY_BYTES,
        )

    def has(self, oid: str) -> bool:
        return oid in self.packed or super().has(oid)

    def raw(self, oid: str) -> bytes:
        return self.packed.get(oid) or super().raw(oid)

    def get(self, oid: str) -> ObjectEnvelope:
        return self._semantic.get(oid)


def _decoded_target(tenant: str, objects: ObjectStore, oid: str, spent: int) -> tuple[Any, int]:
    """Decode one annotation for its ``target_id``, within the listing's byte budget."""
    size = getattr(objects, "size", None)
    if callable(size):
        stored = size(tenant, oid)
        if type(stored) is not int or stored < 0:
            raise ValueError("object store returned an invalid object size")
        if stored > MAX_REF_ANNOTATION_BYTES or spent + stored > MAX_REF_ANNOTATION_TOTAL_BYTES:
            raise ValueError("ref annotation verification exceeds its byte limit")
    raw = objects.get(tenant, oid)
    if len(raw) > MAX_REF_ANNOTATION_BYTES or spent + len(raw) > MAX_REF_ANNOTATION_TOTAL_BYTES:
        raise ValueError("ref annotation verification exceeds its byte limit")
    target = ObjectEnvelope.decode(raw, oid)
    validate_links(target)
    payload = target.payload()
    return (payload.get("target_id") if isinstance(payload, dict) else None), spent + len(raw)


def validate_ref_listing(
    tenant: str, objects: ObjectStore, index: IndexBackend, refs: dict[str, str]
) -> None:
    if not isinstance(refs, dict) or len(refs) > MAX_CONTROL_RESULTS:
        raise ValueError("ref listing exceeds control-plane result limit")
    # Typed IDs are sufficient for every namespace except annotations, whose ref
    # suffix is bound to target_id. That binding is read from the index, which
    # recorded it when install verified the object, rather than by decoding every
    # annotation here: a decode budget meant one large annotation failed this
    # listing, and every fetch, clone and push behind it, for the whole tenant.
    # Only an object the index has no binding for is decoded, under the budget,
    # and update_ref runs this check before it commits (admit_annotation_ref).
    # get, fetch, install, and fsck retain full semantic verification.
    recorded = recorded_targets(
        index, tenant, {oid for oid in refs.values() if str(oid).startswith("annotation:")}
    )
    targets: dict[str, tuple[str, object]] = {}
    annotation_bytes = 0
    for name, oid in refs.items():
        if oid not in targets:
            if not objects.has(tenant, oid):
                raise RuntimeError(f"ref {name} targets a missing object")
            object_type, _ = parse_oid(oid)
            ref_payload = None
            if object_type == "annotation":
                target_id = recorded.get(oid)
                if target_id is None:
                    target_id, annotation_bytes = _decoded_target(
                        tenant, objects, oid, annotation_bytes
                    )
                ref_payload = {"target_id": target_id}
            targets[oid] = (object_type, ref_payload)
        validate_ref_target(normalize_ref(name), *targets[oid])


def admit_annotation_ref(
    tenant: str, objects: ObjectStore, index: IndexBackend, name: str, target: ObjectEnvelope
) -> None:
    """Refuse a ref write the listing could not then validate.

    Records the verified binding first (idempotent; an install interrupted after
    the object write left none), then checks the listing with *name* moved, so
    every bound ``GET /refs`` enforces is enforced here too.
    """
    payload = target.payload()
    index.record_object(tenant, target.oid, len(target.encode()), payload.get("target_id"))
    refs = dict(index.list_refs(tenant))
    refs[name] = target.oid
    validate_ref_listing(tenant, objects, index, refs)
