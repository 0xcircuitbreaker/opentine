"""Tenant-scoped repository adapter used for pack negotiation."""

from opentine.kernel import ObjectEnvelope, parse_oid, validate_links
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


def validate_ref_listing(
    tenant: str, objects: ObjectStore, index: IndexBackend, refs: dict[str, str]
) -> None:
    if not isinstance(refs, dict) or len(refs) > MAX_CONTROL_RESULTS:
        raise ValueError("ref listing exceeds control-plane result limit")
    targets: dict[str, tuple[str, object]] = {}
    annotation_bytes = 0
    size = getattr(objects, "size", None)
    for name, oid in refs.items():
        if oid not in targets:
            if not objects.has(tenant, oid):
                raise RuntimeError(f"ref {name} targets a missing object")
            object_type, _ = parse_oid(oid)
            ref_payload = None
            # Typed IDs are sufficient for every namespace except annotations,
            # whose ref suffix is bound to target_id. Avoid recursively checking
            # every run graph during this bounded control-plane listing; get,
            # fetch, install, and fsck retain full semantic verification.
            if object_type == "annotation":
                if callable(size):
                    stored = size(tenant, oid)
                    if type(stored) is not int or stored < 0:
                        raise ValueError("object store returned an invalid object size")
                    if (
                        stored > MAX_REF_ANNOTATION_BYTES
                        or annotation_bytes + stored > MAX_REF_ANNOTATION_TOTAL_BYTES
                    ):
                        raise ValueError("ref annotation verification exceeds its byte limit")
                raw = objects.get(tenant, oid)
                if (
                    len(raw) > MAX_REF_ANNOTATION_BYTES
                    or annotation_bytes + len(raw) > MAX_REF_ANNOTATION_TOTAL_BYTES
                ):
                    raise ValueError("ref annotation verification exceeds its byte limit")
                annotation_bytes += len(raw)
                target = ObjectEnvelope.decode(raw, oid)
                validate_links(target)
                payload = target.payload()
                if isinstance(payload, dict):
                    ref_payload = {"target_id": payload.get("target_id")}
            targets[oid] = (object_type, ref_payload)
        validate_ref_target(normalize_ref(name), *targets[oid])
