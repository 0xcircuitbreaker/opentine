"""In-memory validation for v2 conversions before legacy bytes are persisted."""

from __future__ import annotations

from typing import Any

from opentine._canon import _redact
from opentine.kernel import ObjectEnvelope, canonical_json, validate_links
from opentine.redaction import redact_blob, redact_value
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._refs import normalize_ref, validate_ref_oid, validate_ref_target
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph
from opentine.repository.pack import MAX_PACK_BODY_BYTES, MAX_PACK_OBJECTS, reachable


class _MemoryRepo:
    def __init__(self, base: Any | None = None) -> None:
        self.base = base
        self.objects: dict[str, ObjectEnvelope] = {}
        self.refs: dict[str, str] = {}

    def has(self, oid: str) -> bool:
        return oid in self.objects or (self.base is not None and self.base.has(oid))

    def put(self, object_type: str, payload: Any, schema: int = 1, *, redact: bool = True) -> str:
        if redact and object_type == "blob":
            stored = redact_blob(payload)
        else:
            stored = redact_value(_redact(payload)) if redact else payload
        envelope = ObjectEnvelope.create(object_type, stored, schema)
        validate_links(envelope, self.has)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        if envelope.oid not in self.objects and len(self.objects) >= MAX_PACK_OBJECTS:
            raise ValueError("v2 migration exceeds the pack synchronization object limit")
        self.objects[envelope.oid] = envelope
        return envelope.oid

    def get(self, oid: str) -> ObjectEnvelope:
        try:
            envelope = self.objects[oid]
        except KeyError as exc:
            if self.base is None:
                raise KeyError(oid) from exc
            return self.base.get(oid)
        validate_links(envelope, self.has)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        return envelope

    def raw(self, oid: str) -> bytes:
        try:
            return self.objects[oid].encode()
        except KeyError as exc:
            if self.base is None:
                raise KeyError(oid) from exc
            return self.base.raw(oid)

    def raw_size(self, oid: str) -> int:
        try:
            envelope = self.objects[oid]
        except KeyError:
            size = getattr(self.base, "raw_size", None)
            return size(oid) if callable(size) else len(self.raw(oid))
        header = {
            "encoding": envelope.encoding,
            "schema": envelope.schema,
            "type": envelope.object_type,
        }
        return len(canonical_json(header)) + 1 + len(envelope.body)

    def iter_oids(self, *, limit: int | None = None, truncate: bool = False) -> list[str]:
        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("object listing limit must be a positive integer")
        if truncate and limit is None:
            raise ValueError("truncated object listings require a limit")
        base = self.base.iter_oids(limit=limit, truncate=truncate) if self.base else []
        values = sorted(set(base) | set(self.objects))
        if limit is not None and len(values) > limit:
            if truncate:
                return values[:limit]
            raise ValueError("repository object listing exceeds search limit")
        return values

    def iter_typed_oids(self, object_types: set[str], *, limit: int = 100_000):
        from opentine.repository._objects import iter_typed_object_oids

        if type(limit) is not int or limit < 1:
            raise ValueError("typed object scan limit must be a positive integer")
        selected = {oid for oid in self.objects if oid.split(":", 1)[0] in object_types}
        count = 0
        for oid in sorted(selected):
            count += 1
            if count > limit:
                raise ValueError("typed object scan exceeds its object limit")
            yield oid
        typed = getattr(self.base, "iter_typed_oids", None)
        path = getattr(self.base, "path", None)
        if callable(typed):
            base = typed(object_types, limit=limit)
        elif path is not None:
            base = iter_typed_object_oids(path, object_types, limit=limit)
        elif self.base is not None:
            base = (
                oid
                for oid in self.base.iter_oids(limit=limit)
                if oid.split(":", 1)[0] in object_types
            )
        else:
            base = ()
        for oid in base:
            if oid in selected:
                continue
            count += 1
            if count > limit:
                raise ValueError("typed object scan exceeds its object limit")
            yield oid

    def read_ref(self, name: str) -> str | None:
        normalized = normalize_ref(name)
        if normalized in self.refs:
            return self.refs[normalized]
        return self.base.read_ref(normalized) if self.base else None

    def update_ref(self, name: str, new_oid: str, expected_old: str | None = None) -> None:
        normalized = normalize_ref(name)
        validate_ref_oid(normalized, new_oid)
        target = self.get(new_oid)
        validate_ref_target(normalized, target.object_type, target.payload())
        if self.read_ref(normalized) != expected_old:
            raise ValueError("concurrent in-memory ref update")
        self.refs[normalized] = new_oid

    def associated_oids(self, target_id: str, *, limit: int) -> list[str]:
        found: list[str] = []
        if self.base is not None:
            from opentine.repository._associations import associated_map

            found.extend(associated_map(self.base, [target_id], limit)[target_id])
        for oid, envelope in self.objects.items():
            if envelope.object_type not in {"annotation", "attestation"}:
                continue
            if envelope.payload().get("target_id") == target_id and oid not in found:
                found.append(oid)
                if len(found) > limit:
                    raise ValueError("association result exceeds pack object limit")
        return found


def _pack_body_size(repo: _MemoryRepo, run_id: str) -> int:
    oids = reachable(repo, [run_id])
    selected = set(oids)
    shallow = {
        link for oid in oids for link in validate_links(repo.get(oid)) if link not in selected
    }
    size = 39
    for index, oid in enumerate(oids):
        encoded = 4 * ((repo.raw_size(oid) + 2) // 3)
        size += 19 + encoded + len(oid) + bool(index)
    for index, oid in enumerate(sorted(shallow)):
        size += 2 + len(oid) + bool(index)
    return size


def _convert(repo: _MemoryRepo, run: Any, **kwargs: Any) -> Any:
    from opentine.repository.runs import _put_run

    result = _put_run(repo, run, **kwargs)
    if _pack_body_size(repo, result.run_id) > MAX_PACK_BODY_BYTES:
        raise ValueError("compatibility run exceeds the pack synchronization byte limit")
    return result


def preflight_run(
    repo: Any,
    run: Any,
    *,
    ref: str | None = None,
    legacy_blob: str | None = None,
    legacy_verification: dict[str, Any] | None = None,
) -> None:
    _convert(
        _MemoryRepo(repo),
        run,
        ref=ref,
        legacy_blob=legacy_blob,
        legacy_verification=legacy_verification,
    )


def preflight_v2(
    base: Any,
    run: Any,
    raw: bytes,
    verification: dict[str, Any],
    *,
    ref: str | None = None,
) -> None:
    repo = _MemoryRepo(base)
    legacy_blob = repo.put("blob", raw, redact=False)
    _convert(repo, run, ref=ref, legacy_blob=legacy_blob, legacy_verification=verification)
