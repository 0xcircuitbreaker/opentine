"""Operation-scoped semantic object cache for adversarial shared graphs."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from opentine.kernel import KernelError, ObjectEnvelope, validate_links
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph


class CachedEnvelope(ObjectEnvelope):
    """Immutable envelope whose decoded JSON payload is retained per operation."""

    __slots__ = ("_decoded_payload",)

    def __init__(self, envelope: ObjectEnvelope):
        super().__init__(
            envelope.object_type,
            envelope.schema,
            envelope.body,
            envelope.encoding,
        )
        object.__setattr__(self, "_decoded_payload", envelope.payload())

    def payload(self) -> Any:
        return self._decoded_payload


class SemanticView:
    """Verify and decode each immutable object at most once in one operation."""

    def __init__(
        self,
        base: Any,
        packed: dict[str, bytes] | None = None,
        *,
        check_link_existence: bool = True,
        max_cache_bytes: int = 16 * 1024 * 1024,
        max_source_bytes: int | None = None,
    ):
        self.base = base
        self.packed = packed or {}
        self._check_links = check_link_existence and callable(getattr(base, "has", None))
        self._base_has = getattr(base, "has", None)
        self._base_link_exists = getattr(base, "_link_exists", self._base_has)
        self._max_cache_bytes = max_cache_bytes
        self._max_source_bytes = max_source_bytes
        self._cache: OrderedDict[str, CachedEnvelope] = OrderedDict()
        self._cache_bytes = 0
        self._source_bytes = 0
        self._source_seen: set[str] = set()
        self._summaries: OrderedDict[str, tuple[Any, ...]] = OrderedDict()
        self._validated: set[str] = set()
        self._validating: set[str] = set()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.base, name)

    def has(self, oid: str) -> bool:
        return oid in self.packed or (callable(self._base_has) and self._base_has(oid))

    def link_exists(self, oid: str) -> bool:
        return oid in self.packed or (
            callable(self._base_link_exists) and self._base_link_exists(oid)
        )

    def raw(self, oid: str) -> bytes:
        raw = self.packed.get(oid)
        return raw if raw is not None else self.base.raw(oid)

    def _preflight_source(self, oid: str, size: int) -> None:
        if type(size) is not int or size < 0:
            raise KernelError("repository object has an invalid encoded size")
        if (
            oid not in self._source_seen
            and self._max_source_bytes is not None
            and self._source_bytes + size > self._max_source_bytes
        ):
            raise KernelError("repository operation exceeds its semantic source limit")

    def cached_envelope(self, oid: str) -> CachedEnvelope:
        envelope = self._cache.get(oid)
        if envelope is None:
            fresh_source = oid not in self._source_seen
            if oid in self.packed:
                raw = self.raw(oid)
                source_size = len(raw)
                self._preflight_source(oid, source_size)
                decoded = ObjectEnvelope.decode(raw, oid)
            elif callable(getattr(self.base, "has", None)):
                size_reader = getattr(self.base, "raw_size", None)
                if fresh_source and callable(size_reader):
                    self._preflight_source(oid, size_reader(oid))
                raw = self.raw(oid)
                source_size = len(raw)
                self._preflight_source(oid, source_size)
                decoded = ObjectEnvelope.decode(raw, oid)
            else:  # Preserve the tiny repository protocol used by embedders/tests.
                decoded = self.base.get(oid)
                source_size = len(decoded.encode())
                self._preflight_source(oid, source_size)
            envelope = CachedEnvelope(decoded)
            if fresh_source:
                self._source_seen.add(oid)
                self._source_bytes += source_size
            self._remember_summary(oid, envelope)
            if source_size <= self._max_cache_bytes:
                while self._cache and self._cache_bytes + source_size > self._max_cache_bytes:
                    _, evicted = self._cache.popitem(last=False)
                    self._cache_bytes -= len(evicted.body)
                self._cache[oid] = envelope
                self._cache_bytes += len(envelope.body)
        else:
            self._cache.move_to_end(oid)
        return envelope

    def _remember_summary(self, oid: str, envelope: CachedEnvelope) -> None:
        payload = envelope.payload()
        if not isinstance(payload, dict):
            return
        if envelope.object_type == "event":
            summary = (
                "event",
                tuple(payload.get("parent_ids") or ()),
                tuple(payload.get("causal_ids") or ()),
            )
        elif envelope.object_type == "annotation":
            summary = ("annotation", payload.get("target_id"))
        else:
            return
        self._summaries[oid] = summary
        self._summaries.move_to_end(oid)
        if len(self._summaries) > 10_000:
            self._summaries.popitem(last=False)

    def event_graph_record(self, oid: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        summary = self._summaries.get(oid)
        if summary is None or summary[0] != "event":
            envelope = self.get(oid)
            summary = self._summaries.get(oid)
            if envelope.object_type != "event" or summary is None:
                raise KernelError("run events must resolve to event objects")
        self._summaries.move_to_end(oid)
        return summary

    def annotation_record(self, oid: str) -> tuple[str, Any]:
        summary = self._summaries.get(oid)
        if summary is None or summary[0] != "annotation":
            envelope = self.get(oid)
            summary = self._summaries.get(oid)
            if envelope.object_type != "annotation" or summary is None:
                raise KernelError("annotation previous object must be an annotation")
        self._summaries.move_to_end(oid)
        return summary

    def get(self, oid: str) -> CachedEnvelope:
        envelope = self.cached_envelope(oid)
        if oid in self._validated or oid in self._validating:
            return envelope
        self._validating.add(oid)
        try:
            validate_links(envelope, self.link_exists if self._check_links else None)
            validate_annotation_chain(self, envelope)
            validate_event_metrics(envelope)
            validate_run_graph(self, envelope)
        finally:
            self._validating.remove(oid)
        self._validated.add(oid)
        return envelope


def semantic_view(repo: Any, *, max_source_bytes: int | None = None) -> SemanticView:
    return (
        repo
        if isinstance(repo, SemanticView)
        else SemanticView(repo, max_source_bytes=max_source_bytes)
    )
