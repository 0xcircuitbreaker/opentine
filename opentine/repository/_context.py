"""Byte budgets for minimal causal context retrieval."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentine.kernel import KernelError, canonical_json, parse_oid
from opentine.repository._access import get_object
from opentine.repository._blob_io import stored_object_size

if TYPE_CHECKING:
    from opentine.kernel import ObjectEnvelope
    from opentine.repository.store import Repo

MAX_CONTEXT_OBJECT_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_SOURCE_BYTES = 32 * 1024 * 1024
MAX_CONTEXT_OUTPUT_BYTES = 16 * 1024 * 1024


class ContextBudget:
    """Reject oversized structured input before reading it and bounded output after decode."""

    def __init__(self) -> None:
        self.source = 0
        self.output = 0

    def event(self, repo: Repo, oid: str) -> tuple[ObjectEnvelope, dict[str, Any]]:
        object_type, _ = parse_oid(oid)
        if object_type != "event":
            raise ValueError(f"context slices require event ids, got {object_type}")
        size = stored_object_size(repo, oid)
        if size > MAX_CONTEXT_OBJECT_BYTES:
            raise ValueError("context slice encountered an oversized structured object")
        self.source += size
        if self.source > MAX_CONTEXT_SOURCE_BYTES:
            raise ValueError("context slice exceeds its aggregate structured-source limit")
        envelope = get_object(repo, oid)
        payload = envelope.payload()
        if envelope.object_type != "event" or not isinstance(payload, dict):
            raise KernelError("context slice object must be an event")
        rendered = canonical_json({"object_type": "event", "oid": oid, "payload": payload})
        self.output += len(rendered)
        if self.output > MAX_CONTEXT_OUTPUT_BYTES:
            raise ValueError("context slice exceeds its aggregate output-byte limit")
        return envelope, payload
