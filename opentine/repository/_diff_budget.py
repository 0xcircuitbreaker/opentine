"""Aggregate source and output bounds for semantic run comparisons."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from opentine.kernel import canonical_json
from opentine.repository._blob_io import stored_object_size
from opentine.repository._semantic_view import SemanticView

MAX_DIFF_OBJECT_BYTES = 4 * 1024 * 1024
MAX_DIFF_SOURCE_BYTES = 32 * 1024 * 1024
MAX_DIFF_OUTPUT_BYTES = 16 * 1024 * 1024


class DiffBudget:
    def __init__(self, repo: Any):
        self.repo = repo
        self.view = SemanticView(
            self,
            max_cache_bytes=16 * 1024 * 1024,
            max_source_bytes=MAX_DIFF_SOURCE_BYTES,
        )
        self.envelopes: dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.repo, name)

    def raw(self, oid: str) -> bytes:
        if stored_object_size(self.repo, oid) > MAX_DIFF_OBJECT_BYTES:
            raise ValueError("semantic diff encountered an oversized structured object")
        return self.repo.raw(oid)

    def get(self, oid: str):
        if oid in self.envelopes:
            return self.envelopes[oid]
        envelope = self.view.get(oid)
        payload = envelope.payload()
        if not isinstance(payload, dict):
            raise ValueError("semantic diff requires structured objects")
        self.envelopes[oid] = envelope
        return envelope

    @staticmethod
    def check_output(result: Any) -> None:
        if len(canonical_json(asdict(result))) > MAX_DIFF_OUTPUT_BYTES:
            raise ValueError("semantic diff exceeds its aggregate output-byte limit")
