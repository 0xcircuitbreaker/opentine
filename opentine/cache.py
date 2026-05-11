"""Semantic cache keys and provenance for replayable calls."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any


def semantic_key(kind: str, payload: dict[str, Any]) -> str:
    blob = json.dumps({"kind": kind, "payload": payload}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class CacheEntry:
    key: str
    kind: str
    value: dict[str, Any]
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "value": self.value,
            "provenance": self.provenance,
            "created_at": self.created_at,
        }
