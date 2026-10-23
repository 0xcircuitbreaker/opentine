"""Recognizing and reading an ATIF document, and naming each step's provider.

Split out of :mod:`opentine._atif` to keep each module under the architecture
gate's line budget.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from opentine.trace._import_guard import bounded_read, shape_checked
from opentine.trace._provider_alias import PROVIDER_ALIASES, canonical_provider
from opentine.trace._transcript_common import MAX_SOURCE_BYTES

ATIF_FORMAT = "atif"
MAX_TRAJECTORIES = 1_000
MAX_DEPTH = 8
MAX_TOOL_CALLS = 1_000
_VERSION = re.compile(r"ATIF-v1\.(\d{1,3})")
#: Model-name prefixes that name their provider when ATIF records only a model.
_PREFIXES = (
    ("claude", "anthropic"),
    ("gpt-", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("codex", "openai"),
    ("gemini", "google"),
    ("grok", "xai"),
    ("deepseek", "deepseek"),
    ("qwen", "qwen"),
    ("glm", "glm"),
    ("kimi", "kimi"),
    ("mistral", "mistral"),
    ("ministral", "mistral"),
    ("codestral", "mistral"),
    ("devstral", "mistral"),
)


#: Providers a ``provider/model`` name may lead with (else the slash is the model's own).
_KNOWN = frozenset(
    {"anthropic", "openai", "google", "xai", "mistral", "deepseek", "qwen", "glm", "kimi",
     "minimax", "meta", "openrouter", "together", "groq", "fireworks", "bedrock", "vertex",
     "foundry", "cerebras", "deepinfra", "ollama"}
)  # fmt: skip


def is_atif(document: Any) -> bool:
    """Whether *document* is an ATIF trajectory root."""
    return (
        isinstance(document, dict)
        and isinstance(document.get("schema_version"), str)
        and bool(_VERSION.fullmatch(document["schema_version"]))
        and isinstance(document.get("steps"), list)
    )


def load(source: str | Path | Iterable[Any]) -> Any:
    if isinstance(source, (str, Path)):
        with Path(source).open("rb") as handle:
            data = bounded_read(handle, MAX_SOURCE_BYTES)
    else:
        data = "\n".join(line.decode() if isinstance(line, bytes) else str(line) for line in source)
        data = data.encode("utf-8", "surrogatepass")
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("ATIF document exceeds the import size limit")
    shape_checked(data)
    return json.loads(data)


def model_provider(model: str, *hints: Any) -> tuple[str, str]:
    """``(model, provider)``: an explicit hint, a ``provider/model`` name, or a prefix."""
    for hint in hints:
        if isinstance(hint, dict) and isinstance(hint.get("provider"), str) and hint["provider"]:
            return model, canonical_provider(hint["provider"][:64])
    head, _, rest = model.partition("/")
    if rest and (head.casefold() in PROVIDER_ALIASES or head.lower() in _KNOWN):
        return rest, canonical_provider(head.lower())
    lowered = model.lower()
    for prefix, provider in _PREFIXES:
        if lowered.startswith(prefix):
            return model, provider
    return model, ""


__all__ = [
    "ATIF_FORMAT",
    "MAX_DEPTH",
    "MAX_TOOL_CALLS",
    "MAX_TRAJECTORIES",
    "is_atif",
    "load",
    "model_provider",
]
