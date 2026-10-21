"""Search-index records and redaction-safe extraction."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from opentine._canon import _redact
from opentine.graph import Run
from opentine.redaction import redact_value

#: Text kept per run in the rebuildable index. A run with more searchable text is
#: marked ``truncated`` and searched in full from its file instead (see
#: ``RunIndex.search``), so a match past the cut-off is never silently missed.
MAX_INDEX_TEXT_CHARS = 8_000
#: Bound on the full-text rescan of one truncated run at search time.
MAX_FULL_TEXT_CHARS = 4 * 1024 * 1024


@dataclass
class IndexEntry:
    file: str
    run_id: str = ""
    model: str = ""
    status: str = ""
    steps: int = 0
    cost: float = 0.0
    created_at: float = 0.0
    mtime: float = 0.0
    format_version: int = 0
    tags: list[str] = field(default_factory=list)
    text: str = ""
    unreadable: bool = False
    #: The agent that produced the run: harness name, transcript source or framework.
    harness: str = ""
    providers: list[str] = field(default_factory=list)
    #: ``text`` holds only the first MAX_INDEX_TEXT_CHARS of the run's searchable text.
    truncated: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> IndexEntry:
        fields = set(cls.__dataclass_fields__)
        entry = cls(**{key: value for key, value in data.items() if key in fields})
        strings = (entry.file, entry.run_id, entry.model, entry.status, entry.text, entry.harness)
        numbers = (entry.cost, entry.created_at, entry.mtime)
        if (
            not all(isinstance(value, str) for value in strings)
            or Path(entry.file).name != entry.file
            or not entry.file.endswith(".tine")
            or any(character in entry.file for character in ("/", "\\", "\0"))
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in numbers
            )
            or any(
                type(value) is not int or value < 0 for value in (entry.steps, entry.format_version)
            )
            or not isinstance(entry.tags, list)
            or not all(isinstance(tag, str) for tag in entry.tags)
            or type(entry.unreadable) is not bool
            or type(entry.truncated) is not bool
            or not isinstance(entry.providers, list)
            or not all(isinstance(provider, str) for provider in entry.providers)
        ):
            raise ValueError("invalid run-index entry")
        return entry


def _flatten(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if value is None or value == {} or value == []:
        return None
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        return None


def searchable_text(run: Run, limit: int = MAX_INDEX_TEXT_CHARS) -> tuple[str, bool]:
    """The run's redacted, lowercased search text, and whether *limit* cut it.

    Every step contributes its whole inputs (tool names *and* arguments), tool
    info, outputs and error, each through the same redaction a saved run gets,
    so a secret never reaches the index.
    """
    chunks: list[str] = []
    retained = 0
    truncated = False

    def add(value: Any) -> None:
        nonlocal retained, truncated
        if truncated:
            return
        text = _flatten(redact_value(_redact(value)))
        if not text:
            return
        if retained + len(text) > limit:
            text, truncated = text[: max(limit - retained, 0)], True
        chunks.append(text)
        retained += len(text) + 1

    for value in (run.id, run.model_info, run.status.value, *run.tags):
        add(value)
    add(run.user_prompt)
    add(run.system_prompt)
    for step in run.steps:
        for value in (step.inputs, step.tool_info, step.outputs, step.error, step.provider):
            add(value)
    return " ".join(chunks)[:limit].lower(), truncated


def _searchable_text(run: Run) -> str:
    return searchable_text(run)[0]


def run_agent(run: Run) -> str:
    """Which agent produced *run*: harness, transcript source, framework, or ``""``."""
    metadata = run.metadata if isinstance(run.metadata, dict) else {}
    capture = metadata.get("capture")
    for candidate in (
        metadata.get("harness"),
        capture.get("source_format") if isinstance(capture, dict) else None,
        metadata.get("framework"),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate[:128]
    return ""


def entry_from_run(run: Run, file: str, mtime: float) -> IndexEntry:
    text, truncated = searchable_text(run)
    return IndexEntry(
        file=file,
        run_id=run.id,
        model=run.model_info,
        status=run.status.value,
        steps=len(run.steps),
        cost=run.total_cost,
        created_at=run.created_at,
        mtime=mtime,
        format_version=run.format_version,
        tags=list(run.tags),
        text=text,
        harness=run_agent(run),
        providers=sorted({step.provider for step in run.steps if step.provider})[:32],
        truncated=truncated,
    )
