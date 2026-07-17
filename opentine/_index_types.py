"""Search-index records and redaction-safe extraction."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from pathlib import Path

from opentine._canon import _redact
from opentine.graph import Run
from opentine.redaction import redact_value

MAX_INDEX_TEXT_CHARS = 8_000


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

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> IndexEntry:
        fields = set(cls.__dataclass_fields__)
        entry = cls(**{key: value for key, value in data.items() if key in fields})
        strings = (entry.file, entry.run_id, entry.model, entry.status, entry.text)
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
        ):
            raise ValueError("invalid run-index entry")
        return entry


def _searchable_text(run: Run) -> str:
    chunks: list[str] = []
    retained = 0

    def add(value) -> None:
        nonlocal retained
        cleaned = redact_value(_redact(value))
        if not isinstance(cleaned, str) or retained >= MAX_INDEX_TEXT_CHARS:
            return
        kept = cleaned[: MAX_INDEX_TEXT_CHARS - retained]
        chunks.append(kept)
        retained += len(kept) + 1

    for value in (run.id, run.model_info, run.status.value, *run.tags):
        add(value)
    add(run.user_prompt)
    add(run.system_prompt)
    for step in run.steps:
        inputs, outputs = step.inputs, step.outputs
        for value in (inputs.get("text"), inputs.get("name"), outputs.get("result")):
            add(value)
    return " ".join(chunks)[:MAX_INDEX_TEXT_CHARS].lower()


def entry_from_run(run: Run, file: str, mtime: float) -> IndexEntry:
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
        text=_searchable_text(run),
    )
