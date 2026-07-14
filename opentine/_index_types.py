"""Search-index records and redaction-safe extraction."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from opentine.graph import Run


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
        return cls(**{key: value for key, value in data.items() if key in fields})


def _searchable_text(run: Run) -> str:
    data = run.to_dict(redact=True)
    metadata = data.get("metadata", {})
    chunks = [run.id, run.model_info, run.status.value, *run.tags]
    chunks.extend([str(metadata.get("user_prompt", "")), str(metadata.get("system_prompt", ""))])
    for step in data.get("graph", {}).get("steps", {}).values():
        inputs, outputs = step.get("inputs", {}), step.get("outputs", {})
        for value in (inputs.get("text"), inputs.get("name"), outputs.get("result")):
            if isinstance(value, str):
                chunks.append(value)
    return " ".join(chunk for chunk in chunks if chunk)[:8000].lower()


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
