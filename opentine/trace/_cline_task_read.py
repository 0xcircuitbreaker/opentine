"""Reading a Cline or Roo Code task directory out of VS Code's globalStorage.

Cline (``saoudrizwan.claude-dev``) and its fork Roo Code
(``rooveterinaryinc.roo-cline``) keep every task under
``<VS Code user dir>/globalStorage/<extension id>/tasks/<task id>/``:

``api_conversation_history.json``  the Anthropic-style ``messages`` array the
                                   extension sends (``role`` + ``content``
                                   blocks; newer versions add ``ts`` and Cline
                                   ``modelInfo``)
``ui_messages.json``               the chat UI's records (``ts``, ``type`` say/ask,
                                   ``say``, ``text``); each ``api_req_started``
                                   carries one request's JSON-encoded token
                                   usage and cost
``task_metadata.json``             (Cline) ``model_usage`` and files in context

SOURCE is the task directory or its ``api_conversation_history.json``; the
siblings are read when present. Every file is bounded and shape-checked
before it is parsed, as for any import.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, NamedTuple

from opentine.trace._import_guard import bounded_read, shape_checked

HISTORY = "api_conversation_history.json"
UI = "ui_messages.json"
METADATA = "task_metadata.json"
MAX_FILE_BYTES = 128 * 1024 * 1024
#: The globalStorage folder of each extension, and the format it imports as.
EXTENSIONS = {"saoudrizwan.claude-dev": "cline-task", "rooveterinaryinc.roo-cline": "roo-task"}


class Task(NamedTuple):
    task_id: str
    history: list[Any]
    ui: list[Any]
    metadata: dict[str, Any]


def task_dir(source: str | Path) -> Path:
    path = Path(source)
    return path.parent if path.name == HISTORY else path


def looks_like_task(source: str | Path) -> bool:
    try:
        return (task_dir(source) / HISTORY).is_file()
    except (OSError, ValueError):
        return False


def format_of(source: str | Path) -> str:
    """``roo-task`` under Roo Code's globalStorage folder, else ``cline-task``."""
    parts = {part.lower() for part in task_dir(source).resolve().parts}
    return next((name for ext, name in EXTENSIONS.items() if ext in parts), "cline-task")


def _load(path: Path, want: type) -> Any:
    if not path.is_file():
        return want()
    with path.open("rb") as handle:
        data = shape_checked(bounded_read(handle, MAX_FILE_BYTES))
    try:
        value = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"{path.name} is not valid JSON") from exc
    if not isinstance(value, want):
        raise ValueError(f"{path.name} is not a JSON {want.__name__}")
    return value


def read_task(source: str | Path | Iterable[Any]) -> Task:
    """The task's three files; lines of text are read as the history alone."""
    if not isinstance(source, (str, Path)):
        text = "\n".join(str(line) for line in source)
        shape_checked(text)
        history = json.loads(text) if text.strip() else []
        if not isinstance(history, list):
            raise ValueError(f"{HISTORY} is not a JSON list")
        return Task("task", history, [], {})
    directory = task_dir(source)
    if not (directory / HISTORY).is_file():
        raise ValueError(f"no {HISTORY} in {directory}")
    return Task(
        directory.name,
        _load(directory / HISTORY, list),
        _load(directory / UI, list),
        _load(directory / METADATA, dict),
    )


__all__ = ["EXTENSIONS", "HISTORY", "Task", "format_of", "looks_like_task", "read_task"]
