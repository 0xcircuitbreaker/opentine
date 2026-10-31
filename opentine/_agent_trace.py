"""Export a run as one Agent Trace record (``tine export --format agent-trace``).

Agent Trace (https://agent-trace.dev/, RFC 0.1.0, schema
``https://agent-trace.dev/schemas/v1/trace-record.json``) attributes the lines
of version-controlled files to AI or human contributors. A run says which of
its tool calls wrote which paths (the 0.11 action index, the same extraction
``tine blame`` reads), so every file the run wrote becomes one ``files`` entry
with one conversation per model, contributor ``ai``.

Nothing is fabricated:

* Line ranges are emitted only where they are known: a full-content write
  (``content``/``file_text``/``contents``) that is the run's *last* write to
  that path covers lines ``1..N`` of the file as the run left it. Edits,
  patches and shell redirects have no recorded position, so their files carry
  file-level attribution: a conversation with an empty ``ranges`` array, which
  the schema permits (``ranges`` is required, ``minItems`` is not set).
* ``vcs`` is omitted: a run records no commit its line numbers refer to.
* ``conversations[].url`` is omitted: a run has no URL. The link back to the
  run rides in ``metadata["io.github.0xcircuitbreaker.opentine"]``
  (reverse-domain of the project home, as the spec asks).
* ``path`` must be repository-relative. An absolute path under *root* is made
  relative; one outside it is not exported and is listed (by count) instead.
* ``version`` is ``"0.1"``: the spec prose says 0.1.0, but the published schema
  requires ``^[0-9]+\\.[0-9]+$``, so the schema-valid spelling is used.

Failed tool calls wrote nothing and are skipped.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._actions import extract_actions
from opentine._agent_identity import run_identity
from opentine._version import __version__

SPEC_VERSION = "0.1"
SCHEMA_URL = "https://agent-trace.dev/schemas/v1/trace-record.json"
VENDOR_KEY = "io.github.0xcircuitbreaker.opentine"
ROOT_MARKER = ".git"  # a checkout marks its root with this entry
MAX_MODEL_ID = 250
_FULL_KEYS = ("content", "file_text", "contents")
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://opentine.com/agent-trace")


def _iso(seconds: float) -> str:
    try:
        when = datetime.fromtimestamp(seconds, UTC) if seconds > 0 else None
    except (OverflowError, OSError, ValueError):
        when = None
    return (when or datetime(1970, 1, 1, tzinfo=UTC)).isoformat().replace("+00:00", "Z")


def model_id(model: str, provider: str) -> str:
    """``provider/model`` (models.dev spelling) when the provider is known."""
    if model and provider and "/" not in model:
        model = f"{provider}/{model}"
    return model[:MAX_MODEL_ID]


def _relative(written: str, root: Path | None) -> str | None:
    path = written.replace("\\", "/")
    if not path or path.startswith("~"):
        return None
    # A leading "/" is rooted everywhere; Windows 3.13+ isabs() says no drive, no root.
    if path.startswith("/") or os.path.isabs(path) or (len(path) > 1 and path[1] == ":"):
        if root is None:
            return None
        try:
            path = Path(path).resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return None
    path = path.removeprefix("./").rstrip("/")
    return path if path and not path.startswith("../") and path != ".." else None


def _full_lines(step: Any) -> int:
    """Lines a whole-file write left behind, or 0 when the write is partial."""
    inputs = step.inputs if isinstance(step.inputs, dict) else {}
    arguments = inputs.get("arguments", inputs.get("input"))
    if not isinstance(arguments, dict):
        return 0
    for key in _FULL_KEYS:
        if isinstance(arguments.get(key), str):
            return len(arguments[key].splitlines())
    return 0


def _tool(run: Any) -> dict[str, str]:
    record = run_identity(run) or {}
    if record.get("harness") and record.get("harness_version"):
        return {"name": str(record["harness"]), "version": str(record["harness_version"])}
    return {"name": "opentine", "version": __version__}


def to_agent_trace(run: Any, root: Path | None = None) -> dict[str, Any]:
    """One Agent Trace record for *run*; absolute paths are taken relative to *root*."""
    actions, clipped = extract_actions(run)
    writes: list[tuple[str, str, Any, Any]] = []  # (path, model id, action, step)
    outside = 0
    for action in actions:
        if action.error or not action.written:
            continue
        step = run.get_step(action.step_id)
        for written in action.written:
            path = _relative(written, root)
            if path is None:
                outside += 1
                continue
            writes.append((path, model_id(action.model, action.provider), action, step))
    last = {path: action.step_id for path, _model, action, _step in writes}
    files: dict[str, dict[str, dict[str, Any]]] = {}
    for path, model, action, step in writes:
        conversations = files.setdefault(path, {})
        contributor = {"type": "ai", **({"model_id": model} if model else {})}
        conversation = conversations.setdefault(model, {"contributor": contributor, "ranges": []})
        lines = _full_lines(step) if step is not None and last[path] == action.step_id else 0
        if lines:
            conversation["ranges"].append({"start_line": 1, "end_line": lines})
    stamps = [action.ts for _path, _model, action, _step in writes if action.ts > 0]
    return {
        "version": SPEC_VERSION,
        "id": str(uuid.uuid5(_NAMESPACE, run.id)),
        "timestamp": _iso(max(stamps) if stamps else float(run.created_at or 0)),
        "tool": _tool(run),
        "files": [
            {"path": path, "conversations": list(conversations.values())}
            for path, conversations in sorted(files.items())
        ],
        "metadata": {
            VENDOR_KEY: {
                "run_id": run.id,
                "status": str(getattr(run.status, "value", run.status)),
                "opentine_version": __version__,
                "write_calls": len({action.step_id for _p, _m, action, _s in writes}),
                "paths_outside_root": outside,
                "actions_clipped": clipped,
            }
        },
    }


def find_root(start: Path) -> Path:
    """The nearest ancestor holding ``.git`` (no subprocess), else *start* itself."""
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ROOT_MARKER).exists():
            return candidate
    return start


def cli_record(run: Any, endpoint: str | None) -> dict[str, Any]:
    """The record ``tine export`` writes, rooted at the enclosing repository.

    *run* is the unredacted run: a scrubbed PEM block collapses lines, so line
    counts come from the recorded write. The record carries only counts and
    paths, the paths are redacted by the action extractor, and the caller
    redacts the whole record once more.
    """
    if endpoint is not None:
        raise ValueError("--format agent-trace writes a record; it cannot be pushed to --endpoint")
    return to_agent_trace(run, find_root(Path.cwd()))


__all__ = ["SCHEMA_URL", "cli_record", "SPEC_VERSION", "find_root", "model_id", "to_agent_trace"]
