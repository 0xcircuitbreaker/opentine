"""Import an Entire checkpoint session (``tine import --format entire``).

SOURCE is a git repository with Entire's ``entire/checkpoints/v1`` branch (see
:mod:`opentine.trace._entire_git` for the on-branch layout, as written by
``github.com/entireio/cli``). ``REPO`` imports the newest checkpoint's last
session, ``REPO::ID`` a checkpoint by id or unique prefix, and ``REPO::ID/N``
its session ``N`` (0-based, in the order the checkpoint summary lists them).

The session's raw transcript is handed to the existing transcript importer for
the agent that wrote it (Claude Code, Codex, Gemini CLI); ``full.jsonl`` is the
whole session up to that checkpoint, so the run is the session so far. An agent
with no transcript importer here, or a session without a transcript, imports as
one human step carrying ``prompt.txt``. Either way the first event carries the
checkpoint's metadata under ``attributes["entire"]``: ids, agent, model,
strategy, branch, commit, files touched and Entire's own token usage.
Everything read is untrusted: shapes are checked, sizes bounded, strings clipped,
and the recorder's redaction runs on every stored payload as for any import.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from opentine._git_link import GitLinkError
from opentine.trace import _entire_git as eg
from opentine.trace._import_helpers import note_import_warning
from opentine.trace._transcript_claude import claude_transcript_events
from opentine.trace._transcript_codex import codex_session_events
from opentine.trace._transcript_common import Chain, label, session_trace_id
from opentine.trace._transcript_gemini import gemini_session_events
from opentine.trace.schema import TraceEvent

FORMAT = "entire"
#: Entire's ``agent`` field (entireio/cli agent/registry.go) to an importer.
AGENT_IMPORTERS = {
    "Claude Code": ("claude-code-transcript", claude_transcript_events),
    "Codex": ("codex-session", codex_session_events),
    "Gemini CLI": ("gemini-session", gemini_session_events),
}
MAX_FILES = 1000
MAX_TEXT = 4096
_USAGE_KEYS = (
    "input_tokens",
    "cache_creation_tokens",
    "cache_read_tokens",
    "output_tokens",
    "api_call_count",
)
_KEPT = ("cli_version", "strategy", "branch", "commit_sha", "created_at", "turn_id", "kind")


def split_source(source: Any) -> tuple[Path, str | None, int | None]:
    """``(repo, checkpoint or None, session index or None)`` from SOURCE."""
    if not isinstance(source, (str, Path)):
        raise ValueError("entire imports read a git repository path, not a stream")
    text = str(source)
    head, sep, tail = text.rpartition("::")
    if not sep or Path(text).exists():
        return Path(text), None, None
    checkpoint, slash, index = tail.partition("/")
    if slash and not (index.isdigit() and len(index) <= 4):
        raise ValueError(f"not a session index: {index[:20]!r}")
    return Path(head), checkpoint or None, int(index) if slash else None


def _json(raw: bytes | None, what: str) -> dict[str, Any]:
    if raw is None:
        raise ValueError(f"{what} is missing")
    try:
        value = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"{what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{what} is not a JSON object")
    return value


def _usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {
        key: value[key]
        for key in _USAGE_KEYS
        if type(value.get(key)) is int and 0 <= value[key] < 1 << 53
    }


def entire_attributes(checkpoint: str, index: int, meta: dict[str, Any]) -> dict[str, Any]:
    """The checkpoint metadata kept on the run, every field shape-checked."""
    kept: dict[str, Any] = {"checkpoint_id": checkpoint, "session_index": index}
    for key in ("session_id", "agent", "model", *_KEPT):
        if isinstance(meta.get(key), str) and meta[key]:
            kept[key] = meta[key][:MAX_TEXT]
    files = meta.get("files_touched")
    if isinstance(files, list):
        kept["files_touched"] = [str(item)[:MAX_TEXT] for item in files[:MAX_FILES]]
    usage = _usage(meta.get("token_usage"))
    if usage:
        kept["token_usage"] = usage
    start = meta.get("checkpoint_transcript_start")
    if type(start) is int and start >= 0:
        kept["checkpoint_transcript_start"] = start
    return kept


def _fallback(attrs: dict[str, Any], prompt: bytes | None) -> list[TraceEvent]:
    chain = Chain(session_trace_id(attrs.get("session_id") or attrs["checkpoint_id"]))
    text = (prompt or b"").decode("utf-8", "replace")
    chain.add(
        "human",
        attrs.get("created_at"),
        "prompt",
        actor="user",
        inputs={"prompt": text},
        model=label(attrs.get("model")),
    )
    return chain.events


def entire_events(source: Any) -> list[TraceEvent]:
    try:
        return _events(source)
    except GitLinkError as exc:  # a RuntimeError; an import failure is a refusal
        raise ValueError(f"git: {exc}") from exc


def _events(source: Any) -> list[TraceEvent]:
    repo, wanted, index = split_source(source)
    if not repo.is_dir():
        raise ValueError(f"{repo} is not a directory")
    ref = eg.find_ref(repo)
    checkpoint = eg.resolve_checkpoint(repo, ref, wanted)
    base = eg.checkpoint_path(checkpoint)
    summary = _json(eg.read_blob(repo, ref, f"{base}/metadata.json", eg.MAX_METADATA_BYTES), base)
    dirs = eg.session_dirs(checkpoint, summary)
    if not dirs:
        raise ValueError(f"checkpoint {checkpoint} lists no readable sessions")
    if index is None:
        index = len(dirs) - 1
    if index >= len(dirs):
        raise ValueError(f"checkpoint {checkpoint} has {len(dirs)} session(s); no {index}")
    session = dirs[index]
    raw = eg.read_blob(repo, ref, f"{session}/metadata.json", eg.MAX_METADATA_BYTES)
    meta = _json(raw, f"{session}/metadata.json")
    attrs = entire_attributes(checkpoint, index, meta)
    importer = AGENT_IMPORTERS.get(str(meta.get("agent", "")))
    events: list[TraceEvent] = []
    transcript = eg.transcript_bytes(repo, ref, session) if importer else None
    if importer and transcript:
        attrs["transcript_format"] = importer[0]
        events = importer[1](transcript.decode("utf-8", "replace").splitlines())
    if not events:
        prompt = eg.read_blob(repo, ref, f"{session}/prompt.txt", eg.MAX_PROMPT_BYTES)
        events = _fallback(attrs, prompt)
    first = dict(events[0].attributes or {})
    first["entire"] = attrs
    if importer is None:
        note_import_warning(first, f"no transcript importer for agent {attrs.get('agent', '')!r}")
    return [replace(events[0], attributes=first), *events[1:]]
