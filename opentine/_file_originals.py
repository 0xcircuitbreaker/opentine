"""A file's full content before a run first edited it, kept for ``tine rewind``.

Claude Code (``toolUseResult.originalFile``) and Gemini CLI
(``resultDisplay.originalContent``) report what a file held before an edit.
A recorder keeps that once per file, content-addressed: the step's outputs get
a small ``file_original`` marker (path and ``sha256:`` digest, plus the digest
of the content after the edit when the harness reports it) and the text goes
to ``run.metadata["file_originals"]`` under its digest, never into the step.

The text is redacted on save like everything else. Its digest is taken before,
so a redacted (or clipped) original no longer matches and rewind refuses to use
it instead of writing ``[REDACTED]`` into the user's file.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

KEY = "file_originals"
MARKER = "file_original"
MAX_ORIGINAL_CHARS = 2_000_000  # one file
MAX_TOTAL_CHARS = 16_000_000  # one run


def digest(text: str) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:  # a lone surrogate has no bytes to compare
        return None


class Originals:
    """Per-session capture: each path's original is kept once, within budget."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.total = 0

    def marker(self, path: Any, original: Any, post: Any = None) -> dict[str, Any] | None:
        found: dict[str, Any] = {}
        if isinstance(post, str) and (after := digest(post)):
            found["post_sha256"] = after
        if (
            isinstance(path, str)
            and path
            and path not in self.seen
            and isinstance(original, str)
            and len(original) <= MAX_ORIGINAL_CHARS
            and self.total + len(original) <= MAX_TOTAL_CHARS
            and (before := digest(original))
        ):
            self.seen.add(path)
            self.total += len(original)
            found.update(path=path, sha256=before, content=original)
        return found or None

    def claude(self, result: Any) -> dict[str, Any] | None:
        """From a Claude Code ``toolUseResult`` (Edit, MultiEdit, Write)."""
        if not isinstance(result, dict):
            return None
        original = result.get("originalFile", result.get("originalFileContents"))
        post = result.get("content") if result.get("type") in ("create", "update") else None
        return self.marker(result.get("filePath"), original, post)

    def gemini(self, arguments: Any, display: Any) -> dict[str, Any] | None:
        """From a Gemini CLI tool call's ``resultDisplay`` (replace, write_file)."""
        if not isinstance(display, dict) or not isinstance(arguments, dict):
            return None
        path = arguments.get("file_path", arguments.get("absolute_path"))
        return self.marker(path, display.get("originalContent"), display.get("newContent"))


def hoist(store: dict[str, Any], outputs: Any) -> Any:
    """*outputs* with the original's text moved into *store* under its digest."""
    marker = outputs.get(MARKER) if isinstance(outputs, dict) else None
    if not isinstance(marker, dict) or "content" not in marker:
        return outputs
    kept = {key: value for key, value in marker.items() if key != "content"}
    if isinstance(marker.get("sha256"), str) and isinstance(marker["content"], str):
        store.setdefault(KEY, {})[marker["sha256"]] = marker["content"]
    return {**outputs, MARKER: kept}


def hoist_events(events: list[Any]) -> tuple[list[Any], dict[str, str]]:
    """Trace events without inline originals, and the originals by digest."""
    store: dict[str, Any] = {}
    out = [
        dataclasses.replace(event, outputs=hoist(store, event.outputs))
        if isinstance(event.outputs.get(MARKER), dict)
        else event
        for event in events
    ]
    return out, store.get(KEY, {})


__all__ = ["KEY", "MARKER", "Originals", "digest", "hoist", "hoist_events"]
