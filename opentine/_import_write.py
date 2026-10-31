"""Recording imported events as a run, with the importer's agent identity.

Split from :mod:`opentine._cli_import`. A transcript import names the agent CLI
that wrote it, so its run gets an ``opentine-agent/1`` record (harness from the
format, the first model seen, a fresh instance nonce) instead of reading as a
``legacy:`` label. Like every identity record it is a claim: the agent wrote
the transcript.
"""

from __future__ import annotations

import secrets
from typing import Any

from opentine import _agent_identity as identity
from opentine.repository._annotations import write_run_annotation
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

#: Which agent CLI each transcript format comes from.
HARNESS_OF = {
    "claude-code-transcript": "claude-code",
    "codex-session": "codex",
    "gemini-session": "gemini",
    "qwen-session": "qwen",
    "opencode-session": "opencode",
    "atif": "atif",
    "hermes-trajectory": "hermes",
    "entire": "entire",
}


def first_model(events: list[TraceEvent]) -> str:
    return next((item.model for item in events if item.kind == "model" and item.model), "")


def import_identity(
    source_format: str, events: list[TraceEvent], *, harness: str = "", **lineage: str
) -> dict[str, Any] | None:
    """The record for an imported run, or ``None`` for a non-transcript format."""
    name = harness or HARNESS_OF.get(source_format, "")
    if not name and source_format.startswith("adapter:"):
        from opentine.harnesses._adapter_spec import resolve

        name = resolve(source_format[8:]).harness or source_format[8:]
    if not name:
        return None
    try:
        return identity.build(
            harness=name, model=first_model(events), instance=secrets.token_hex(16), **lineage
        )
    except identity.IdentityError:
        try:  # a malformed lineage claim is dropped, never guessed
            return identity.build(harness=name, model=first_model(events))
        except identity.IdentityError:
            return None


def annotate(repo: Any, run_id: str, metadata: dict[str, Any]) -> None:
    kept = {key: value for key, value in metadata.items() if value}
    if kept:
        write_run_annotation(repo, run_id, kept, [])


def record(
    repo: Any,
    events: list[TraceEvent],
    ref: str,
    capture: dict | None,
    source_format: str = "",
) -> str:
    """Record *events* on *ref* and annotate the run; its final id."""
    recorder = Recorder.start(repo, ref=ref, capture=False)
    recorder.import_events(events, trusted_billing=True)  # distrusted + priced by the caller
    run_id = recorder.finalize()
    # A transcript is the agent's own, agent-writable account of itself.
    annotate(
        repo,
        run_id,
        {
            "capture": capture,
            "agent_identity": import_identity(source_format, events) if capture else None,
        },
    )
    return run_id


__all__ = ["HARNESS_OF", "annotate", "first_model", "import_identity", "record"]
