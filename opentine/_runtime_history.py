"""Replay and resume operations separated from the execution loop.

``validate_run_record`` types a run's *containers* -- transcript is a list, manifest
and metadata are objects, refs map strings to stored step IDs -- and deliberately
leaves what is inside them open, because that openness is what lets a newer writer
add a field this build round-trips without understanding. ``save()`` then writes
those values back verbatim. So every read here of a transcript item, of
``manifest["resume_history"]``, of an assistant message's ``tool_calls``, is a read
of a value that a ``.tine`` file this build's own validator accepts may hold in any
shape -- and each one that assumed a shape turned ``agent.resume()`` on a *loadable*
run into a raw ``AttributeError``/``TypeError``/``IndexError``.

The rule this module now applies, per site, is the one the rest of the release
settled on: resume may not be stricter than ``Run.load``, so a record that simply is
not a message is skipped exactly the way an absent one is; but where the shape is
what a *safety* check reads, an unreadable value is a refusal with a message, never
a shrug that resumes from an incoherent point.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from opentine._runtime_accounting import _container
from opentine.graph import Run, RunStatus


def _messages_from_transcript(transcript: list[dict]) -> list[dict]:
    """Chat messages recoverable from a transcript, skipping records that are not any.

    ``validate_run_record`` constrains nothing about transcript *items*, so ``5``,
    ``"abc"``, ``None`` and ``[1]`` are all validator-accepted entries and ``.items()``
    on one raised ``AttributeError`` out of ``agent.resume()`` and ``agent.replay()``.
    ``_graph_analysis._causal_transcript`` already fixed the rule for the other reader
    of this field -- "loading tolerates non-dict items, so fork treats them as unscoped
    turns" -- and this loop follows it: the record stays in the transcript, because it
    is somebody's audit evidence and dropping it would rewrite their artifact, but it
    is not a message. A non-mapping is no more a chat turn than the mapping without a
    ``role`` that this loop has always skipped, so both are treated as absence.
    """
    messages = []
    for item in transcript:
        if not isinstance(item, dict):
            continue
        message = {key: value for key, value in item.items() if key != "step_id"}
        if "role" in message:
            messages.append(message)
    return messages


def _batch_ids(message: dict[str, Any]) -> list[str]:
    """Call IDs of one assistant tool-call batch, refusing a record it cannot read.

    The opposite call from ``_messages_from_transcript``, and for a reason. A truthy
    ``tool_calls`` that is not a list of objects (``5`` -> ``TypeError: 'int' object is
    not iterable``; ``"a"``/``[5]``/``[None]`` -> ``AttributeError``) cannot be skipped
    like absence: the only job of the caller is to prove the resume point is *not*
    inside an unterminated batch, and a value it cannot enumerate is exactly the case
    where it cannot prove that. Calling it "no tool calls" would resume mid-batch and
    forward the unusable field to the provider besides. So it refuses the way the two
    coherence failures in the caller already do -- the run still loads, shows, diffs
    and forks, and an earlier ``from_step`` still resumes it. A falsy value (absent,
    ``[]``, ``0``) is not a batch and never reaches here, which is what this code did
    with it before the guard.
    """
    calls = message["tool_calls"]
    if not isinstance(calls, list) or any(not isinstance(call, dict) for call in calls):
        raise RuntimeError("resume transcript has a tool-call record that is not a list of objects")
    return [str(call.get("id") or call.get("name") or "") for call in calls]


def _require_complete_tool_batches(messages: list[dict]) -> None:
    pending: list[str] = []
    for message in messages:
        role = message.get("role")
        if pending and role != "tool":
            raise RuntimeError("resume point ends inside a tool-call batch")
        if role == "assistant" and message.get("tool_calls"):
            pending = _batch_ids(message)
        elif role == "tool" and pending:
            identifier = str(message.get("tool_call_id") or message.get("name") or "")
            if identifier not in pending:
                raise RuntimeError("resume transcript has an unmatched tool result")
            pending.remove(identifier)
    if pending:
        raise RuntimeError("resume point ends inside a tool-call batch")


class HistoryMixin:
    async def replay(self, run: Run, mode: Literal["cache", "rerun"] = "cache") -> Run:
        if mode == "cache":
            # RunBase seeds refs["main"] with "" when the graph is empty, so the `or`
            # chain fell through to steps[-1] and raised IndexError on a run that has no
            # recorded steps -- a shape validate_run_record accepts and Run.load returns.
            # There is no tip to reuse, so name the mode that does work on such a run.
            tip = run.refs.get("main") or (run.steps[-1].id if run.steps else "")
            if not tip:
                raise RuntimeError("cannot cache-replay a run with no recorded steps; use rerun")
            replayed = run.fork(tip, new_run_id=f"{run.id}-replay")
            replayed.metadata["replay"] = {
                "mode": "cache",
                "reused_steps": len(replayed.steps),
                "source_run": run.id,
            }
            replayed.status = RunStatus.completed
            return replayed
        return await self.run(run.user_prompt or "", run_id=f"{run.id}-rerun")

    async def resume(
        self,
        run: Run,
        from_step: str | None = None,
        prompt: str | None = None,
    ) -> Run:
        if run.manifest and not run.manifest.get("resume", False):
            raise RuntimeError("Run manifest declares that resume is unsupported")
        base = from_step or run.refs.get("main") or (run.steps[-1].id if run.steps else None)
        resumed = run.fork(base, new_run_id=f"{run.id}-resume") if base else run
        source_model = resumed.model_info
        resumed.model_info = self.model.name
        resumed.system_prompt = self.system
        resumed.manifest["model"] = {"name": self.model.name}
        resumed.manifest["tools"] = [schema["name"] for schema in self.schemas]
        if self.budget is not None:
            resumed.manifest["budget"] = self.budget.to_dict()
        resumed.metadata["model_info"] = self.model.name
        resumed.metadata["system_prompt"] = self.system
        # setdefault rescues absence and then appended to whatever a scalar
        # manifest["resume_history"] happened to be. Replacing a wrong shape rather than
        # refusing is what every other path already does with this field: Run.fork pops
        # resume_history outright, so the ordinary resume (any run with a step to fork
        # from) starts a fresh list regardless -- only the zero-step run, which forks
        # nothing, ever inherited one. A junk audit field must not cost a resumable run.
        history, _ = _container(resumed.manifest, "resume_history", list, [])
        history.append({"from_model": source_model, "model": self.model.name})
        messages = _messages_from_transcript(resumed.transcript)
        _require_complete_tool_batches(messages)
        if prompt:
            messages.append({"role": "user", "content": prompt})
            resumed.transcript.append({"role": "user", "content": prompt})
        resumed.status = RunStatus.running
        autosaver = self._make_autosaver()
        try:
            await self._continue(resumed, messages, autosaver=autosaver)
        finally:
            await asyncio.to_thread(autosaver.flush, resumed)
        return resumed
