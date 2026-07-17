"""Replay and resume operations separated from the execution loop."""

from __future__ import annotations

import asyncio
from typing import Literal

from opentine.graph import Run, RunStatus


def _messages_from_transcript(transcript: list[dict]) -> list[dict]:
    messages = []
    for item in transcript:
        message = {key: value for key, value in item.items() if key != "step_id"}
        if "role" in message:
            messages.append(message)
    return messages


def _require_complete_tool_batches(messages: list[dict]) -> None:
    pending: list[str] = []
    for message in messages:
        role = message.get("role")
        if pending and role != "tool":
            raise RuntimeError("resume point ends inside a tool-call batch")
        if role == "assistant" and message.get("tool_calls"):
            pending = [
                str(call.get("id") or call.get("name") or "") for call in message["tool_calls"]
            ]
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
            tip = run.refs.get("main") or run.steps[-1].id
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
        history = resumed.manifest.setdefault("resume_history", [])
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
