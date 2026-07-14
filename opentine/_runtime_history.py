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
        messages = _messages_from_transcript(resumed.transcript)
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
