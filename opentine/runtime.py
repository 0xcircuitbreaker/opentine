"""Agent runtime, replay, and resume contracts."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from typing import Any, Literal, Protocol, runtime_checkable

from opentine.cache import CacheEntry, semantic_key
from opentine.graph import Run, RunStatus, StepKind, step_id
from opentine.tools import tool_schema


@runtime_checkable
class Model(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def supports_tools(self) -> bool: ...
    @property
    def supports_thinking(self) -> bool: ...

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> dict[str, Any]: ...

    async def stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        system: str | None = None,
        temperature: float = 0.0,
    ) -> AsyncIterator[dict[str, Any]]: ...


class Agent:
    """Executes opentine-native model/tool runs."""

    supports_resume = True

    def __init__(
        self,
        model: Model,
        tools: list[Callable] | None = None,
        system: str = "You are a helpful assistant.",
        max_steps: int = 30,
        max_output_chars: int = 8000,
    ):
        self.model = model
        self.tools = {fn.__name__: fn for fn in (tools or [])}
        self.schemas = [tool_schema(fn) for fn in (tools or [])]
        self.system = system
        self.max_steps = max_steps
        self.max_output_chars = max_output_chars

    async def _call_tool(self, name: str, args: dict[str, Any]) -> str:
        result = self.tools[name](**args)
        result = await result if asyncio.iscoroutine(result) else result
        out = str(result)
        if len(out) > self.max_output_chars:
            out = out[: self.max_output_chars - 14] + "... (truncated)"
        return f"[Tool output from {name}] {out}"

    async def run(self, prompt: str, run_id: str | None = None) -> Run:
        rid = run_id or step_id(StepKind.model, {"prompt": prompt, "created_at": time.time_ns()})
        run = Run(
            id=rid,
            model_info=self.model.name,
            system_prompt=self.system,
            user_prompt=prompt,
            manifest={
                "kind": "opentine-native",
                "resume": True,
                "replay": ["cache", "rerun"],
                "model": {"name": self.model.name},
                "tools": [schema["name"] for schema in self.schemas],
            },
            policies={},
            metadata={
                "model_info": self.model.name,
                "system_prompt": self.system,
                "user_prompt": prompt,
            },
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        run.transcript.append({"role": "user", "content": prompt})
        await self._continue(run, messages)
        return run

    async def _continue(self, run: Run, messages: list[dict[str, Any]]) -> Run:
        for _ in range(self.max_steps):
            request = {
                "model": self.model.name,
                "messages": messages,
                "tools": self.schemas if self.tools else None,
                "system": self.system,
                "temperature": 0.0,
            }
            cache_key = semantic_key("model.complete", request)
            t0 = time.time()
            resp = await self.model.complete(
                messages, tools=self.schemas if self.tools else None, system=self.system
            )
            dt = time.time() - t0
            run.cache[cache_key] = CacheEntry(
                cache_key,
                "model.complete",
                dict(resp),
                {"mode": "rerun", "model": self.model.name},
            ).to_dict()
            text = resp.get("text", "")
            tool_calls = resp.get("tool_calls", [])
            cost = resp.get("cost", 0.0)
            if text:
                kind = StepKind.done if not tool_calls else StepKind.think
                step = run.add_step(kind, {"text": text}, cost=cost, duration=dt)
                run.transcript.append({"step_id": step.id, "role": "assistant", "content": text})
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": text}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            messages.append(assistant_msg)
            if not tool_calls:
                run.status = RunStatus.completed
                break
            for tc in tool_calls:
                tname, targs = tc["name"], tc.get("arguments", {})
                tc_id = tc.get("id", tname)
                tool_key = semantic_key("tool.call", {"name": tname, "arguments": targs})
                try:
                    result_str = await self._call_tool(tname, targs)
                    run.cache[tool_key] = CacheEntry(
                        tool_key,
                        "tool.call",
                        {"result": result_str},
                        {"mode": "rerun", "tool": tname},
                    ).to_dict()
                except Exception as exc:
                    result_str = f"[Tool output from {tname}] Error: {exc}"
                    run.add_step(
                        StepKind.error,
                        {"tool": tname, "error": result_str},
                        outputs={"result": result_str},
                        error={"type": type(exc).__name__, "message": str(exc)},
                    )
                step = run.add_step(
                    StepKind.tool,
                    {"name": tname, "arguments": targs},
                    outputs={"result": result_str},
                    tool_info={"name": tname},
                )
                run.transcript.append(
                    {
                        "step_id": step.id,
                        "role": "tool",
                        "content": result_str,
                        "name": tname,
                        "tool_call_id": tc_id,
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "content": result_str,
                        "name": tname,
                        "tool_call_id": tc_id,
                    }
                )
        else:
            run.status = RunStatus.failed
            run.add_step(StepKind.error, {"text": "Max steps reached"})
        return run

    async def replay(self, run: Run, mode: Literal["cache", "rerun"] = "cache") -> Run:
        if mode == "cache":
            tip = run.refs.get("main") or run.steps[-1].id
            replayed = run.fork(tip, new_run_id=f"{run.id}-replay")
            replayed.metadata["replay"] = {
                "mode": "cache",
                "source_run": run.id,
                "reused_steps": len(replayed.steps),
            }
            replayed.status = RunStatus.completed
            return replayed
        return await self.run(run.user_prompt or "", run_id=f"{run.id}-rerun")

    async def resume(
        self, run: Run, from_step: str | None = None, prompt: str | None = None
    ) -> Run:
        if run.manifest and not run.manifest.get("resume", False):
            raise RuntimeError("Run manifest declares that resume is unsupported")
        base_ref = from_step or run.refs.get("main") or (run.steps[-1].id if run.steps else None)
        resumed = run.fork(base_ref, new_run_id=f"{run.id}-resume") if base_ref else run
        messages = _messages_from_transcript(resumed.transcript)
        if prompt:
            messages.append({"role": "user", "content": prompt})
            resumed.transcript.append({"role": "user", "content": prompt})
        resumed.status = RunStatus.running
        return await self._continue(resumed, messages)

    def run_sync(self, prompt: str, run_id: str | None = None) -> Run:
        return asyncio.run(self.run(prompt, run_id))

    def replay_sync(self, run: Run, mode: Literal["cache", "rerun"] = "cache") -> Run:
        return asyncio.run(self.replay(run, mode))

    def resume_sync(self, run: Run, from_step: str | None = None, prompt: str | None = None) -> Run:
        return asyncio.run(self.resume(run, from_step, prompt))


def _messages_from_transcript(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    messages = []
    for item in transcript:
        msg = {k: v for k, v in item.items() if k not in {"step_id"}}
        if "role" in msg:
            messages.append(msg)
    return messages
