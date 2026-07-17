"""Model/tool execution loop; every invocation is recorded exactly once."""

from __future__ import annotations

import time
from typing import Any

from opentine.autosave import Autosaver
from opentine.cache import CacheEntry, semantic_key
from opentine.graph import Run, RunStatus, StepKind


class RuntimeLoopMixin:
    async def _invoke(self, run: Run, messages: list[dict[str, Any]], request: dict[str, Any]):
        started = time.time()
        try:
            response = await self.model.complete(
                messages,
                tools=self.schemas if self.tools else None,
                system=self.system,
            )
        except Exception as exc:
            partial = getattr(exc, "opentine_response", None)
            partial = partial if isinstance(partial, dict) else {}
            step = run.add_step(
                StepKind.error,
                {"text": "Model invocation failed"},
                outputs={"partial": partial.get("text", "")},
                duration=time.time() - started,
                cost=partial.get("cost", 0),
                usage=partial.get("usage"),
                billing=partial.get("billing"),
                error={"message": str(exc), "type": type(exc).__name__},
            )
            self._pin_billing(run, step.id, partial.get("billing") or {})
            raise
        duration = time.time() - started
        cache_key = semantic_key("model.complete", request)
        run.cache[cache_key] = CacheEntry(
            cache_key,
            "model.complete",
            dict(response),
            {"mode": "rerun", "model": self.model.name},
        ).to_dict()
        return response, duration

    def _record_model(
        self,
        run: Run,
        response: dict[str, Any],
        duration: float,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        self._warnings(run, response)
        text = response.get("text", "")
        tool_calls = response.get("tool_calls", [])
        refusal = response.get("refusal")
        kind = (
            StepKind.error
            if refusal
            else StepKind.think
            if text and tool_calls
            else StepKind.model
            if tool_calls or not text
            else StepKind.done
        )
        outputs = {
            key: response[key]
            for key in ("tool_calls", "refusal", "thinking", "reasoning_content")
            if response.get(key)
        }
        billing = response.get("billing") or {}
        step = run.add_step(
            kind,
            {"text": text},
            outputs=outputs,
            cost=response.get("cost", 0),
            duration=duration,
            usage=response.get("usage"),
            billing=billing,
            error={"message": str(refusal), "type": "ModelRefusal"} if refusal else None,
        )
        self._pin_billing(run, step.id, billing)
        assistant = {"step_id": step.id, "role": "assistant", "content": text}
        if tool_calls:
            assistant["tool_calls"] = tool_calls
        for key in ("response_items", "reasoning_content", "refusal"):
            if response.get(key):
                assistant[key] = response[key]
        run.transcript.append(dict(assistant))
        message = {key: value for key, value in assistant.items() if key != "step_id"}
        return message, tool_calls, bool(refusal)

    async def _execute_tools(
        self,
        run: Run,
        messages: list[dict[str, Any]],
        tool_calls: list[dict[str, Any]],
    ) -> None:
        for call in tool_calls:
            name, arguments = call["name"], call.get("arguments", {})
            call_id = call.get("id", name)
            cache_key = semantic_key("tool.call", {"arguments": arguments, "name": name})
            try:
                result = await self._call_tool(name, arguments)
                run.cache[cache_key] = CacheEntry(
                    cache_key,
                    "tool.call",
                    {"result": result},
                    {"mode": "rerun", "tool": name},
                ).to_dict()
            except Exception as exc:
                result = f"[Tool output from {name}] Error: {exc}"
                run.add_step(
                    StepKind.error,
                    {"error": result, "tool": name},
                    outputs={"result": result},
                    error={"message": str(exc), "type": type(exc).__name__},
                )
            step = run.add_step(
                StepKind.tool,
                {"arguments": arguments, "name": name},
                outputs={"result": result},
                tool_info={"name": name},
            )
            message = {
                "step_id": step.id,
                "role": "tool",
                "content": result,
                "name": name,
                "tool_call_id": call_id,
            }
            run.transcript.append(message)
            messages.append({key: value for key, value in message.items() if key != "step_id"})

    async def _continue(
        self,
        run: Run,
        messages: list[dict[str, Any]],
        autosaver: Autosaver | None = None,
    ) -> Run:
        budget = run.budget()
        for _ in range(self.max_steps):
            if budget is not None and self._enforce_budget(run, budget):
                return run
            request = {
                "messages": messages,
                "model": self.model.name,
                "system": self.system,
                "temperature": 0.0,
                "tools": self.schemas if self.tools else None,
            }
            response, duration = await self._invoke(run, messages, request)
            assistant, tool_calls, refused = self._record_model(run, response, duration)
            messages.append(assistant)
            if refused:
                run.status = RunStatus.failed
                break
            if not tool_calls:
                run.status = RunStatus.completed
                break
            await self._execute_tools(run, messages, tool_calls)
            if autosaver is not None:
                autosaver.maybe_save(run)
        else:
            run.status = RunStatus.failed
            run.add_step(StepKind.error, {"text": "Max steps reached"})
        return run
