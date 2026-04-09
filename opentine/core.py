"""Core primitives: Step, Run, Model protocol, and Agent runtime."""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
from collections.abc import AsyncIterator, Callable
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import msgspec

# --- Step -------------------------------------------------------------------

class StepKind(str, Enum):
    think = "think"
    tool = "tool"
    model = "model"
    done = "done"
    error = "error"

class Step(msgspec.Struct, frozen=True, tag=True):
    id: str
    parent_id: str | None
    kind: StepKind
    inputs: dict[str, Any]
    outputs: dict[str, Any] = {}
    model_info: str = ""
    timestamp: float = 0.0
    duration: float = 0.0
    cost: float = 0.0

def step_id(kind: StepKind, inputs: dict[str, Any], parent_id: str | None = None) -> str:
    """Content-addressed ID: sha256(kind + inputs + parent)[:12]."""
    blob = msgspec.json.encode({"k": kind.value, "i": inputs, "p": parent_id})
    return hashlib.sha256(blob).hexdigest()[:12]

# --- Run (the tree) ---------------------------------------------------------

class RunStatus(str, Enum):
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"

class Run(msgspec.Struct, tag=True):
    id: str
    steps: list[Step] = []
    status: RunStatus = RunStatus.running
    model_info: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    created_at: float = 0.0
    metadata: dict[str, Any] = {}

    def add_step(self, kind: StepKind, inputs: dict[str, Any], outputs: dict[str, Any] | None = None,
                 parent_id: str | None = None, duration: float = 0.0, cost: float = 0.0) -> Step:
        parent = parent_id or (self.steps[-1].id if self.steps else None)
        s = Step(id=step_id(kind, inputs, parent), parent_id=parent, kind=kind, inputs=inputs,
                 outputs=outputs or {}, model_info=self.model_info, timestamp=time.time(),
                 duration=duration, cost=cost)
        self.steps.append(s)
        return s

    def get_step(self, sid: str) -> Step | None:
        return next((s for s in self.steps if s.id == sid), None)

    def children(self, sid: str) -> list[Step]:
        return [s for s in self.steps if s.parent_id == sid]

    def root_steps(self) -> list[Step]:
        return [s for s in self.steps if s.parent_id is None]

    def ancestors(self, sid: str) -> list[Step]:
        chain: list[Step] = []
        cur = self.get_step(sid)
        while cur:
            chain.append(cur)
            cur = self.get_step(cur.parent_id) if cur.parent_id else None
        chain.reverse()
        return chain

    @property
    def total_cost(self) -> float:
        return sum(s.cost for s in self.steps)

    @property
    def total_duration(self) -> float:
        return sum(s.duration for s in self.steps)

    def fork(self, from_step_id: str, new_run_id: str | None = None) -> Run:
        kept = self.ancestors(from_step_id)
        rid = new_run_id or step_id(StepKind.model, {"fork": from_step_id})
        return Run(id=rid, steps=list(kept), status=RunStatus.running, model_info=self.model_info,
                   system_prompt=self.system_prompt, user_prompt=self.user_prompt,
                   created_at=time.time(),
                   metadata={**self.metadata, "forked_from": self.id, "fork_point": from_step_id})

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(msgspec.json.encode(self))
        return p

    @classmethod
    def load(cls, path: str | Path) -> Run:
        return msgspec.json.decode(Path(path).read_bytes(), type=cls)

    def pause(self, path: str | Path) -> Path:
        self.status = RunStatus.paused
        return self.save(path)

    @classmethod
    def resume(cls, path: str | Path) -> Run:
        run = cls.load(path)
        run.status = RunStatus.running
        return run

# --- Model protocol ---------------------------------------------------------

@runtime_checkable
class Model(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def supports_tools(self) -> bool: ...
    @property
    def supports_thinking(self) -> bool: ...

    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                       system: str | None = None, temperature: float = 0.0) -> dict[str, Any]: ...
    async def stream(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
                     system: str | None = None, temperature: float = 0.0) -> AsyncIterator[dict[str, Any]]: ...

# --- Tool introspection -----------------------------------------------------

_TYPE_MAP = {str: "string", int: "integer", float: "number", bool: "boolean"}

def tool_schema(fn: Callable) -> dict[str, Any]:
    """Build a tool-use schema from a function's signature + docstring."""
    sig = inspect.signature(fn)
    props, required = {}, []
    for name, p in sig.parameters.items():
        props[name] = {"type": _TYPE_MAP.get(p.annotation, "string"), "description": name}
        if p.default is inspect.Parameter.empty:
            required.append(name)
    return {"name": fn.__name__, "description": (fn.__doc__ or "").strip(),
            "input_schema": {"type": "object", "properties": props, "required": required}}

# --- Agent runtime ----------------------------------------------------------

class Agent:
    """Executes a run: Model calls, tool dispatch, tree construction."""
    def __init__(self, model: Model, tools: list[Callable] | None = None,
                 system: str = "You are a helpful assistant.", max_steps: int = 30):
        self.model = model
        self.tools = {fn.__name__: fn for fn in (tools or [])}
        self.schemas = [tool_schema(fn) for fn in (tools or [])]
        self.system = system
        self.max_steps = max_steps

    async def _call_tool(self, name: str, args: dict[str, Any]) -> Any:
        fn = self.tools[name]
        result = fn(**args)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    async def run(self, prompt: str, run_id: str | None = None) -> Run:
        rid = run_id or step_id(StepKind.model, {"prompt": prompt})
        run = Run(id=rid, model_info=self.model.name, system_prompt=self.system,
                  user_prompt=prompt, created_at=time.time())
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

        for _ in range(self.max_steps):
            t0 = time.time()
            resp = await self.model.complete(messages, tools=self.schemas if self.tools else None,
                                             system=self.system)
            dt = time.time() - t0
            text, tool_calls, cost = resp.get("text", ""), resp.get("tool_calls", []), resp.get("cost", 0.0)

            if text:
                kind = StepKind.done if not tool_calls else StepKind.think
                run.add_step(kind, {"text": text}, cost=cost, duration=dt)
                messages.append({"role": "assistant", "content": text})
            if not tool_calls:
                run.status = RunStatus.completed
                break
            for tc in tool_calls:
                tname, targs = tc["name"], tc.get("arguments", {})
                run.add_step(StepKind.tool, {"name": tname, "arguments": targs})
                try:
                    result_str = str(await self._call_tool(tname, targs))
                except Exception as e:
                    result_str = f"Error: {e}"
                    run.add_step(StepKind.error, {"tool": tname, "error": result_str})
                messages.append({"role": "tool", "content": result_str, "name": tname})
        else:
            run.status = RunStatus.failed
            run.add_step(StepKind.error, {"text": "Max steps reached"})
        return run

    def run_sync(self, prompt: str, run_id: str | None = None) -> Run:
        return asyncio.run(self.run(prompt, run_id))
