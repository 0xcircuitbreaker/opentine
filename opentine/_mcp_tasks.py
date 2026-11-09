"""MCP 2025-11-25 tasks for ``tine mcp`` tool calls (0.47, SPEC 8.20).

On a 2025-11-25 connection, a ``tools/call`` whose params carry ``task``
(``{"ttl": <ms>}``) returns at once with ``{"task": {...}}`` (status
``working``) and runs the tool in the background; ``tasks/get``, ``tasks/result``,
``tasks/list`` and
``tasks/cancel`` follow it. The SDK leaves ``tasks/*`` out of its spec method
table, so the methods are served by an extension (:func:`extension`) and the
calls turned into tasks by :class:`TaskMiddleware`, both bound at
construction; a server class that takes no extensions simply has no tasks.

:class:`TaskStore` is the protocol state and has no SDK dependency: ids are 128
random bits, a ttl is clamped to :data:`MIN_TTL_MS` .. :data:`MAX_TTL_MS`, at
most :data:`MAX_TASKS` are held (the oldest finished one is forgotten first,
and a store full of working tasks refuses a new one), and an expired task is
forgotten on the next access. A cancelled task's result is never stored, even
if its tool finishes later.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

IDENTIFIER = "io.opentine/tasks"
#: Tasks are a 2025-11-25 feature; on another version ``task`` is ignored.
PROTOCOL = "2025-11-25"
DEFAULT_TTL_MS = 300_000
MIN_TTL_MS = 1_000
MAX_TTL_MS = 3_600_000
POLL_INTERVAL_MS = 500
MAX_TASKS = 64
FINAL = ("completed", "failed", "cancelled")
_RUNNING: set[Any] = set()


class TaskError(LookupError):
    """No such task, or a request the task's state does not allow."""


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class TaskStore:
    def __init__(self, clock: Any = time.time) -> None:
        self._clock = clock
        self._tasks: dict[str, dict[str, Any]] = {}
        self._work: dict[str, Any] = {}

    def attach(self, task_id: str, handle: Any) -> None:
        """The running work of *task_id*: cancelled with the task or when it expires."""
        self._work[task_id] = handle
        handle.add_done_callback(lambda _: self._work.pop(task_id, None))

    def _stop(self, task_id: str) -> None:
        handle = self._work.pop(task_id, None)
        if handle is not None:
            handle.cancel()

    def _expire(self) -> None:
        now = self._clock()
        for task_id in [k for k, t in self._tasks.items() if now > t["expires"]]:
            del self._tasks[task_id]
            self._stop(task_id)  # an expired task's tool does not keep running unseen

    def create(self, ttl: Any = None) -> dict[str, Any]:
        self._expire()
        if len(self._tasks) >= MAX_TASKS:
            done = sorted((t["created"], k) for k, t in self._tasks.items() if t["status"] in FINAL)
            if not done:
                raise TaskError(f"at most {MAX_TASKS} tasks may be working at once")
            del self._tasks[done[0][1]]
        wanted = ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else DEFAULT_TTL_MS
        ttl_ms = max(MIN_TTL_MS, min(MAX_TTL_MS, wanted))
        now = self._clock()
        task_id = secrets.token_hex(16)
        self._tasks[task_id] = {"status": "working", "created": now, "updated": now,
                                "ttl": ttl_ms, "expires": now + ttl_ms / 1000,
                                "message": None, "result": None, "error": None}  # fmt: skip
        return self.wire(task_id)

    def _get(self, task_id: Any) -> dict[str, Any]:
        self._expire()
        task = self._tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            raise TaskError("no such task")
        return task

    def wire(self, task_id: str) -> dict[str, Any]:
        task = self._get(task_id)
        out = {"taskId": task_id, "status": task["status"], "createdAt": _iso(task["created"]),
               "lastUpdatedAt": _iso(task["updated"]), "ttl": task["ttl"],
               "pollInterval": POLL_INTERVAL_MS}  # fmt: skip
        if task["message"]:
            out["statusMessage"] = task["message"]
        return out

    def _move(self, task_id: str, status: str, **fields: Any) -> None:
        task = self._tasks.get(task_id)
        if task is None or task["status"] in FINAL:
            return  # a cancelled task keeps no late result
        task.update(status=status, updated=self._clock(), **fields)

    def complete(self, task_id: str, result: dict[str, Any]) -> None:
        self._move(task_id, "completed", result=result)

    def fail(self, task_id: str, message: str) -> None:
        self._move(task_id, "failed", error=message, message=message)

    def cancel(self, task_id: str) -> dict[str, Any]:
        if self._get(task_id)["status"] in FINAL:
            raise TaskError("the task has already finished")
        self._move(task_id, "cancelled", message="cancelled by the client")
        self._stop(task_id)  # the tool stops too: a cancelled write must not land later
        return self.wire(task_id)

    def result(self, task_id: str) -> dict[str, Any]:
        task = self._get(task_id)
        if task["status"] == "completed":
            return task["result"]
        if task["status"] == "failed":
            return {"content": [{"type": "text", "text": task["error"]}], "isError": True}
        raise TaskError(f"the task is {task['status']}, not completed")

    def list(self) -> list[dict[str, Any]]:
        self._expire()
        order = sorted(self._tasks, key=lambda k: self._tasks[k]["created"])
        return [self.wire(task_id) for task_id in order]


def _dump(result: Any) -> dict[str, Any]:
    if hasattr(result, "model_dump"):
        return result.model_dump(by_alias=True, exclude_none=True, mode="json")
    return dict(result or {})


def extension(store: TaskStore | None = None) -> Any:
    """The ``tasks/*`` extension for SDK 2.x's ``MCPServer``; ``None`` without one."""
    try:
        from mcp.server.extension import Extension, MethodBinding
        from mcp_types._types import RequestParams
    except ImportError:
        return None
    tasks = store or TaskStore()

    class TaskParams(RequestParams):
        taskId: str  # noqa: N815 - the wire name

    class ListParams(RequestParams):
        cursor: str | None = None

    async def get(ctx: Any, params: Any) -> dict[str, Any]:
        return tasks.wire(params.taskId)

    async def result(ctx: Any, params: Any) -> dict[str, Any]:
        return tasks.result(params.taskId)

    async def cancel(ctx: Any, params: Any) -> dict[str, Any]:
        return tasks.cancel(params.taskId)

    async def listing(ctx: Any, params: Any) -> dict[str, Any]:
        return {"tasks": tasks.list()}

    class Tasks(Extension):
        identifier = IDENTIFIER

        def settings(self) -> dict[str, Any]:
            return {"requests": {"tools": {"call": {}}}, "list": {}, "cancel": {}}

        def methods(self) -> Any:
            return (MethodBinding("tasks/get", TaskParams, get),
                    MethodBinding("tasks/result", TaskParams, result),
                    MethodBinding("tasks/cancel", TaskParams, cancel),
                    MethodBinding("tasks/list", ListParams, listing))  # fmt: skip

    Tasks.tasks = tasks  # type: ignore[attr-defined]
    return Tasks()


class TaskMiddleware:
    """Server middleware: a 2025-11-25 ``tools/call`` with ``task`` becomes a task.

    It runs above the runner's result check, which knows ``tools/call`` only as
    a ``CallToolResult``: a middleware that answers by itself owns its result.
    """

    def __init__(self, tasks: TaskStore) -> None:
        self.tasks = tasks

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        params = ctx.params if isinstance(ctx.params, dict) else {}
        meta = params.get("task")
        if ctx.method != "tools/call" or ctx.protocol_version != PROTOCOL or meta is None:
            return await call_next(ctx)
        task = self.tasks.create(meta.get("ttl") if isinstance(meta, dict) else None)
        inner = replace(ctx, params={k: v for k, v in params.items() if k != "task"})

        async def work() -> None:
            try:
                self.tasks.complete(task["taskId"], _dump(await call_next(inner)))
            except Exception as exc:  # noqa: BLE001 - reported as the task's failure
                # The type only: a protocol error's text can echo arguments or paths,
                # which the tool-level sanitizer never saw.
                self.tasks.fail(task["taskId"], f"the tool call failed ({type(exc).__name__})")

        running = asyncio.get_running_loop().create_task(work())
        _RUNNING.add(running)  # held until done, so the loop cannot drop it
        running.add_done_callback(_RUNNING.discard)
        self.tasks.attach(task["taskId"], running)
        return {"task": task}


def construct(server_class: Any, name: str) -> Any:
    """``server_class(name)`` with tasks where the class takes extensions (SDK 2.x)."""
    store = TaskStore()
    found = extension(store)
    if found is not None:
        try:
            server = server_class(name, extensions=[found])
        except TypeError:
            return server_class(name)  # SDK 1.x FastMCP (or a test double): no tasks
        server.middleware.append(TaskMiddleware(store))
        return server
    return server_class(name)


__all__ = ["IDENTIFIER", "TaskError", "TaskMiddleware", "TaskStore", "construct", "extension"]
