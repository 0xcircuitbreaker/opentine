"""The remote half of ``tine task`` (0.47, ``caps.coord``).

``tine task ACTION ... --remote NAME|URL`` runs the same operation on a ``tine
serve`` tenant instead of the local repository. :class:`RemoteTasks` has the
call shape of :mod:`opentine.coord._tasks` (``add``, ``claim``, ``heartbeat``,
``done``, ``list_tasks``), so callers and the scale test can drive either one.
A ``409`` becomes :class:`~opentine.coord._tasks.LeaseError` with the server's
code; the uniform ``404`` becomes ``LeaseError("missing")``. A remote without
``caps.coord`` is refused before anything is sent.

Requests go straight through the caller's client (its own timeouts, a bounded
JSON read), not the process-wide request pool of ``_http.request_json``: fifty
workers in one process each hold their own connection.
"""

from __future__ import annotations

import argparse
from typing import Any
from urllib.parse import quote

from opentine._cli_remote_target import resolve, tenant_path
from opentine.coord._tasks import LeaseError, ref_name


class RemoteTasks:
    def __init__(self, http: Any, tenant: str, *, timeout: float = 30.0):
        self.http, self.tenant, self.timeout = http, tenant, timeout
        _, caps = self._send("GET", "/v1/capabilities", None, (200,))
        if not isinstance(caps.get("coord"), dict):
            raise ValueError("the remote does not serve tasks (no caps.coord)")

    def _send(self, method: str, url: str, body: dict | None, allowed: tuple[int, ...]):
        from opentine.repository._http import raise_for_status, read_json

        kwargs = {"json": body} if body is not None else {}
        with self.http.stream(method, url, timeout=self.timeout, **kwargs) as response:
            if response.status_code not in allowed:
                raise_for_status(response)
            return response.status_code, read_json(response, max_seconds=self.timeout)

    def _call(self, method: str, resource: str, body: dict | None = None) -> Any:
        status, reply = self._send(
            method, tenant_path(self.tenant, resource), body, (200, 201, 404, 409)
        )
        if status == 404:
            raise LeaseError("missing", "not found (or not visible to this token)")
        if status == 409:
            raise LeaseError(str(reply.get("code") or "contended"), str(reply.get("error")))
        return reply

    def _task(self, task: str, action: str, body: dict[str, Any]) -> dict[str, Any]:
        ref_name(task)  # the same id rule, checked before anything is sent
        return self._call("POST", f"coord/tasks/{quote(task, safe='')}/{action}", body)["task"]

    def add(self, task: str, title: str = "") -> dict[str, Any]:
        ref_name(task)
        return self._call("POST", "coord/tasks", {"task": task, "title": title})["task"]

    def get(self, task: str) -> dict[str, Any]:
        ref_name(task)
        return self._call("GET", f"coord/tasks/{quote(task, safe='')}")["task"]

    def claim(self, task: str, holder: str, ttl: float = 60.0) -> dict[str, Any]:
        return self._task(task, "claim", {"holder": holder, "ttl": ttl})

    def heartbeat(self, task: str, holder: str, fencing: int, ttl: float = 60.0) -> dict:
        return self._task(task, "heartbeat", {"holder": holder, "fencing": fencing, "ttl": ttl})

    def done(self, task: str, holder: str, fencing: int) -> dict[str, Any]:
        return self._task(task, "done", {"holder": holder, "fencing": fencing})

    def list_tasks(self) -> list[dict[str, Any]]:
        return self._call("GET", "coord/tasks")["tasks"]


def run(args: argparse.Namespace) -> dict | list:
    """One ``tine task`` action against ``--remote``."""
    from contextlib import closing

    from opentine.repository._http import client

    base, tenant, token = resolve(args, args.remote)
    with closing(client(base, token, allow_insecure=args.allow_insecure,
                        timeout=args.timeout)) as http:  # fmt: skip
        remote = RemoteTasks(http, tenant, timeout=args.timeout)
        if args.action == "list":
            return remote.list_tasks()
        if not args.task:
            raise ValueError(f"{args.action} needs a task id")
        if args.action == "add":
            return remote.add(args.task, args.title)
        if not args.holder:
            raise ValueError(f"{args.action} needs --holder")
        if args.action == "claim":
            return remote.claim(args.task, args.holder, args.ttl)
        if args.fencing is None:
            raise ValueError(f"{args.action} needs --fencing (the token claim printed)")
        if args.action == "heartbeat":
            return remote.heartbeat(args.task, args.holder, args.fencing, args.ttl)
        return remote.done(args.task, args.holder, args.fencing)


__all__ = ["RemoteTasks", "run"]
