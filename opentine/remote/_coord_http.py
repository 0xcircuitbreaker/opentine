"""``caps.coord`` (0.47): ``opentine-coord/1`` tasks and leases over HTTP.

The same compare-and-swap rules as a local repository (:mod:`opentine.coord._tasks`),
run by ``tine serve`` against the tenant's own refs, so every task version is an
annotation under ``coord/tasks/<id>`` and every move is an ``update_ref`` row of
the audit chain. Under ``/v1/tenants/<t>/``:

* ``GET coord/tasks`` (``read_ref``): ``{"tasks": [...]}``.
* ``POST coord/tasks`` (``update_ref``) ``{task, title}``: ``201 {"task": ...}``.
* ``GET coord/tasks/<id>`` (``read_ref``): ``{"task": ...}``.
* ``POST coord/tasks/<id>/claim|heartbeat|done`` (``update_ref``) ``{holder,
  fencing, ttl}``: ``200 {"task": ...}``, or ``409 {"error", "code"}`` with the
  lease code (``exists``, ``held``, ``done``, ``stale``, ``contended``).

Leases run on the server's clock, never the client's. A task the caller may
not read, a missing task and another tenant's task all answer the same ``404
{"error": "not found"}``; a reader who may not write gets ``403``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from opentine.coord import FORMAT
from opentine.coord import _tasks as tasks
from opentine.kernel import ObjectEnvelope
from opentine.remote import _hosted_reads as reads
from opentine.repository._ref_retry import RefCasMismatch

NOT_FOUND = {"error": "not found"}
ACTIONS = ("claim", "heartbeat", "done")
PREFIX = "coord/tasks"


def capabilities(service: Any) -> dict[str, Any]:
    if not callable(getattr(service.index, "read_ref", None)):
        return {}
    return {"coord": {"path": PREFIX, "format": FORMAT, "actions": ["add", *ACTIONS],
                      "clock": "server"}}  # fmt: skip


class CoordRepo:
    """The slice of :class:`opentine.repository.Repo` the task functions use, on one tenant."""

    def __init__(self, service: Any, identity: Any, tenant: str):
        self.service, self.identity, self.tenant = service, identity, tenant

    def read_ref(self, name: str) -> str | None:
        return self.service.index.read_ref(self.tenant, name)

    def get(self, oid: str) -> ObjectEnvelope:
        return ObjectEnvelope.decode(self.service.objects.get(self.tenant, oid), oid)

    def put(self, object_type: str, payload: Any, schema: int = 1) -> str:
        envelope = ObjectEnvelope.create(object_type, payload, schema)
        raw = envelope.encode()
        if not self.service.objects.has(self.tenant, envelope.oid):
            self.service.objects.put(self.tenant, envelope.oid, raw)
            self.service.index.record_object(self.tenant, envelope.oid, len(raw), None)
        return envelope.oid

    def update_ref(self, name: str, oid: str, *, expected_old=None, actor: str = "") -> None:
        if not self.service.index.update_ref(self.tenant, name, oid, expected_old):
            raise RefCasMismatch(f"{name} moved")
        details = {"expected_old": expected_old, "name": name, "new": oid}
        self.service._audit(self.identity, self.tenant, "update_ref", "ok", details)

    def list_refs(self) -> dict[str, str]:
        return self.service.index.list_refs(self.tenant)


def _writable(service: Any, identity, tenant: str) -> None:
    try:
        service._authorize(identity, "update_ref", tenant)
    except PermissionError:
        reads.readable(service, identity, tenant, "read_ref")  # the uniform 404 first
        raise


def _write(app: Any, repo: CoordRepo, task: str | None, action: str, environ) -> tuple:
    if action == "add":
        request = app._json(environ, "task", "title")
        value = tasks.add(repo, str(request.get("task")), str(request.get("title") or ""))
        return "201 Created", value
    request = app._json(environ, "fencing", "holder", "ttl")
    holder, ttl = request.get("holder"), request.get("ttl", 60)
    if not isinstance(ttl, int | float) or isinstance(ttl, bool):
        raise ValueError("ttl is a number of seconds")
    tasks.get(repo, task)  # a missing task is the uniform 404, not a lease code
    if action == "claim":
        return "200 OK", tasks.claim(repo, task, holder, float(ttl))
    fencing = request.get("fencing")
    if not isinstance(fencing, int) or isinstance(fencing, bool):
        raise ValueError("fencing is the integer token claim returned")
    if action == "heartbeat":
        return "200 OK", tasks.heartbeat(repo, task, holder, fencing, float(ttl))
    return "200 OK", tasks.done(repo, task, holder, fencing)


def _target(resource: str) -> tuple[str | None, str | None]:
    """``(task, action)`` of a ``coord/tasks...`` resource; action ``None`` is a read."""
    rest = resource[len(PREFIX) :].lstrip("/")
    if not rest:
        return None, None
    parts = [unquote(part) for part in rest.split("/")]
    if len(parts) == 1:
        return parts[0], None
    if len(parts) == 2 and parts[1] in ACTIONS:
        return parts[0], parts[1]
    raise reads.Hidden("no such route")


def coord_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """The ``caps.coord`` routes, or ``None`` when *resource* is not one of them."""
    service = app.service
    if not (resource == PREFIX or resource.startswith(PREFIX + "/")) or not capabilities(service):
        return None
    repo, task = CoordRepo(service, identity, tenant), None
    try:
        task, action = _target(resource)
        if task is not None:
            tasks.ref_name(task)
        if method == "GET" and action is None:
            reads.readable(service, identity, tenant, "read_ref")
            if task is None:
                return app._json_response(sr, "200 OK", {"tasks": tasks.list_tasks(repo)})
            return app._json_response(sr, "200 OK", {"task": tasks.get(repo, task)})
        if method != "POST" or (task is None) != (action is None):
            raise reads.Hidden("no such route")
        _writable(service, identity, tenant)
        status, value = _write(app, repo, task, action or "add", environ)
        return app._json_response(sr, status, {"task": value})
    except reads.Hidden:
        return app._json_response(sr, "404 Not Found", NOT_FOUND)
    except tasks.LeaseError as exc:
        if exc.code == "missing":
            return app._json_response(sr, "404 Not Found", NOT_FOUND)
        return app._json_response(sr, "409 Conflict", {"error": str(exc), "code": exc.code})
    except ValueError as exc:
        if task is not None and "invalid task id" in str(exc):
            return app._json_response(sr, "404 Not Found", NOT_FOUND)
        return app._json_response(sr, "400 Bad Request", {"error": str(exc)})


__all__ = ["ACTIONS", "CoordRepo", "capabilities", "coord_routes"]
