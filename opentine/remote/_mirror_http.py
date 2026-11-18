"""``project/mirror`` and the refusals of ``project/code/*`` (0.55, ``caps.project.mirror``).

* ``GET project/mirror`` (``read_ref``): the link and last sync.
* ``PUT project/mirror`` (``update_ref``): link the mirror to a slot of the
  current manifest and sync once. A private slot's upstream is given as
  ``{url, salt}`` that open its commitment; a public project over private code
  is refused (``mirror.private-upstream``).
* ``POST project/mirror/sync`` (``update_ref``): the webhook-triggered sync;
  ``429`` with ``Retry-After`` inside ``min_interval_seconds``.
* ``DELETE project/mirror`` (``update_ref``): unlink, deleting the mirror,
  its state and every cache.

The mirror is read-only: git smart HTTP (``info/refs``, ``git-upload-pack``,
``git-receive-pack``), archive downloads, LFS and every non-``GET`` under
``project/code/`` are refused with ``403`` and a ``mirror.*-refused`` code,
after the tenant's read check, so a caller who may not read the tenant still
gets the uniform ``404``. The reads are :mod:`._code_http`.
"""

from __future__ import annotations

from typing import Any

from opentine import _mirror_state
from opentine.remote import _hosted_reads as reads
from opentine.remote import _mirror_store as store

NOT_FOUND = {"error": "not found"}
COMPUTED_BY = "host"
_REFUSED = (
    ("git-receive-pack", "mirror.push-refused", "the mirror is read-only: push is refused"),
    ("info/lfs", "mirror.lfs-refused", "the mirror does not serve LFS"),
    ("archive", "mirror.archive-refused", "the mirror does not serve archive downloads"),
    ("info/refs", "mirror.git-protocol-refused", "the mirror does not speak git smart HTTP"),
    ("git-upload-pack", "mirror.git-protocol-refused", "the mirror does not speak git smart HTTP"),
)


def config(service: Any) -> dict[str, Any] | None:
    if getattr(service.objects, "root", None) is None:
        return None
    return getattr(service, "mirror", None)


def capabilities(service: Any) -> dict[str, Any]:
    """``caps.project.mirror``: the sync spec, or nothing when the mirror is off."""
    cfg = config(service)
    if cfg is None:
        return {}
    return {"mirror": {
        "path": "project/mirror", "code": "project/code",
        "reads": ["refs", "tree", "blob", "raw", "history", "compare", "search"],
        "sync": {"poll_seconds": cfg["poll_seconds"], "webhook": "project/mirror/sync",
                 "min_interval_seconds": cfg["min_interval_seconds"]},
        "limits": {"max_repo_bytes": cfg["max_repo_bytes"], "max_refs": cfg["max_refs"],
                   "max_blob_bytes": cfg["max_blob_bytes"], "max_page": cfg["max_page"]},
        "refuses": ["push", "receive-pack", "upload-pack", "archive", "lfs",
                    "public-project-private-code"],
        "computed_by": COMPUTED_BY, "label": _mirror_state.LABEL,
    }}  # fmt: skip


def label(root, tenant: str) -> dict[str, Any]:
    """What every mirror response carries: upstream, last sync, and who computed it."""
    linked = store.link_of(root, tenant)
    if linked is None:
        raise reads.Hidden("no mirror")
    state = store.state_of(root, tenant) or {}
    return {"upstream": linked["shown"], "slot": linked["slot"],
            "synced_at": state.get("synced_at"), "status": state.get("status", "never-synced"),
            "reasons": state.get("reasons", []), "computed_by": COMPUTED_BY,
            "label": _mirror_state.LABEL}  # fmt: skip


def _status(root, tenant: str) -> dict[str, Any]:
    state = store.state_of(root, tenant)
    linked = store.link_of(root, tenant) or {}
    return {"mirror": label(root, tenant), "manifest": linked.get("manifest"),
            "default_branch": linked.get("default_branch"),
            "refs": len(state["refs"]) if state else 0,
            "state": state}  # fmt: skip


def _refusal(app, sr, code: str, message: str):
    return app._json_response(sr, "403 Forbidden", {"error": message, "code": code})


def _write(app, identity, tenant: str, root, cfg, resource: str, method: str, environ, sr):
    service = app.service
    try:
        service._authorize(identity, "update_ref", tenant)
    except PermissionError:
        reads.readable(service, identity, tenant, "read_ref")
        raise
    limits = getattr(app, "limits", None)
    cap = limits.limit(tenant, "mirror_bytes") if limits is not None else None
    if method == "DELETE":
        gone = store.unlink(root, tenant)
        service._audit(identity, tenant, "mirror", "unlinked", {"existed": gone})
        if not gone:
            raise reads.Hidden("no mirror")
        return app._json_response(sr, "200 OK", {"unlinked": True})
    if method == "PUT":
        request = app._json(environ, "slot", "url", "salt", "private")
        try:
            store.link(root, tenant, request, cfg)
        except store.Refused as exc:
            service._audit(identity, tenant, "mirror", "refused", {"code": exc.code})
            return _refusal(app, sr, exc.code, str(exc))
    try:
        store.sync(root, tenant, cfg, force=method == "PUT", max_bytes=cap)
    except LookupError as exc:
        raise reads.Hidden("no mirror") from exc
    except store.TooSoon as exc:
        retry = [("Retry-After", str(exc.retry_after))]
        body = {"error": "synced too recently", "code": "mirror.too-soon"}
        return app._json_response(sr, "429 Too Many Requests", body, retry)
    service._audit(identity, tenant, "mirror", "synced", {"how": method})
    return app._json_response(sr, "200 OK", _status(root, tenant))


def mirror_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """The mirror and code routes, or ``None`` when the mirror is off or *resource* is not one."""
    cfg = config(app.service)
    if cfg is None or not (resource == "project/mirror/sync" or resource == "project/mirror"
                           or resource.startswith("project/code/")):  # fmt: skip
        return None
    root = app.service.objects.root
    try:
        if resource.startswith("project/code/"):
            reads.readable(app.service, identity, tenant, "read_ref")
            sub = resource[len("project/code/") :]
            for prefix, code, message in _REFUSED:
                if sub == prefix or sub.startswith(prefix + "/"):
                    return _refusal(app, sr, code, message)
            if method != "GET":
                return _refusal(app, sr, "mirror.push-refused", "the mirror is read-only")
            from opentine.remote._code_http import code_read

            return code_read(app, tenant, root, cfg, sub, environ, sr, label(root, tenant))
        if method == "GET" and resource == "project/mirror":
            reads.readable(app.service, identity, tenant, "read_ref")
            return app._json_response(sr, "200 OK", _status(root, tenant))
        if (resource, method) in (("project/mirror", "PUT"), ("project/mirror", "DELETE"),
                                  ("project/mirror/sync", "POST")):  # fmt: skip
            return _write(app, identity, tenant, root, cfg, resource, method, environ, sr)
        return None
    except reads.Hidden:
        return app._json_response(sr, "404 Not Found", NOT_FOUND)


__all__ = ["COMPUTED_BY", "capabilities", "config", "label", "mirror_routes"]
