"""Hosted-beta HTTP routes (0.46) and their ``/v1/capabilities`` entries.

Tenant routes (bearer auth, per-tenant authz on every read):

* ``GET objects/<oid>`` (``object_read_http``) -- one stored object, ``private``
  immutable cache headers, ``Vary: Authorization``; ``If-None-Match`` gives 304.
* ``POST runs/<oid>/closure`` (``run_closure``) -- the run's objects in one pack
  negotiated like ``fetch`` (``haves``, ``pack_formats``); ``lazy_blobs`` leaves
  blobs out (``OpenTine-Lazy-Blobs`` counts them) for per-blob ``objects/`` reads.
* ``GET list/runs``, ``GET list/refs`` (``list``) -- cursor-paginated.
* ``GET log/entries`` (``log_http``) -- this tenant's transparency-log entries.
* ``GET|POST shares``, ``DELETE shares/<id>`` (``share``) and ``GET admin/stats`` (``admin``).

Public share routes, no bearer: ``GET /v1/share/<token>``,
``POST /v1/share/<token>/closure`` and ``GET /v1/share/<token>/objects/<oid>``.
An unknown, expired or revoked token and an oid outside the shared run all get
the same 404; failures count against the client like failed logins (429).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, unquote

from opentine.remote import _hosted_reads as reads
from opentine.remote._auth_throttle import AuthThrottle
from opentine.repository import _pack4, _pack_peer

NOT_FOUND = {"error": "not found"}
PACK_TYPE = "application/vnd.opentine.pack"
OBJECT_TYPE = "application/vnd.opentine.object"
LAZY_HEADER = "OpenTine-Lazy-Blobs"
_NO_REFERRER = [("Referrer-Policy", "no-referrer")]
_CLOSURE_KEYS = ("depth", "haves", "lazy_blobs", "pack_codecs", "pack_formats")


def capabilities(service: Any) -> dict[str, Any]:
    caps: dict[str, Any] = {
        "object_read_http": {"path": "objects/{oid}", "cache": "private-immutable"},
        "run_closure": {"path": "runs/{oid}/closure", "lazy_blobs": True},
        "list": {"paths": ["list/runs", "list/refs"], "max_page": reads.MAX_PAGE},
        "search": {"path": "search", "filters": ["type", "text"]},
        "log_http": {"read": True, "path": "log/entries"},
        "admin": {"paths": ["admin/stats"]},
    }
    if getattr(service, "shares", None) is not None:
        from opentine.remote._shares import MAX_TTL, SCOPES

        caps["share"] = {"path": "shares", "public": "/v1/share/{token}", "max_ttl": MAX_TTL,
                         "scopes": list(SCOPES)}  # fmt: skip
    return caps


def _query(environ) -> dict[str, str]:
    raw = str(environ.get("QUERY_STRING", ""))
    if len(raw) > 4096:
        raise ValueError("query string is too long")
    return {key: values[-1] for key, values in parse_qs(raw).items()}


def _object(app, environ, sr, data: bytes, oid: str):
    etag = f'"{oid}"'
    headers = [("ETag", etag), *reads.OBJECT_CACHE]
    if app._headers(environ).get("if-none-match") == etag:
        sr("304 Not Modified", headers)
        return [b""]
    return _send(sr, "200 OK", data, OBJECT_TYPE, headers)


def _send(sr, status: str, body: bytes, content_type: str, headers):
    names = {name.lower() for name, _ in headers}
    cache = [] if "cache-control" in names else [("Cache-Control", "no-store")]
    sr(status, [("Content-Length", str(len(body))), ("Content-Type", content_type),
                *cache, *headers])  # fmt: skip
    return [body]


def _pack(app, environ, sr, service, tenant: str, run: str, within=None):
    request = app._json(environ, *_CLOSURE_KEYS, _pack_peer.PEER_VERSION)
    if within is not None:  # a share's haves count only inside its run: no tenant oracle
        haves = request.get("haves") or []
        request["haves"] = [h for h in haves if isinstance(h, str) and h in within]
    with app._guarded(app._install_guard):
        data, lazy = reads.run_pack(service, tenant, run, request)
        fmt, codec = _pack_peer.choose(request.get("pack_formats"), request.get("pack_codecs"))
        peer = request.get(_pack_peer.PEER_VERSION)
        data = _pack_peer.convert(data, fmt, codec, peer_version=peer)
    headers = [(_pack4.FORMAT_HEADER, fmt), (LAZY_HEADER, str(lazy))]
    return _send(sr, "200 OK", data, PACK_TYPE, headers)


def tenant_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """The hosted routes, or ``None`` when *resource* is not one of them."""
    service = app.service
    try:
        if resource.startswith("objects/") and method in ("GET", "HEAD"):
            reads.readable(service, identity, tenant)
            oid = unquote(resource[8:])
            return _object(app, environ, sr, reads.object_bytes(service, tenant, oid), oid)
        if resource.startswith("runs/") and resource.endswith("/closure") and method == "POST":
            reads.readable(service, identity, tenant)
            return _pack(app, environ, sr, service, tenant, unquote(resource[5:-8]))
        if resource in ("list/runs", "list/refs") and method == "GET":
            reads.readable(service, identity, tenant, "read_ref")
            lister = reads.list_runs if resource == "list/runs" else reads.list_refs
            return app._json_response(sr, "200 OK", lister(service, tenant, _query(environ)))
        if resource == "log/entries" and method == "GET":
            reads.readable(service, identity, tenant, "read_ref")
            body = reads.log_entries(service, tenant, _query(environ))
            if body is None:
                raise reads.Hidden("no log")
            return app._json_response(sr, "200 OK", body)
        if resource == "admin/stats" and method == "GET":
            reads.readable(service, identity, tenant, "admin")
            return app._json_response(sr, "200 OK", reads.admin_stats(service, tenant))
        if resource == "shares" or resource.startswith("shares/"):
            return _share_admin(app, identity, tenant, resource, method, environ, sr)
    except reads.Hidden:
        return app._json_response(sr, "404 Not Found", NOT_FOUND)
    return None


def _share_admin(app, identity, tenant: str, resource: str, method: str, environ, sr):
    service = app.service
    shares = getattr(service, "shares", None)
    if shares is None:
        raise reads.Hidden("no shares")
    reads.readable(service, identity, tenant, "share")
    if resource == "shares" and method == "GET":
        run = _query(environ).get("run")
        return app._json_response(sr, "200 OK", {"shares": shares.list(tenant, run)})
    if resource == "shares" and method == "POST":
        request = app._json(environ, "run", "scope", "ttl")
        run = str(request.get("run") or "")
        if not reads.checked_oid(run).startswith("run:") or not service.objects.has(tenant, run):
            raise reads.Hidden("no such run")
        token, row = shares.create(
            tenant, run, identity.subject, ttl=request.get("ttl", 7 * 86400),
            scope=request.get("scope", "read"),
        )  # fmt: skip
        service._audit(identity, tenant, "share", "ok", {"created": row["id"], "run": run})
        return app._json_response(sr, "201 Created", {**row, "token": token})
    if resource.startswith("shares/") and method == "DELETE":
        share_id = unquote(resource[7:])
        try:
            row = shares.revoke(tenant, share_id)
        except KeyError as exc:
            raise reads.Hidden("no such share") from exc
        service._audit(identity, tenant, "share", "ok", {"revoked": share_id})
        return app._json_response(sr, "200 OK", row)
    raise reads.Hidden("no such route")


def share_route(app: Any, rest: str, method: str, environ, sr):
    """``/v1/share/<token>[/closure|/objects/<oid>]``: no bearer, uniform 404, throttled."""
    service = app.service

    def sr(status, headers, *rest, _sr=sr):  # every share answer: never leak the URL onward
        if not any(name.lower() == "referrer-policy" for name, _ in headers):
            headers = [*headers, *_NO_REFERRER]
        return _sr(status, headers, *rest)

    throttle = app.__dict__.setdefault("share_throttle", AuthThrottle())
    cache = app.__dict__.setdefault("share_closures", reads.ClosureCache())
    client = environ.get("REMOTE_ADDR") or "unknown"
    wait = throttle.retry_after(client)
    if wait:
        body = {"error": "too many failed share lookups"}
        return app._json_response(sr, "429 Too Many Requests", body, [("Retry-After", str(wait))])
    token, _, tail = rest.partition("/")
    shares = getattr(service, "shares", None)
    record = shares.resolve(token) if shares is not None else None
    try:
        if record is None:
            raise reads.Hidden("no share")
        tenant, run = record["tenant"], record["run"]
        if not tail and method == "GET":
            body = {"expires": record["expires"], "run": run, "scope": record["scope"]}
            result = app._json_response(sr, "200 OK", body)
        elif tail == "closure" and method == "POST":
            members = cache.members(service, tenant, run)
            result = _pack(app, environ, sr, service, tenant, run, members)
        elif tail.startswith("objects/") and method in ("GET", "HEAD"):
            oid = unquote(tail[8:])
            if oid not in cache.members(service, tenant, run):
                raise reads.Hidden("outside the share")
            result = _object(app, environ, sr, reads.object_bytes(service, tenant, oid), oid)
        else:
            raise reads.Hidden("no such route")
    except reads.Hidden:
        throttle.failed(client)
        return app._json_response(sr, "404 Not Found", NOT_FOUND)
    # No ``succeeded()``: a holder of one live token must not be able to reset
    # its failure count between guesses at other tokens or other oids.
    return result


__all__ = ["LAZY_HEADER", "capabilities", "share_route", "tenant_routes"]
