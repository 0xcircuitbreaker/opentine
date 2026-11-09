"""Minimal WSGI HTTP transport for the OpenTine remote protocol."""

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from opentine.kernel import OBJECT_TYPES, validate_json_shape
from opentine.remote._app_uploads import UploadRoutes
from opentine.remote._auth_throttle import AuthThrottle, internal_error
from opentine.remote._events_http import extra_routes
from opentine.remote._hosted_http import share_route
from opentine.remote._quota import QuotaExceeded
from opentine.remote._ref_txn import route as ref_txn_route
from opentine.remote._request_audit import AuthorizationDenied, FailureAudit, request_action
from opentine.remote._uploads import UploadRegistry
from opentine.remote._wsgi import json_response, request_headers, response
from opentine.remote.interfaces import KeyProvider
from opentine.remote.service import RemoteService
from opentine.repository import _pack4, _pack_peer
from opentine.repository.pack import MAX_PACK_BYTES, OMITTED_HEADER


class ServerBusy(RuntimeError):
    """Every slot for a heavy walk or install stayed busy past ``guard_wait_seconds``."""


#: Status and body per refusal, most specific first; anything else is a 500.
_REFUSALS = (
    (json.JSONDecodeError, "400 Bad Request", "invalid JSON"),
    (ServerBusy, "503 Service Unavailable", "server is busy"),
    (QuotaExceeded, "429 Too Many Requests", "quota exceeded"),
    (PermissionError, "403 Forbidden", "forbidden"),
    (KeyError, "404 Not Found", "not found"),
    (ValueError, "400 Bad Request", "invalid request"),
)


class RemoteApp(UploadRoutes):
    #: How long a request waits for a walk or install slot before ``503``.
    guard_wait_seconds = 30.0
    _json_response = staticmethod(json_response)
    _response = staticmethod(response)
    _headers = staticmethod(request_headers)

    def __init__(
        self,
        service: RemoteService,
        state_dir: str | Path,
        *,
        max_request_bytes: int = 16 * 1024 * 1024,
        max_upload_bytes: int = MAX_PACK_BYTES,
        upload_ttl_seconds: float = 24 * 60 * 60,
        max_pending_uploads: int = 1024,
        staging_keys: KeyProvider | None = None,
    ):
        self.service = service
        self.state = Path(state_dir).resolve()
        self.uploads = self.state / "uploads"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self.max_request_bytes = max_request_bytes
        self.max_upload_bytes = min(max_upload_bytes, MAX_PACK_BYTES)
        if self.max_request_bytes < 1 or self.max_upload_bytes < 1:
            raise ValueError("request and upload limits must be positive")
        keys = staging_keys or getattr(service.objects, "keys", None)
        self._uploads = UploadRegistry(
            self.uploads,
            keys,
            ttl_seconds=upload_ttl_seconds,
            max_pending=max_pending_uploads,
            max_bytes=self.max_upload_bytes,
        )
        self._install_guard = threading.BoundedSemaphore(2)
        # Negotiation walks a pack's worth of objects, like a fetch: guard it too.
        self._walk_guard = threading.BoundedSemaphore(2)
        self._failures = FailureAudit(getattr(service, "audit", None))
        self.auth_throttle = AuthThrottle()

    @contextmanager
    def _guarded(self, guard: threading.BoundedSemaphore):
        if not guard.acquire(timeout=self.guard_wait_seconds):
            raise ServerBusy("no free slot")
        try:
            yield
        finally:
            guard.release()

    def _body(self, environ: dict[str, Any]) -> bytes:
        raw_length = environ.get("CONTENT_LENGTH") or "0"
        length = int(raw_length)
        if length < 0 or length > self.max_request_bytes:
            raise ValueError("request body is too large")
        body = environ["wsgi.input"].read(length)
        if len(body) != length:
            raise ValueError("request body ended before Content-Length")
        return body

    def _json(self, environ: dict[str, Any], *allowed: str) -> dict[str, Any]:
        raw = self._body(environ) or b"{}"
        try:
            validate_json_shape(raw, max_tokens=100_000)
            data = json.loads(raw)
        except (ValueError, RecursionError, UnicodeDecodeError) as exc:
            raise ValueError("invalid request JSON") from exc
        if not isinstance(data, dict) or set(data) - set(allowed):
            raise ValueError("request JSON must be an object")
        return data

    def __call__(self, environ: dict[str, Any], start_response):
        identity = None
        tenant = resource = ""
        method = environ.get("REQUEST_METHOD", "GET").upper()
        try:
            path = environ.get("PATH_INFO", "/").rstrip("/") or "/"
            if path.startswith("/v1/share/"):  # 0.46: public share links, no bearer
                return share_route(self, path[10:], method, environ, start_response)
            if method == "GET" and path == "/v1/capabilities":
                return self._json_response(start_response, "200 OK", self.service.capabilities())
            prefix = "/v1/tenants/"
            remainder = path[len(prefix) :] if path.startswith(prefix) else ""
            tenant, separator, resource = remainder.partition("/")
            client = environ.get("REMOTE_ADDR") or "unknown"
            wait = self.auth_throttle.retry_after(client)
            if wait:
                return self._json_response(
                    start_response,
                    "429 Too Many Requests",
                    {"error": "too many failed authentications"},
                    [("Retry-After", str(wait))],
                )
            try:
                identity = self.service.authenticate(self._headers(environ))
            except PermissionError as exc:
                self.auth_throttle.failed(client)
                self._failures.unauthenticated(tenant, type(exc).__name__)
                denied = {"error": "authentication failed"}
                return self._json_response(start_response, "401 Unauthorized", denied)
            self.auth_throttle.succeeded(client)
            if not path.startswith(prefix):
                return self._json_response(start_response, "404 Not Found", {"error": "not found"})
            if not separator:
                raise ValueError("missing tenant resource")
            return self._dispatch(identity, tenant, resource, method, environ, start_response)
        except Exception as exc:
            if identity is not None and not isinstance(exc, AuthorizationDenied):
                action = request_action(resource, method)
                self._failures.failed(identity, tenant, action, exc)
            for kind, status, message in _REFUSALS:
                if isinstance(exc, kind):
                    extra = getattr(exc, "headers", ()) if kind is QuotaExceeded else ()
                    return self._json_response(start_response, status, {"error": message}, extra)
            body = internal_error(exc)
            return self._json_response(start_response, "500 Internal Server Error", body)

    def _dispatch(self, identity, tenant, resource, method, environ, start_response):
        if resource == "refs" and method == "GET":
            return self._json_response(
                start_response, "200 OK", {"refs": self.service.list_refs(identity, tenant)}
            )
        if resource.startswith("refs/") and method == "PUT":
            name = unquote(resource[5:])
            request = self._json(environ, "expected_old", "force", "new")
            changed = self.service.update_ref(
                identity,
                tenant,
                name,
                request["new"],
                request.get("expected_old"),
                force=request.get("force") is True,
            )
            status = "200 OK" if changed else "409 Conflict"
            return self._json_response(start_response, status, {"updated": changed})
        if resource == "ref-txn" and method == "POST":  # 0.43, all-or-nothing (_ref_txn)
            return ref_txn_route(self, identity, tenant, environ, start_response)
        if resource == "negotiate" and method == "POST":
            request = self._json(environ, "depth", "haves", "wants")
            with self._guarded(self._walk_guard):
                missing = self.service.negotiate(
                    identity,
                    tenant,
                    request.get("wants") or [],
                    request.get("haves") or [],
                    depth=request.get("depth"),
                )
            return self._json_response(start_response, "200 OK", {"missing": missing})
        if resource == "fetch" and method == "POST":
            request = self._json(
                environ,
                "depth",
                "haves",
                "object_types",
                "pack_codecs",
                "pack_formats",
                _pack_peer.PEER_VERSION,
                "tips",
                "wants",
            )
            raw_types = request.get("object_types") or []
            if not isinstance(raw_types, list) or not all(
                isinstance(item, str) and item in OBJECT_TYPES for item in raw_types
            ):
                raise ValueError("invalid object type filter")
            omitted: list[str] = []
            with self._guarded(self._install_guard):
                data = self.service.fetch_pack(
                    identity,
                    tenant,
                    request.get("wants") or [],
                    request.get("haves") or [],
                    depth=request.get("depth"),
                    object_types=set(raw_types) or None,
                    omitted=omitted,
                    tips=request.get("tips"),
                )
                # Only a client that asked for v4 or v5 gets it (``_pack_peer``).
                fmt, codec = _pack_peer.choose(
                    request.get("pack_formats"), request.get("pack_codecs")
                )
                peer = request.get(_pack_peer.PEER_VERSION)
                data = _pack_peer.convert(data, fmt, codec, peer_version=peer)
            # Additive: newer clients report runs whose associations did not fit.
            headers = [(OMITTED_HEADER, str(len(omitted)))] if omitted else []
            headers.append((_pack4.FORMAT_HEADER, fmt))
            pack_type = "application/vnd.opentine.pack"
            return self._response(start_response, "200 OK", data, pack_type, headers)
        if resource == "packs" and method == "POST":
            content_type = self._headers(environ).get("content-type", "")
            if content_type.startswith("application/vnd.opentine.pack"):
                self.service._authorize(identity, "upload", tenant)
                data = self._body(environ)  # off the guard: a slow body must not hold it
                with self._guarded(self._install_guard):
                    pack_id, count = self.service.install_pack(identity, tenant, data)
                body = {"objects": count, "pack_id": pack_id}
                return self._json_response(start_response, "201 Created", body)
            return self._start_upload(
                identity, tenant, self._json(environ, "sha256", "size"), start_response
            )
        if resource.startswith("packs/") and method in {"HEAD", "PATCH"}:
            upload_id = resource[6:]
            return self._upload(identity, tenant, upload_id, method, environ, start_response)
        if resource == "search" and method == "POST":
            cut: list[bool] = []
            query = self._json(environ, "text", "type")
            results = self.service.search(identity, tenant, query, truncated=cut)
            body = {"objects": results, "truncated": bool(cut)}
            return self._json_response(start_response, "200 OK", body)
        # audit/verify, transparency/*, events (SSE), webhooks: ``_events_http``
        return extra_routes(self, identity, tenant, resource, method, environ, start_response)
