"""Minimal WSGI HTTP transport for the OpenTine remote protocol."""

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from opentine.kernel import OBJECT_TYPES, validate_json_shape
from opentine.remote._app_uploads import UploadRoutes
from opentine.remote._request_audit import AuthorizationDenied, FailureAudit, request_action
from opentine.remote._uploads import UploadRegistry
from opentine.remote._wsgi import json_response, request_headers, response
from opentine.remote.interfaces import KeyProvider
from opentine.remote.service import RemoteService
from opentine.repository.pack import MAX_PACK_BYTES, OMITTED_HEADER


class ServerBusy(RuntimeError):
    """Every slot for a heavy walk or install stayed busy past ``guard_wait_seconds``."""


#: Status and body per refusal, most specific first; anything else is a 500.
_REFUSALS = (
    (json.JSONDecodeError, "400 Bad Request", "invalid JSON"),
    (ServerBusy, "503 Service Unavailable", "server is busy"),
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
        # Negotiation walks up to a pack's worth of objects, like a fetch, and was
        # unguarded: enough concurrent negotiates could take every worker's CPU.
        self._walk_guard = threading.BoundedSemaphore(2)
        self._failures = FailureAudit(getattr(service, "audit", None))

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
            if method == "GET" and path == "/v1/capabilities":
                return self._json_response(start_response, "200 OK", self.service.capabilities())
            prefix = "/v1/tenants/"
            remainder = path[len(prefix) :] if path.startswith(prefix) else ""
            tenant, separator, resource = remainder.partition("/")
            try:
                identity = self.service.authenticate(self._headers(environ))
            except PermissionError as exc:
                self._failures.unauthenticated(tenant, type(exc).__name__)
                return self._json_response(
                    start_response, "401 Unauthorized", {"error": "authentication failed"}
                )
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
                    return self._json_response(start_response, status, {"error": message})
            return self._json_response(
                start_response, "500 Internal Server Error", {"error": type(exc).__name__}
            )

    def _dispatch(self, identity, tenant, resource, method, environ, start_response):
        if resource == "refs" and method == "GET":
            return self._json_response(
                start_response, "200 OK", {"refs": self.service.list_refs(identity, tenant)}
            )
        if resource.startswith("refs/") and method == "PUT":
            name = unquote(resource[5:])
            request = self._json(environ, "expected_old", "new")
            changed = self.service.update_ref(
                identity, tenant, name, request["new"], request.get("expected_old")
            )
            status = "200 OK" if changed else "409 Conflict"
            return self._json_response(start_response, status, {"updated": changed})
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
            request = self._json(environ, "depth", "haves", "object_types", "wants")
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
                )
            # Additive: older clients ignore it; newer ones report runs whose
            # attestations (or annotations) did not fit in the pack.
            headers = [(OMITTED_HEADER, str(len(omitted)))] if omitted else []
            pack_type = "application/vnd.opentine.pack"
            return self._response(start_response, "200 OK", data, pack_type, headers)
        if resource == "packs" and method == "POST":
            content_type = self._headers(environ).get("content-type", "")
            if content_type.startswith("application/vnd.opentine.pack"):
                self.service._authorize(identity, "upload", tenant)
                data = self._body(environ)  # off the guard: a slow body must not hold it
                with self._guarded(self._install_guard):
                    pack_id, count = self.service.install_pack(identity, tenant, data)
                return self._json_response(
                    start_response, "201 Created", {"objects": count, "pack_id": pack_id}
                )
            return self._start_upload(
                identity, tenant, self._json(environ, "sha256", "size"), start_response
            )
        if resource.startswith("packs/") and method in {"HEAD", "PATCH"}:
            upload_id = resource[6:]
            return self._upload(identity, tenant, upload_id, method, environ, start_response)
        if resource == "search" and method == "POST":
            cut: list[bool] = []
            query = self._json(environ, "type")
            results = self.service.search(identity, tenant, query, truncated=cut)
            body = {"objects": results, "truncated": bool(cut)}
            return self._json_response(start_response, "200 OK", body)
        if resource == "audit/verify" and method == "GET":
            result = self.service.verify_audit_chain(identity, tenant)
            return self._json_response(start_response, "200 OK", result)
        return self._json_response(start_response, "404 Not Found", {"error": "not found"})
