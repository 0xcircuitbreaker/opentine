"""Minimal WSGI HTTP transport for the OpenTine remote protocol."""

import hashlib
import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from opentine.kernel import OBJECT_TYPES, validate_json_shape
from opentine.remote._uploads import TerminalUploadError, UploadRegistry
from opentine.remote._wsgi import json_response, response
from opentine.remote.interfaces import KeyProvider
from opentine.remote.service import RemoteService
from opentine.repository.pack import MAX_PACK_BYTES


class RemoteApp:
    _json_response = staticmethod(json_response)
    _response = staticmethod(response)

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

    @staticmethod
    def _headers(environ: dict[str, Any]) -> dict[str, str]:
        headers = {
            key[5:].replace("_", "-").lower(): str(value)
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }
        if environ.get("CONTENT_TYPE"):
            headers["content-type"] = environ["CONTENT_TYPE"]
        return headers

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
        try:
            method = environ.get("REQUEST_METHOD", "GET").upper()
            path = environ.get("PATH_INFO", "/").rstrip("/") or "/"
            if method == "GET" and path == "/v1/capabilities":
                return self._json_response(start_response, "200 OK", self.service.capabilities())
            try:
                identity = self.service.authenticate(self._headers(environ))
            except PermissionError:
                return self._json_response(
                    start_response, "401 Unauthorized", {"error": "authentication failed"}
                )
            prefix = "/v1/tenants/"
            if not path.startswith(prefix):
                return self._json_response(start_response, "404 Not Found", {"error": "not found"})
            remainder = path[len(prefix) :]
            tenant, separator, resource = remainder.partition("/")
            if not separator:
                raise ValueError("missing tenant resource")
            return self._dispatch(identity, tenant, resource, method, environ, start_response)
        except json.JSONDecodeError:
            return self._json_response(start_response, "400 Bad Request", {"error": "invalid JSON"})
        except PermissionError:
            return self._json_response(start_response, "403 Forbidden", {"error": "forbidden"})
        except KeyError:
            return self._json_response(start_response, "404 Not Found", {"error": "not found"})
        except ValueError:
            return self._json_response(
                start_response, "400 Bad Request", {"error": "invalid request"}
            )
        except Exception as exc:
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
            with self._install_guard:
                data = self.service.fetch_pack(
                    identity,
                    tenant,
                    request.get("wants") or [],
                    request.get("haves") or [],
                    depth=request.get("depth"),
                    object_types=set(raw_types) or None,
                )
            return self._response(start_response, "200 OK", data, "application/vnd.opentine.pack")
        if resource == "packs" and method == "POST":
            content_type = self._headers(environ).get("content-type", "")
            if content_type.startswith("application/vnd.opentine.pack"):
                self.service._authorize(identity, "upload", tenant)
                with self._install_guard:
                    pack_id, count = self.service.install_pack(
                        identity, tenant, self._body(environ)
                    )
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
            results = self.service.search(identity, tenant, self._json(environ, "type"))
            return self._json_response(start_response, "200 OK", {"objects": results})
        if resource == "audit/verify" and method == "GET":
            result = self.service.verify_audit_chain(identity, tenant)
            return self._json_response(start_response, "200 OK", result)
        return self._json_response(start_response, "404 Not Found", {"error": "not found"})

    def _start_upload(self, identity, tenant, request, start_response):
        self.service._authorize(identity, "upload", tenant)
        size = request.get("size")
        digest = str(request["sha256"])
        valid_size = type(size) is int and 0 < size <= self.max_upload_bytes
        if not valid_size or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid resumable upload declaration")
        upload_id = uuid.uuid4().hex
        paths = self._uploads.create(tenant, upload_id, {"sha256": digest, "size": size})
        try:
            self.service.admission.admit(
                identity,
                "upload",
                {"bytes": size, "objects": 0, "phase": "declaration", "tenant": tenant},
            )
        except Exception:
            self._uploads.cleanup(paths)
            raise
        return self._json_response(
            start_response, "201 Created", {"offset": 0, "upload_id": upload_id}
        )

    def _upload(self, identity, tenant, upload_id, method, environ, start_response):
        self.service._authorize(identity, "upload", tenant)
        with self._uploads.locked(tenant, upload_id) as paths:
            try:
                response, terminal = self._upload_locked(
                    identity, tenant, method, environ, start_response, paths
                )
            except TerminalUploadError:
                self._uploads.cleanup(paths)
                raise
            if terminal:
                self._uploads.cleanup(paths)
            return response

    def _upload_locked(self, identity, tenant, method, environ, start_response, paths):
        try:
            metadata = self._uploads.load(tenant, paths)
        except FileNotFoundError as exc:
            raise KeyError("upload not found") from exc
        offset = metadata["offset"]
        if method == "HEAD":
            headers = (("Upload-Offset", str(offset)),)
            return self._json_response(start_response, "200 OK", {"offset": offset}, headers), False
        expected_offset = int(self._headers(environ).get("upload-offset", "-1"))
        if expected_offset != offset:
            return self._json_response(start_response, "409 Conflict", {"offset": offset}), False
        chunk = self._body(environ)
        if offset + len(chunk) > metadata["size"]:
            raise TerminalUploadError("upload exceeds declared size")
        metadata = self._uploads.append(tenant, paths, metadata, chunk)
        offset = metadata["offset"]
        if offset != metadata["size"]:
            return self._json_response(start_response, "200 OK", {"offset": offset}), False
        with self._install_guard:
            data = self._uploads.materialize(tenant, paths, metadata)
            if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                raise TerminalUploadError("resumable upload checksum mismatch")
            try:
                pack_id, count = self.service.install_pack(identity, tenant, data)
            except ValueError as exc:
                # A complete invalid pack cannot be repaired by appending bytes.
                raise TerminalUploadError("completed upload is not a valid pack") from exc
        result = {"objects": count, "offset": offset, "pack_id": pack_id}
        return self._json_response(start_response, "201 Created", result), True
