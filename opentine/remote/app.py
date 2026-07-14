"""Minimal WSGI HTTP transport for the OpenTine remote protocol."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from opentine.remote.service import RemoteService
from opentine.repository.pack import MAX_PACK_BYTES


class RemoteApp:
    def __init__(
        self,
        service: RemoteService,
        state_dir: str | Path,
        *,
        max_request_bytes: int = 16 * 1024 * 1024,
        max_upload_bytes: int = MAX_PACK_BYTES,
    ):
        self.service = service
        self.state = Path(state_dir).resolve()
        self.uploads = self.state / "uploads"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self.max_request_bytes = max_request_bytes
        self.max_upload_bytes = min(max_upload_bytes, MAX_PACK_BYTES)
        if self.max_request_bytes < 1 or self.max_upload_bytes < 1:
            raise ValueError("request and upload limits must be positive")
        self._upload_guard = threading.Lock()
        self._upload_locks: dict[str, threading.Lock] = {}
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

    def _json(self, environ: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(self._body(environ) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("request JSON must be an object")
        return data

    @staticmethod
    def _response(start_response, status: str, body: bytes, content_type: str):
        start_response(
            status,
            [
                ("Content-Length", str(len(body))),
                ("Content-Type", content_type),
                ("Cache-Control", "no-store"),
            ],
        )
        return [body]

    def _json_response(self, start_response, status: str, value: Any):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return self._response(start_response, status, body, "application/json")

    def __call__(self, environ: dict[str, Any], start_response):
        try:
            method = environ.get("REQUEST_METHOD", "GET").upper()
            path = environ.get("PATH_INFO", "/").rstrip("/") or "/"
            if method == "GET" and path == "/v1/capabilities":
                return self._json_response(start_response, "200 OK", self.service.capabilities())
            identity = self.service.authenticate(self._headers(environ))
            prefix = "/v1/tenants/"
            if not path.startswith(prefix):
                return self._json_response(start_response, "404 Not Found", {"error": "not found"})
            remainder = path[len(prefix) :]
            tenant, separator, resource = remainder.partition("/")
            if not separator:
                raise ValueError("missing tenant resource")
            return self._dispatch(identity, tenant, resource, method, environ, start_response)
        except json.JSONDecodeError as exc:
            return self._json_response(start_response, "400 Bad Request", {"error": str(exc)})
        except PermissionError as exc:
            return self._json_response(start_response, "403 Forbidden", {"error": str(exc)})
        except KeyError as exc:
            return self._json_response(start_response, "404 Not Found", {"error": str(exc)})
        except ValueError as exc:
            return self._json_response(start_response, "400 Bad Request", {"error": str(exc)})
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
            request = self._json(environ)
            changed = self.service.update_ref(
                identity, tenant, name, request["new"], request.get("expected_old")
            )
            status = "200 OK" if changed else "409 Conflict"
            return self._json_response(start_response, status, {"updated": changed})
        if resource == "negotiate" and method == "POST":
            request = self._json(environ)
            missing = self.service.negotiate(
                identity,
                tenant,
                request.get("wants") or [],
                request.get("haves") or [],
                depth=request.get("depth"),
            )
            return self._json_response(start_response, "200 OK", {"missing": missing})
        if resource == "fetch" and method == "POST":
            request = self._json(environ)
            with self._install_guard:
                data = self.service.fetch_pack(
                    identity,
                    tenant,
                    request.get("wants") or [],
                    request.get("haves") or [],
                    depth=request.get("depth"),
                    object_types=set(request.get("object_types") or []) or None,
                )
            return self._response(start_response, "200 OK", data, "application/vnd.opentine.pack")
        if resource == "packs" and method == "POST":
            content_type = self._headers(environ).get("content-type", "")
            if content_type.startswith("application/vnd.opentine.pack"):
                # Authorize before reading the (potentially large) body into memory.
                self.service._authorize(identity, "upload", tenant)
                with self._install_guard:
                    pack_id, count = self.service.install_pack(
                        identity, tenant, self._body(environ)
                    )
                return self._json_response(
                    start_response, "201 Created", {"objects": count, "pack_id": pack_id}
                )
            return self._start_upload(identity, tenant, self._json(environ), start_response)
        if resource.startswith("packs/") and method in {"HEAD", "PATCH"}:
            upload_id = resource[6:]
            return self._upload(identity, tenant, upload_id, method, environ, start_response)
        if resource == "search" and method == "POST":
            results = self.service.search(identity, tenant, self._json(environ))
            return self._json_response(start_response, "200 OK", {"objects": results})
        return self._json_response(start_response, "404 Not Found", {"error": "not found"})

    def _upload_paths(self, tenant: str, upload_id: str) -> tuple[Path, Path]:
        if not upload_id.isalnum():
            raise ValueError("invalid upload id")
        directory = self.uploads / tenant
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{upload_id}.part", directory / f"{upload_id}.json"

    def _start_upload(self, identity, tenant, request, start_response):
        self.service._authorize(identity, "upload", tenant)
        size = int(request["size"])
        digest = str(request["sha256"])
        if size < 0 or size > self.max_upload_bytes or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid resumable upload declaration")
        self.service.admission.admit(
            identity,
            "upload",
            {"bytes": size, "objects": 0, "phase": "declaration", "tenant": tenant},
        )
        upload_id = uuid.uuid4().hex
        part, metadata = self._upload_paths(tenant, upload_id)
        part.touch(exist_ok=False)
        metadata.write_text(json.dumps({"sha256": digest, "size": size}), encoding="utf-8")
        return self._json_response(
            start_response, "201 Created", {"offset": 0, "upload_id": upload_id}
        )

    def _upload(self, identity, tenant, upload_id, method, environ, start_response):
        self.service._authorize(identity, "upload", tenant)
        with self._upload_guard:
            lock = self._upload_locks.setdefault(f"{tenant}/{upload_id}", threading.Lock())
        with lock:
            return self._upload_locked(identity, tenant, upload_id, method, environ, start_response)

    def _upload_locked(self, identity, tenant, upload_id, method, environ, start_response):
        part, metadata_path = self._upload_paths(tenant, upload_id)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        offset = part.stat().st_size
        if method == "HEAD":
            return self._json_response(start_response, "200 OK", {"offset": offset})
        expected_offset = int(self._headers(environ).get("upload-offset", "-1"))
        if expected_offset != offset:
            return self._json_response(start_response, "409 Conflict", {"offset": offset})
        chunk = self._body(environ)
        if offset + len(chunk) > metadata["size"]:
            raise ValueError("upload exceeds declared size")
        with part.open("ab") as handle:
            handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        offset += len(chunk)
        if offset != metadata["size"]:
            return self._json_response(start_response, "200 OK", {"offset": offset})
        with self._install_guard:
            data = part.read_bytes()
            if hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                raise ValueError("resumable upload checksum mismatch")
            pack_id, count = self.service.install_pack(identity, tenant, data)
        part.unlink()
        metadata_path.unlink()
        return self._json_response(
            start_response,
            "201 Created",
            {"objects": count, "offset": offset, "pack_id": pack_id},
        )
