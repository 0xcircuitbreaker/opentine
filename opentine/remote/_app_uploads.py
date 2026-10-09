"""Resumable upload routes of the reference transport (``POST/HEAD/PATCH packs``).

An upload id was the only thing tying an upload to its creator: any writer in the
tenant who learned one -- the server's request log printed it -- could append to
it, read its progress, or complete it and have the install attributed to them. An
upload now records a digest of the tenant and subject that declared it, and
every later request must come from that same identity (``403`` otherwise, which
the app audits). An upload declared before 0.9.2 has no owner and expires within
its TTL as before.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid

from opentine.remote._uploads import TerminalUploadError


def upload_owner(identity, tenant: str) -> str:
    material = f"{tenant}\0{identity.subject}".encode()
    return hashlib.sha256(b"opentine.upload-owner.v1\0" + material).hexdigest()


class UploadRoutes:
    def _start_upload(self, identity, tenant, request, start_response):
        self.service._authorize(identity, "upload", tenant)
        size = request.get("size")
        digest = str(request["sha256"])
        valid_size = type(size) is int and 0 < size <= self.max_upload_bytes
        if not valid_size or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid resumable upload declaration")
        upload_id = uuid.uuid4().hex
        declared = {"owner": upload_owner(identity, tenant), "sha256": digest, "size": size}
        paths = self._uploads.create(tenant, upload_id, declared)
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
        owner = metadata.get("owner")
        if owner is not None and not hmac.compare_digest(
            str(owner), upload_owner(identity, tenant)
        ):
            raise PermissionError("this upload was declared by another identity")
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
        with self._guarded(self._install_guard):
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
