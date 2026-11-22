"""Where ``tine serve`` keeps packs: a small storage interface (0.77).

A :class:`PackBlobs` stores immutable named byte strings. Two backends:

* :class:`FilesystemPackBlobs`: files under a directory, each made durable
  under a temporary name and linked in with ``os.link`` (which refuses an
  existing name), so a name is never overwritten.
* :class:`S3PackBlobs`: S3 (or MinIO) through boto3 (as the WORM store). A
  body goes up as a multipart upload completed with ``If-None-Match: *`` (S3 refuses
  to replace an existing key; the upload is atomic, readers see all or
  nothing). Every part carries its SHA-256 checksum and the completed upload's
  ETag must equal the one computed locally (MD5 of the part MD5s), so a part
  that was altered in transit or reordered is refused and the upload aborted.

A body of at most one part goes up as one ``PutObject`` with the same
``If-None-Match``, SHA-256 checksum and ETag (MD5) check.

``put`` returns ``False`` when the name already exists (the caller checks that
the existing bytes are the same content); it never replaces bytes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

PART_BYTES = 8 * 1024 * 1024
MIN_PART_BYTES = 5 * 1024 * 1024  # S3 refuses smaller parts (all but the last)
_MISSING = {"NoSuchKey", "404", "NotFound"}
_EXISTS = {"PreconditionFailed", "412", "ConditionalRequestConflict"}


class PackBlobs(Protocol):
    def put(self, name: str, data: bytes) -> bool: ...
    def get(self, name: str) -> bytes: ...
    def exists(self, name: str) -> bool: ...
    def names(self, prefix: str) -> Iterator[str]: ...
    def delete(self, name: str) -> None: ...


class DigestMismatch(OSError):
    """The stored bytes are not the bytes that were sent."""


class FilesystemPackBlobs:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, name: str) -> Path:
        parts = name.split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise ValueError(f"invalid pack blob name {name!r}")
        return self.root.joinpath(*parts)

    def put(self, name: str, data: bytes) -> bool:
        from opentine._canon import _fsync_dir

        path = self._path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)  # refuses an existing name: never overwrite
            except FileExistsError:
                return False
            _fsync_dir(path.parent)
            return True
        finally:
            os.unlink(temporary)

    def get(self, name: str) -> bytes:
        try:
            return self._path(name).read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(name) from exc

    def exists(self, name: str) -> bool:
        return self._path(name).is_file()

    def names(self, prefix: str) -> Iterator[str]:
        base = self._path(prefix.rstrip("/")) if prefix.strip("/") else self.root
        if not base.is_dir():
            return
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.name.startswith("."):
                yield path.relative_to(self.root).as_posix()

    def delete(self, name: str) -> None:
        from opentine._canon import _fsync_dir

        path = self._path(name)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        _fsync_dir(path.parent)


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return str(response.get("Error", {}).get("Code", ""))


def multipart_etag(parts: list[bytes]) -> str:
    """The ETag S3 gives a multipart upload of *parts* (unencrypted, SSE-S3)."""
    joined = b"".join(hashlib.md5(p, usedforsecurity=False).digest() for p in parts)
    return f'"{hashlib.md5(joined, usedforsecurity=False).hexdigest()}-{len(parts)}"'


class S3PackBlobs:
    def __init__(self, bucket: str, client: Any = None, *, prefix: str = "",
                 part_bytes: int = PART_BYTES, check_etag: bool = True,
                 **session: Any):  # fmt: skip
        if client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise RuntimeError("the S3 pack store needs boto3") from exc
            client = boto3.client("s3", **session)
        self.bucket, self.s3 = bucket, client
        self.part_bytes = max(part_bytes, MIN_PART_BYTES)
        self.check_etag = check_etag  # off for SSE-KMS buckets, whose ETags are not MD5s
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""

    def put(self, name: str, data: bytes) -> bool:
        if len(data) <= self.part_bytes:
            return self._put_one(name, data)
        key = self.prefix + name
        parts = [data[i : i + self.part_bytes] for i in range(0, len(data), self.part_bytes)]
        parts = parts or [b""]
        upload = self.s3.create_multipart_upload(Bucket=self.bucket, Key=key,
                                                 ChecksumAlgorithm="SHA256")  # fmt: skip
        uid, done = upload["UploadId"], []
        try:
            for number, part in enumerate(parts, 1):
                sha = base64.b64encode(hashlib.sha256(part).digest()).decode("ascii")
                sent = self.s3.upload_part(Bucket=self.bucket, Key=key, UploadId=uid,
                                           PartNumber=number, Body=part,
                                           ChecksumSHA256=sha)  # fmt: skip
                done.append({"PartNumber": number, "ETag": sent["ETag"], "ChecksumSHA256": sha})
            result = self.s3.complete_multipart_upload(
                Bucket=self.bucket, Key=key, UploadId=uid, IfNoneMatch="*",
                MultipartUpload={"Parts": done})  # fmt: skip
        except Exception as exc:
            self._abort(key, uid)
            if _code(exc) in _EXISTS:
                return False
            raise
        if self.check_etag and result.get("ETag") != multipart_etag(parts):
            self.delete(name)  # this upload made it, and it is not what was sent
            raise DigestMismatch(f"{key}: stored ETag {result.get('ETag')} is not the upload's")
        return True

    def _put_one(self, name: str, data: bytes) -> bool:
        sha = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        md5 = hashlib.md5(data, usedforsecurity=False)
        digest = base64.b64encode(md5.digest()).decode("ascii")
        try:
            result = self.s3.put_object(Bucket=self.bucket, Key=self.prefix + name, Body=data,
                                        IfNoneMatch="*", ChecksumSHA256=sha,
                                        ContentMD5=digest)  # fmt: skip
        except Exception as exc:
            if _code(exc) in _EXISTS:
                return False
            raise
        if self.check_etag and result.get("ETag") != f'"{md5.hexdigest()}"':
            self.delete(name)
            raise DigestMismatch(f"{name}: stored ETag {result.get('ETag')} is not the body's")
        return True

    def _abort(self, key: str, uid: str) -> None:
        try:
            self.s3.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=uid)
        except Exception:  # noqa: BLE001, S110 - a completed or vanished upload
            pass

    def get(self, name: str) -> bytes:
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=self.prefix + name)
        except Exception as exc:
            if _code(exc) in _MISSING:
                raise KeyError(name) from exc
            raise
        return response["Body"].read()

    def exists(self, name: str) -> bool:
        try:
            self.s3.head_object(Bucket=self.bucket, Key=self.prefix + name)
        except Exception as exc:
            if _code(exc) in _MISSING:
                return False
            raise
        return True

    def names(self, prefix: str) -> Iterator[str]:
        pages = self.s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=self.prefix + prefix)  # fmt: skip
        for page in pages:
            for item in page.get("Contents", []):
                yield item["Key"][len(self.prefix) :]

    def delete(self, name: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self.prefix + name)


__all__ = ["DigestMismatch", "FilesystemPackBlobs", "PackBlobs", "S3PackBlobs",
           "multipart_etag"]  # fmt: skip
