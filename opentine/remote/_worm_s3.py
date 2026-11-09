"""S3 Object Lock adapter for ``WormObjectStore`` (boto3, the ``s3`` extra).

The bucket must be created with Object Lock enabled (which turns on
versioning). Each put sends ``ObjectLockMode`` (``GOVERNANCE``/``COMPLIANCE``)
and ``ObjectLockRetainUntilDate``; a legal hold is ``ObjectLockLegalHoldStatus``.
A delete names the current version id, so S3 must remove that version (and
refuses it inside retention) instead of stacking a delete marker on top of a
still-retained version. ``delete`` never sends ``BypassGovernanceRetention``.

Works with AWS and with MinIO (``endpoint_url``), which implements Object Lock.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator
from typing import Any

from opentine.remote._worm import BlobRetention, RetentionLocked

_REFUSED = {"AccessDenied", "InvalidRequest", "ObjectLocked", "InvalidObjectState"}
_MISSING = {"NoSuchKey", "404", "NotFound", "NoSuchVersion"}


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return str(response.get("Error", {}).get("Code", ""))


class S3BlobClient:
    def __init__(self, bucket: str, client: Any = None, **session: Any):
        if client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise RuntimeError("the S3 object store needs boto3") from exc
            client = boto3.client("s3", **session)
        self.bucket, self.s3 = bucket, client

    def put(
        self,
        key: str,
        data: bytes,
        *,
        mode: str | None,
        until: datetime.datetime | None,
        legal_hold: bool,
    ) -> None:
        extra: dict[str, Any] = {}
        if mode and until:
            extra["ObjectLockMode"] = mode.upper()
            extra["ObjectLockRetainUntilDate"] = until
        if legal_hold:
            extra["ObjectLockLegalHoldStatus"] = "ON"
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=data, **extra)

    def _head(self, key: str) -> dict[str, Any]:
        try:
            return self.s3.head_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            if _code(exc) in _MISSING:
                raise KeyError(key) from exc
            raise

    def get(self, key: str) -> bytes:
        try:
            return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except Exception as exc:
            if _code(exc) in _MISSING:
                raise KeyError(key) from exc
            raise

    def exists(self, key: str) -> bool:
        try:
            self._head(key)
        except KeyError:
            return False
        return True

    def keys(self, prefix: str) -> Iterator[str]:
        pages = self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix)
        for page in pages:
            for item in page.get("Contents", []):
                yield item["Key"]

    def retention(self, key: str) -> BlobRetention:
        head = self._head(key)
        mode = head.get("ObjectLockMode")
        return BlobRetention(
            mode=mode.lower() if isinstance(mode, str) else None,
            until=head.get("ObjectLockRetainUntilDate"),
            legal_hold=head.get("ObjectLockLegalHoldStatus") == "ON",
        )

    def delete(self, key: str) -> None:
        version = self._head(key).get("VersionId")
        args: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
        if version and version != "null":
            args["VersionId"] = version
        try:
            self.s3.delete_object(**args)
        except Exception as exc:
            if _code(exc) in _REFUSED:
                raise RetentionLocked(f"S3 refused to delete {key}: {_code(exc)}") from exc
            raise

    def set_legal_hold(self, key: str, on: bool) -> None:
        self.s3.put_object_legal_hold(
            Bucket=self.bucket, Key=key, LegalHold={"Status": "ON" if on else "OFF"}
        )

    def extend(self, key: str, mode: str, until: datetime.datetime) -> None:
        """Move retention later (never sooner; S3 refuses a shortening anyway)."""
        self.s3.put_object_retention(
            Bucket=self.bucket,
            Key=key,
            Retention={"Mode": mode.upper(), "RetainUntilDate": until},
        )
