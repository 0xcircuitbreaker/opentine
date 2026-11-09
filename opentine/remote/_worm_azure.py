"""Azure immutable-blob adapter for ``WormObjectStore`` (azure-storage-blob).

The container needs version-level immutability support (version-level WORM).
Each put sets a blob ``ImmutabilityPolicy``: OpenTine's *governance* maps to an
``Unlocked`` policy (an account with the right permission can shorten or
remove it) and *compliance* to ``Locked`` (no one can shorten it). OpenTine
holds map to the blob's legal hold. Works against Azure and Azurite.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator
from typing import Any

from opentine.remote._worm import COMPLIANCE, GOVERNANCE, BlobRetention, RetentionLocked

_AZURE_MODE = {GOVERNANCE: "Unlocked", COMPLIANCE: "Locked"}
_OUR_MODE = {"unlocked": GOVERNANCE, "locked": COMPLIANCE}


def _status(exc: Exception) -> int:
    return int(getattr(exc, "status_code", 0) or 0)


class AzureBlobClient:
    def __init__(self, container: Any):
        """*container* is an ``azure.storage.blob.ContainerClient`` (or a stand-in)."""
        self.container = container

    @classmethod
    def from_connection_string(cls, connection: str, name: str) -> AzureBlobClient:
        try:
            from azure.storage.blob import ContainerClient
        except ImportError as exc:  # pragma: no cover - depends on the package
            raise RuntimeError("the Azure object store needs azure-storage-blob") from exc
        return cls(ContainerClient.from_connection_string(connection, name))

    def _blob(self, key: str) -> Any:
        return self.container.get_blob_client(key)

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
            from azure.storage.blob import ImmutabilityPolicy

            extra["immutability_policy"] = ImmutabilityPolicy(
                expiry_time=until, policy_mode=_AZURE_MODE[mode]
            )
        if legal_hold:
            extra["legal_hold"] = True
        self._blob(key).upload_blob(data, overwrite=False, **extra)

    def get(self, key: str) -> bytes:
        try:
            return self._blob(key).download_blob().readall()
        except Exception as exc:
            if _status(exc) == 404:
                raise KeyError(key) from exc
            raise

    def exists(self, key: str) -> bool:
        return bool(self._blob(key).exists())

    def keys(self, prefix: str) -> Iterator[str]:
        for item in self.container.list_blobs(name_starts_with=prefix):
            yield item.name

    def retention(self, key: str) -> BlobRetention:
        try:
            props = self._blob(key).get_blob_properties()
        except Exception as exc:
            if _status(exc) == 404:
                raise KeyError(key) from exc
            raise
        policy = getattr(props, "immutability_policy", None)
        mode = str(getattr(policy, "policy_mode", "") or "").lower()
        return BlobRetention(
            mode=_OUR_MODE.get(mode),
            until=getattr(policy, "expiry_time", None),
            legal_hold=bool(getattr(props, "has_legal_hold", False)),
        )

    def delete(self, key: str) -> None:
        try:
            self._blob(key).delete_blob()
        except Exception as exc:
            if _status(exc) in (403, 409):
                raise RetentionLocked(f"Azure refused to delete {key}") from exc
            raise

    def set_legal_hold(self, key: str, on: bool) -> None:
        self._blob(key).set_legal_hold(on)
