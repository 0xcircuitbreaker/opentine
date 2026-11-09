"""``tine serve`` object-store selection from the environment (0.49).

``TINE_REMOTE_OBJECT_STORE`` unset keeps the filesystem store. Otherwise:

* ``s3://<bucket>[/<prefix>]``: S3 Object Lock. ``TINE_REMOTE_S3_ENDPOINT``
  points at MinIO or another S3-compatible service; boto3 reads credentials
  and region the usual way (``AWS_*`` variables, profiles, instance roles).
* ``azblob://<container>[/<prefix>]``: Azure immutable blobs, connected with
  ``AZURE_STORAGE_CONNECTION_STRING``.

``TINE_REMOTE_RETENTION_MODE`` (``governance`` | ``compliance``) and
``TINE_REMOTE_RETENTION_DAYS`` set the retention every new object is written
with. Holds are read from ``<root>/objects/.holds/<tenant>``, as for the
filesystem store, and mirrored to the cloud as legal holds.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from opentine.remote._worm import WormPolicy

STORE_ENV = "TINE_REMOTE_OBJECT_STORE"
MODE_ENV = "TINE_REMOTE_RETENTION_MODE"
DAYS_ENV = "TINE_REMOTE_RETENTION_DAYS"
ENDPOINT_ENV = "TINE_REMOTE_S3_ENDPOINT"
AZURE_ENV = "AZURE_STORAGE_CONNECTION_STRING"


def policy_from_env(env: Mapping[str, str]) -> WormPolicy:
    mode = (env.get(MODE_ENV) or "").strip().lower() or None
    raw = (env.get(DAYS_ENV) or "").strip()
    try:
        days = int(raw) if raw else 0
    except ValueError as exc:
        raise ValueError(f"{DAYS_ENV} must be a whole number of days") from exc
    return WormPolicy(mode, days)


def parse_location(url: str) -> tuple[str, str, str]:
    """``(scheme, bucket-or-container, prefix)`` from a store URL."""
    scheme, sep, rest = url.partition("://")
    name, _, prefix = rest.partition("/")
    if not sep or scheme not in ("s3", "azblob") or not name:
        raise ValueError(
            f"{STORE_ENV} must be s3://<bucket>[/prefix] or azblob://<container>[/prefix]"
        )
    return scheme, name, prefix.strip("/")


def object_store_from_env(
    state: Path,
    keys: Any,
    *,
    env: Mapping[str, str] | None = None,
    client: Any = None,
) -> Any | None:
    """A ``WormObjectStore`` when ``TINE_REMOTE_OBJECT_STORE`` names one, else None."""
    env = os.environ if env is None else env
    url = (env.get(STORE_ENV) or "").strip()
    if not url:
        return None
    from opentine.remote._worm_store import WormObjectStore

    scheme, name, prefix = parse_location(url)
    if client is None and scheme == "s3":
        from opentine.remote._worm_s3 import S3BlobClient

        endpoint = (env.get(ENDPOINT_ENV) or "").strip()
        client = S3BlobClient(name, **({"endpoint_url": endpoint} if endpoint else {}))
    elif client is None:
        from opentine.remote._worm_azure import AzureBlobClient

        connection = env.get(AZURE_ENV) or ""
        if not connection:
            raise ValueError(f"azblob:// needs {AZURE_ENV}")
        client = AzureBlobClient.from_connection_string(connection, name)
    return WormObjectStore(
        client, keys, policy_from_env(env), prefix=prefix, holds_root=state / "objects"
    )
