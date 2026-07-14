"""HTTP fetch/push client with pack negotiation, CAS refs, and resume."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

import httpx

from opentine.repository.pack import MAX_PACK_BYTES, create_pack, negotiate

if TYPE_CHECKING:
    from opentine.repository import Repo


@dataclass(frozen=True)
class TransferResult:
    objects: int
    pack_id: str
    ref: str | None = None


def _remote(remote: str, tenant: str | None) -> tuple[str, str]:
    url = remote.rstrip("/")
    marker = "/v1/tenants/"
    if marker in url:
        base, embedded = url.split(marker, 1)
        return base, tenant or embedded.split("/", 1)[0]
    if not tenant:
        raise ValueError("tenant is required unless embedded in the remote URL")
    return url, tenant


def _require_secure_remote(base: str, allow_insecure: bool) -> None:
    parsed = urlparse(base)
    if parsed.scheme != "https" and not (
        allow_insecure or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("remote requires HTTPS; opt into insecure development explicitly")


def _client(
    base: str,
    token: str | None,
    *,
    allow_insecure: bool,
    timeout: float,
) -> httpx.Client:
    _require_secure_remote(base, allow_insecure)
    secret = token or os.environ.get("TINE_REMOTE_TOKEN")
    if not secret:
        raise ValueError("remote bearer token is required")
    return httpx.Client(
        base_url=base,
        headers={"Authorization": f"Bearer {secret}"},
        timeout=timeout,
        follow_redirects=False,
    )


def _prefix(tenant: str) -> str:
    return f"/v1/tenants/{quote(tenant, safe='')}"


def capabilities(
    remote: str, *, timeout: float = 30, allow_insecure: bool = False
) -> dict[str, Any]:
    base = remote.rstrip("/")
    _require_secure_remote(base, allow_insecure)
    with httpx.Client(base_url=base, timeout=timeout, follow_redirects=False) as client:
        response = client.get("/v1/capabilities")
        response.raise_for_status()
        data = response.json()
    if data.get("object_format") != "opentine-v3":
        raise ValueError("remote does not support OpenTine v3 objects")
    return data


def _read_pack(response: httpx.Response, limit: int = MAX_PACK_BYTES) -> bytes:
    declared = response.headers.get("content-length")
    if declared is not None and int(declared) > limit:
        raise ValueError("remote pack exceeds maximum transfer size")
    data = bytearray()
    for chunk in response.iter_bytes():
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("remote pack exceeds maximum transfer size")
    return bytes(data)


def fetch(
    repo: Repo,
    remote: str,
    *,
    tenant: str | None = None,
    token: str | None = None,
    ref: str = "heads/main",
    wants: list[str] | None = None,
    depth: int | None = None,
    object_types: set[str] | None = None,
    remote_name: str = "origin",
    allow_insecure: bool = False,
    timeout: float = 120,
) -> TransferResult:
    base, namespace = _remote(remote, tenant)
    with _client(base, token, allow_insecure=allow_insecure, timeout=timeout) as client:
        caps = client.get("/v1/capabilities")
        caps.raise_for_status()
        if caps.json().get("object_format") != "opentine-v3":
            raise ValueError("remote object format is incompatible")
        refs_response = client.get(_prefix(namespace) + "/refs")
        refs_response.raise_for_status()
        remote_refs = refs_response.json().get("refs") or {}
        selected = wants or ([remote_refs[ref]] if ref in remote_refs else [])
        if not selected:
            raise KeyError(f"remote ref not found: {ref}")
        with client.stream(
            "POST",
            _prefix(namespace) + "/fetch",
            json={
                "depth": depth,
                "haves": repo.iter_oids(),
                "object_types": sorted(object_types or ()),
                "wants": selected,
            },
        ) as response:
            response.raise_for_status()
            pack = _read_pack(response)
    result = repo.import_pack(pack)
    if ref in remote_refs:
        tracking = f"remotes/{remote_name}/{ref.removeprefix('heads/')}"
        repo.update_ref(tracking, remote_refs[ref], expected_old=repo.read_ref(tracking))
    return TransferResult(len(result.objects), result.pack_id, ref)


def _upload(
    client: httpx.Client,
    endpoint: str,
    data: bytes,
    *,
    chunk_size: int,
) -> dict[str, Any]:
    declaration = client.post(
        endpoint,
        json={"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
    )
    declaration.raise_for_status()
    state = declaration.json()
    upload = endpoint + "/" + state["upload_id"]
    offset = int(state.get("offset", 0))
    while offset < len(data):
        chunk = data[offset : offset + chunk_size]
        response = client.patch(upload, content=chunk, headers={"Upload-Offset": str(offset)})
        if response.status_code == 409:
            offset = int(response.json()["offset"])
            continue
        response.raise_for_status()
        state = response.json()
        offset = int(state["offset"])
    return state


def push(
    repo: Repo,
    remote: str,
    *,
    tenant: str | None = None,
    token: str | None = None,
    ref: str = "heads/main",
    remote_ref: str | None = None,
    chunk_size: int = 4 * 1024 * 1024,
    allow_insecure: bool = False,
    timeout: float = 120,
) -> TransferResult:
    local_oid = repo.read_ref(ref)
    if not local_oid:
        raise KeyError(f"local ref not found: {ref}")
    destination = remote_ref or ref
    base, namespace = _remote(remote, tenant)
    with _client(base, token, allow_insecure=allow_insecure, timeout=timeout) as client:
        refs_response = client.get(_prefix(namespace) + "/refs")
        refs_response.raise_for_status()
        old = (refs_response.json().get("refs") or {}).get(destination)
        missing = negotiate(repo, [local_oid], [old] if old else [])
        pack = create_pack(repo, missing)
        uploaded = _upload(client, _prefix(namespace) + "/packs", pack, chunk_size=chunk_size)
        update = client.put(
            _prefix(namespace) + "/refs/" + quote(destination, safe=""),
            json={"expected_old": old, "new": local_oid},
        )
        if update.status_code == 409:
            raise ValueError("remote ref changed concurrently")
        update.raise_for_status()
    return TransferResult(int(uploaded.get("objects", 0)), uploaded["pack_id"], destination)


def clone(
    remote: str,
    path: str | Path,
    **kwargs: Any,
) -> Repo:
    from opentine.repository import Repo

    repo = Repo.init(path)
    fetch(repo, remote, **kwargs)
    ref = str(kwargs.get("ref", "heads/main"))
    remote_name = str(kwargs.get("remote_name", "origin"))
    tracking = f"remotes/{remote_name}/{ref.removeprefix('heads/')}"
    target = repo.read_ref(tracking)
    if target:
        repo.update_ref(ref, target, expected_old=repo.read_ref(ref))
    return repo
