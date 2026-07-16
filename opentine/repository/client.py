"""HTTP fetch/push client with pack negotiation, CAS refs, and resume."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from opentine.kernel import KernelError, parse_oid
from opentine.repository._http import (
    client as _client,
)
from opentine.repository._http import (
    read_pack as _read_pack,
)
from opentine.repository._http import (
    request_json as _request_json,
)
from opentine.repository._http import (
    require_secure_remote as _require_secure_remote,
)
from opentine.repository.pack import create_pack, negotiate

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


def _prefix(tenant: str) -> str:
    return f"/v1/tenants/{quote(tenant, safe='')}"


def _refs(value: dict[str, Any]) -> dict[str, str]:
    refs = value.get("refs")
    if not isinstance(refs, dict) or not all(
        isinstance(name, str) and isinstance(oid, str) for name, oid in refs.items()
    ):
        raise ValueError("remote returned an invalid ref listing")
    try:
        for oid in refs.values():
            parse_oid(oid)
    except KernelError as exc:
        raise ValueError("remote returned an invalid ref target") from exc
    return refs


def _offset(state: dict[str, Any], default: int = -1) -> int:
    raw = state.get("offset", default)
    if type(raw) is not int:
        raise ValueError("remote returned an invalid upload offset")
    return raw


def _upload_result(state: dict[str, Any]) -> tuple[int, str]:
    objects, pack_id = state.get("objects"), state.get("pack_id")
    if type(objects) is not int or objects < 0:
        raise ValueError("remote returned an invalid uploaded-object count")
    if not isinstance(pack_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", pack_id):
        raise ValueError("remote returned an invalid pack id")
    return objects, pack_id


def capabilities(
    remote: str, *, timeout: float = 30, allow_insecure: bool = False
) -> dict[str, Any]:
    base = remote.rstrip("/")
    _require_secure_remote(base, allow_insecure)
    with httpx.Client(base_url=base, timeout=timeout, follow_redirects=False) as client:
        _, data = _request_json(client, "GET", "/v1/capabilities", max_seconds=timeout)
    if data.get("object_format") != "opentine-v3":
        raise ValueError("remote does not support OpenTine v3 objects")
    return data


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
        _, caps = _request_json(client, "GET", "/v1/capabilities")
        if caps.get("object_format") != "opentine-v3":
            raise ValueError("remote object format is incompatible")
        _, refs = _request_json(client, "GET", _prefix(namespace) + "/refs")
        remote_refs = _refs(refs)
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
            pack = _read_pack(response, max_seconds=timeout)
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
    if chunk_size < 1:
        raise ValueError("upload chunk size must be positive")
    _, state = _request_json(
        client,
        "POST",
        endpoint,
        allowed=(200, 201),
        json={"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
    )
    upload_id = state.get("upload_id")
    if not isinstance(upload_id, str) or not re.fullmatch(r"[0-9a-f]{32}", upload_id):
        raise ValueError("remote returned an invalid upload id")
    upload = endpoint + "/" + upload_id
    offset = _offset(state, 0)
    if not 0 <= offset <= len(data):
        raise ValueError("remote returned an invalid upload offset")
    max_iterations = (len(data) + chunk_size - 1) // chunk_size + 4
    iterations = 0
    while offset < len(data):
        iterations += 1
        if iterations > max_iterations:
            raise ValueError("remote upload did not converge")
        chunk = data[offset : offset + chunk_size]
        status, state = _request_json(
            client,
            "PATCH",
            upload,
            allowed=(200, 201, 409),
            content=chunk,
            headers={"Upload-Offset": str(offset)},
        )
        next_offset = _offset(state)
        if not offset < next_offset <= len(data):
            raise ValueError("remote upload offset did not advance")
        if status != 409 and next_offset != offset + len(chunk):
            raise ValueError("remote acknowledged an invalid upload length")
        offset = next_offset
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
        _, refs = _request_json(client, "GET", _prefix(namespace) + "/refs")
        old = _refs(refs).get(destination)
        missing = negotiate(repo, [local_oid], [old] if old else [])
        pack = create_pack(repo, missing)
        uploaded = _upload(client, _prefix(namespace) + "/packs", pack, chunk_size=chunk_size)
        objects, pack_id = _upload_result(uploaded)
        status, _ = _request_json(
            client,
            "PUT",
            _prefix(namespace) + "/refs/" + quote(destination, safe=""),
            allowed=(200, 409),
            json={"expected_old": old, "new": local_oid},
        )
        if status == 409:
            raise ValueError("remote ref changed concurrently")
    return TransferResult(objects, pack_id, destination)


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
