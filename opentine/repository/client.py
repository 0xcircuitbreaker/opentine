"""HTTP fetch/push client with pack negotiation, CAS refs, and resume."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from opentine.kernel import KernelError, parse_oid
from opentine.repository._http import client as _client
from opentine.repository._http import read_pack as _read_pack  # noqa: F401
from opentine.repository._http import request_json as _request_json
from opentine.repository._http import request_pack as _request_pack
from opentine.repository._http import require_secure_remote as _require_secure_remote
from opentine.repository._upload_client import upload as _upload
from opentine.repository.pack import MAGIC, MAX_PACK_OBJECTS, create_pack, negotiate, reachable

if TYPE_CHECKING:
    from opentine.repository import Repo


@dataclass(frozen=True)
class TransferResult:
    objects: int
    pack_id: str
    ref: str | None = None


def _annotation_ref(run_id: str) -> str | None:
    try:
        object_type, digest = parse_oid(run_id)
    except KernelError:
        return None
    return f"annotations/{digest}" if object_type == "run" else None


def _annotation_fast_forward(repo: Repo, old: str | None, new: str) -> bool:
    current = new
    for _ in range(MAX_PACK_OBJECTS):
        if current == old or old is None:
            return True
        payload = repo.get(current).payload()
        previous = payload.get("previous_id")
        if not isinstance(previous, str):
            return False
        current = previous
    return False


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


def _upload_result(
    state: dict[str, Any], *, expected_objects: int | None = None, expected_pack: str | None = None
) -> tuple[int, str]:
    objects, pack_id = state.get("objects"), state.get("pack_id")
    if type(objects) is not int or objects < 0:
        raise ValueError("remote returned an invalid uploaded-object count")
    if not isinstance(pack_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", pack_id):
        raise ValueError("remote returned an invalid pack id")
    mismatch = (expected_objects is not None and objects != expected_objects) or (
        expected_pack is not None and pack_id != expected_pack
    )
    if mismatch:
        raise ValueError("remote upload receipt does not match the submitted pack")
    return objects, pack_id


def capabilities(
    remote: str, *, timeout: float = 30, allow_insecure: bool = False
) -> dict[str, Any]:
    base = remote.rstrip("/")
    _require_secure_remote(base, allow_insecure)
    with httpx.Client(
        base_url=base, timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
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
        _, caps = _request_json(client, "GET", "/v1/capabilities", max_seconds=timeout)
        if caps.get("object_format") != "opentine-v3":
            raise ValueError("remote object format is incompatible")
        _, refs = _request_json(client, "GET", _prefix(namespace) + "/refs", max_seconds=timeout)
        remote_refs = _refs(refs)
        selected = wants or ([remote_refs[ref]] if ref in remote_refs else [])
        if not selected:
            raise KeyError(f"remote ref not found: {ref}")
        pack = _request_pack(
            client,
            "POST",
            _prefix(namespace) + "/fetch",
            max_seconds=timeout,
            json={
                "depth": depth,
                # The wire protocol deliberately bounds negotiation sets. A
                # truncated have-list can only cause a redundant transfer;
                # sending more would make otherwise healthy large repositories
                # impossible to fetch into.
                "haves": repo.iter_oids(limit=MAX_PACK_OBJECTS, truncate=True),
                "object_types": sorted(object_types or ()),
                "wants": selected,
            },
        )
    result = repo.import_pack(pack)
    # A filtered or shallow fetch may intentionally omit the advertised root.
    # Only materialize a tracking ref when its target is actually present and
    # verified locally; otherwise the fetched objects remain inspectable
    # without creating a dangling ref.
    if ref in remote_refs and repo.has(remote_refs[ref]):
        tracking = f"remotes/{remote_name}/{ref.removeprefix('heads/')}"
        repo.update_ref(tracking, remote_refs[ref], expected_old=repo.read_ref(tracking))
        annotation = _annotation_ref(remote_refs[ref])
        remote_annotation = remote_refs.get(annotation or "")
        if annotation and remote_annotation and repo.has(remote_annotation):
            local_annotation = repo.read_ref(annotation)
            if _annotation_fast_forward(repo, local_annotation, remote_annotation):
                repo.update_ref(annotation, remote_annotation, expected_old=local_annotation)
    return TransferResult(len(result.objects), result.pack_id, ref)


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
        _, refs = _request_json(client, "GET", _prefix(namespace) + "/refs", max_seconds=timeout)
        old = _refs(refs).get(destination)
        known = reachable(repo, [old], include_associated=False) if old and repo.has(old) else []
        missing = negotiate(repo, [local_oid], known)
        pack = create_pack(repo, missing)
        uploaded = _upload(
            client,
            _prefix(namespace) + "/packs",
            pack,
            chunk_size=chunk_size,
            timeout=timeout,
        )
        expected_pack = "sha256:" + pack[len(MAGIC) : len(MAGIC) + 32].hex()
        objects, pack_id = _upload_result(
            uploaded, expected_objects=len(missing), expected_pack=expected_pack
        )
        status, _ = _request_json(
            client,
            "PUT",
            _prefix(namespace) + "/refs/" + quote(destination, safe=""),
            allowed=(200, 409),
            max_seconds=timeout,
            json={"expected_old": old, "new": local_oid},
        )
        if status == 409:
            raise ValueError("remote ref changed concurrently")
        annotation = _annotation_ref(local_oid)
        local_annotation = repo.read_ref(annotation) if annotation else None
        if annotation and local_annotation:
            annotation_status, _ = _request_json(
                client,
                "PUT",
                _prefix(namespace) + "/refs/" + quote(annotation, safe=""),
                allowed=(200, 409),
                max_seconds=timeout,
                json={
                    "expected_old": _refs(refs).get(annotation),
                    "new": local_annotation,
                },
            )
            if annotation_status == 409:
                raise ValueError("remote annotation ref changed concurrently")
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
