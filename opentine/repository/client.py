"""HTTP fetch/push client with pack negotiation, CAS refs, and resume."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from opentine.kernel import KernelError, parse_oid
from opentine.repository import _pack4
from opentine.repository._http import client as _client
from opentine.repository._http import read_pack as _read_pack  # noqa: F401
from opentine.repository._http import request_json as _request_json
from opentine.repository._http import request_pack as _request_pack
from opentine.repository._http import require_secure_remote as _require_secure_remote
from opentine.repository._http import split_remote as _remote
from opentine.repository._pack_fit import fitted_pack
from opentine.repository._unadopted import adopt_advertised_annotations, runs_held
from opentine.repository._upload_client import upload as _upload
from opentine.repository.pack import (  # noqa: F401
    MAGIC,
    MAX_PACK_OBJECTS,
    OMITTED_HEADER,
    reachable,
)

if TYPE_CHECKING:
    from opentine.repository import Repo


@dataclass(frozen=True)
class TransferResult:
    objects: int
    pack_id: str
    ref: str | None = None
    #: Runs whose attestations (or annotations) did not fit in a fetched pack.
    associations_omitted: int = 0


def _omitted(headers: dict[str, str]) -> int:
    value = headers.get(OMITTED_HEADER.lower(), "0")
    return int(value) if value.isdigit() and int(value) <= MAX_PACK_OBJECTS else 0


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
    adopt_annotations: bool = False,
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
        received: dict[str, str] = {}
        pack = _request_pack(
            client,
            "POST",
            _prefix(namespace) + "/fetch",
            max_seconds=timeout,
            response_headers=received,
            json={
                "depth": depth,
                # The wire protocol deliberately bounds negotiation sets. A
                # truncated have-list can only cause a redundant transfer;
                # sending more would make otherwise healthy large repositories
                # impossible to fetch into.
                "haves": repo.iter_oids(limit=MAX_PACK_OBJECTS, truncate=True),
                "object_types": sorted(object_types or ()),
                "wants": selected,
                **_pack4.request_fields(caps),
            },
        )
    held_before = runs_held(repo, remote_refs)
    result = repo.import_pack(pack)
    # A filtered or shallow fetch may intentionally omit the advertised root.
    # Only materialize a tracking ref when its target is actually present and
    # verified locally; otherwise the fetched objects remain inspectable
    # without creating a dangling ref.
    if ref in remote_refs and repo.has(remote_refs[ref]):
        tracking = f"remotes/{remote_name}/{ref.removeprefix('heads/')}"
        repo.update_ref(tracking, remote_refs[ref], expected_old=repo.read_ref(tracking))
        adopt_advertised_annotations(
            repo, remote_refs, held_before, remote_name, adopt_held=adopt_annotations
        )
    return TransferResult(len(result.objects), result.pack_id, ref, _omitted(received))


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
    force: bool = False,
) -> TransferResult:
    """Send *ref*'s run; *force* asks a fast-forward-only server to move a head anyway."""
    local_oid = repo.read_ref(ref)
    if not local_oid:
        raise KeyError(f"local ref not found: {ref}")
    destination = remote_ref or ref
    base, namespace = _remote(remote, tenant)
    with _client(base, token, allow_insecure=allow_insecure, timeout=timeout) as client:
        _, caps = _request_json(client, "GET", "/v1/capabilities", max_seconds=timeout)
        _, refs = _request_json(client, "GET", _prefix(namespace) + "/refs", max_seconds=timeout)
        old = _refs(refs).get(destination)
        known = reachable(repo, [old], include_associated=False) if old and repo.has(old) else []
        short: list[str] = []
        pack, missing = fitted_pack(repo, [local_oid], known, omitted=short)
        pack = _pack4.for_peer(pack, caps)  # v4 only to a server that lists it
        uploaded = _upload(
            client,
            _prefix(namespace) + "/packs",
            pack,
            chunk_size=chunk_size,
            timeout=timeout,
        )
        expected_pack = _pack4.pack_digest(pack)
        objects, pack_id = _upload_result(
            uploaded, expected_objects=len(missing), expected_pack=expected_pack
        )
        status, _ = _request_json(
            client,
            "PUT",
            _prefix(namespace) + "/refs/" + quote(destination, safe=""),
            allowed=(200, 409),
            max_seconds=timeout,
            json={"expected_old": old, "new": local_oid, **({"force": True} if force else {})},
        )
        if status == 409:
            raise ValueError("remote ref changed concurrently")
        annotation = (
            "annotations/" + local_oid[11:] if local_oid.startswith("run:sha256:") else None
        )
        local_annotation = repo.read_ref(annotation) if annotation else None
        if annotation and local_annotation:
            annotation_status, _ = _request_json(
                client,
                "PUT",
                _prefix(namespace) + "/refs/" + quote(annotation, safe=""),
                allowed=(200, 409),
                max_seconds=timeout,
                json={"expected_old": _refs(refs).get(annotation), "new": local_annotation},
            )
            if annotation_status == 409:
                raise ValueError("remote annotation ref changed concurrently")
    return TransferResult(objects, pack_id, destination, len(short))


def clone(
    remote: str,
    path: str | Path,
    **kwargs: Any,
) -> Repo:
    from opentine.repository import Repo

    repo = Repo.init(path)
    # Cloning into a repository that already held refs re-pointed its heads/main
    # silently (the compare-and-swap was against the value just read).
    if repo.list_refs() or repo.iter_oids(limit=1, truncate=True):
        raise ValueError(f"clone target already holds a repository: {path}; use fetch")
    fetch(repo, remote, **kwargs)
    ref = str(kwargs.get("ref", "heads/main"))
    tracking = f"remotes/{kwargs.get('remote_name', 'origin')}/{ref.removeprefix('heads/')}"
    target = repo.read_ref(tracking)
    if target:
        repo.update_ref(ref, target, expected_old=repo.read_ref(ref))
    return repo
