"""Atomic shallow-boundary preflight and verified pack installation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentine.kernel import KernelError, validate_links
from opentine.repository._paths import atomic_bytes, install_verified, internal_path
from opentine.repository._semantic_view import SemanticView
from opentine.repository._shallow import encode_shallow, shallow_lock

if TYPE_CHECKING:
    from opentine.repository.store import Repo


def _same_pack(raw: bytes, pack_id: str, max_body: int, max_pack: int) -> bool:
    from opentine.repository.pack import inspect_pack

    return inspect_pack(raw, max_body=max_body, max_pack=max_pack)[0] == pack_id


def install_inspected(
    repo: Repo,
    data: bytes,
    pack_id: str,
    objects: list[tuple[str, bytes]],
    shallow: list[str],
    *,
    max_body: int,
    max_pack: int,
) -> int:
    packed_ids = {oid for oid, _ in objects}
    incoming_shallow = set(shallow)
    shallow_path = internal_path(repo.path, "shallow")
    with shallow_lock(shallow_path):
        existing = repo.shallow_oids()
        boundaries = {
            oid
            for oid in existing | incoming_shallow
            if oid not in packed_ids and not repo.has(oid)
        }
        shallow_body = encode_shallow(boundaries)
        view = SemanticView(
            repo,
            dict(objects),
            check_link_existence=False,
            max_source_bytes=max_body,
        )
        external: set[str] = set()
        for oid, _ in objects:
            envelope = view.get(oid)
            for link in validate_links(envelope):
                if link in packed_ids:
                    continue
                external.add(link)
                if not repo.has(link) and link not in incoming_shallow:
                    raise KernelError(f"pack has unresolved link: {link}")
        if incoming_shallow != external:
            raise KernelError("pack shallow boundaries do not match its external links")
        written = 0
        for oid, raw in objects:
            if install_verified(repo._object_path(oid), raw, "object"):
                written += len(raw)
        pack_path = internal_path(repo.path, "packs", f"{pack_id[7:]}.pack")
        install_verified(
            pack_path,
            data,
            "pack",
            equivalent=lambda raw: _same_pack(raw, pack_id, max_body, max_pack),
            read_limit=max_pack,
        )
        if shallow or shallow_path.exists():
            atomic_bytes(shallow_path, shallow_body)
            repo._invalidate_shallow()
    return written
