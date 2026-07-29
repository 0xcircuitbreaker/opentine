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


def _dependency_order(
    objects: list[tuple[str, bytes]], links: dict[str, set[str]]
) -> list[tuple[str, bytes]]:
    """Order objects so every link target is written before the object citing it.

    Installing in object-id order meant an interrupted install — Ctrl-C, ENOSPC —
    could leave an annotation or run behind whose targets were never written. The
    destination then reported "missing linked object" from fsck and could not read
    that object at all, permanently, until the whole pack was fetched again.
    Dependency order makes any truncation link-closed instead of broken.
    """
    raw_by_oid = dict(objects)
    ordered: list[tuple[str, bytes]] = []
    placed: set[str] = set()
    expanded: set[str] = set()
    for root in raw_by_oid:
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            oid, done = stack.pop()
            if oid in placed or oid not in raw_by_oid:
                continue
            if done:
                placed.add(oid)
                ordered.append((oid, raw_by_oid[oid]))
                continue
            if oid in expanded:
                continue
            expanded.add(oid)
            stack.append((oid, True))
            stack.extend((link, False) for link in sorted(links.get(oid, ())))
    return ordered


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
        internal: dict[str, set[str]] = {}
        for oid, _ in objects:
            envelope = view.get(oid)
            links = validate_links(envelope)
            internal[oid] = {link for link in links if link in packed_ids}
            for link in links:
                if link in packed_ids:
                    continue
                external.add(link)
                if not repo.has(link) and link not in incoming_shallow:
                    raise KernelError(f"pack has unresolved link: {link}")
        if incoming_shallow != external:
            raise KernelError("pack shallow boundaries do not match its external links")
        written = 0
        for oid, raw in _dependency_order(objects, internal):
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
