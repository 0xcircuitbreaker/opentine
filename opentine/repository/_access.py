"""Consistent repository-read errors for operations and frontends."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentine.kernel import KernelError, ObjectEnvelope

if TYPE_CHECKING:
    from opentine.repository.store import Repo


def get_object(repo: Repo, oid: str) -> ObjectEnvelope:
    try:
        return repo.get(oid)
    except (KernelError, KeyError, OSError) as exc:
        raise ValueError(f"repository object is unavailable: {oid}") from exc
