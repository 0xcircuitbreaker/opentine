"""Public Git-shaped v3 repository API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.repository.ops import SemanticDiff
from opentine.repository.store import Repo as ObjectDatabase
from opentine.repository.verify import FsckResult


class Repo(ObjectDatabase):
    def import_pack(self, data: bytes):
        from opentine.repository.pack import install_pack

        return install_pack(self, data)

    def put_run(self, run, *, ref: str | None = None):
        from opentine.repository.runs import put_run

        return put_run(self, run, ref=ref)

    def load_run(self, oid_or_ref: str):
        from opentine.repository.runs import load_run

        return load_run(self, oid_or_ref)

    def migrate_v2(self, path: str | Path, **kwargs: Any):
        from opentine.repository._migration import migrate_v2

        return migrate_v2(self, path, **kwargs)

    def fork(
        self,
        run: str,
        from_event: str,
        *,
        overrides: dict[str, Any] | None = None,
        ref: str | None = None,
    ) -> str:
        from opentine.repository.ops import fork_run

        return fork_run(self, run, from_event, overrides=overrides, ref=ref)

    def context_slice(self, event_id: str, *, depth: int = 8):
        from opentine.repository.ops import context_slice

        return context_slice(self, event_id, depth=depth)

    def attest(
        self,
        target_id: str,
        claim: dict[str, Any],
        *,
        signer: str,
        signature: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> str:
        from opentine.repository.ops import attest

        return attest(
            self,
            target_id,
            claim,
            signer=signer,
            signature=signature,
            evidence_ids=evidence_ids,
        )

    def promote(self, run_id: str, name: str, *, expected_old: str | None = None) -> None:
        from opentine.repository.ops import promote

        promote(self, run_id, name, expected_old=expected_old)

    def fetch(self, remote: str, **kwargs: Any):
        from opentine.repository.client import fetch

        return fetch(self, remote, **kwargs)

    def push(self, remote: str, **kwargs: Any):
        from opentine.repository.client import push

        return push(self, remote, **kwargs)

    def search(self, query: str = "", **kwargs: Any):
        from opentine.repository.search import search

        return search(self, query, **kwargs)

    def inspect(self, oid: str, *, resolve_blobs: bool = False):
        from opentine.repository.search import inspect

        return inspect(self, oid, resolve_blobs=resolve_blobs)


__all__ = ["FsckResult", "Repo", "SemanticDiff"]
