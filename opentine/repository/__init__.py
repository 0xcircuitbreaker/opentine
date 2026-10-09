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
        key: Any | None = None,
        algorithm: str = "hmac-sha256",
        key_id: str | None = None,
        signed_at: str | None = None,
    ) -> str:
        """Write an attestation, signed at ``tine-attest/1`` when ``key`` is given.

        Without ``key`` (and without a prepared ``signature``) this writes the
        byte-identical unsigned object every release since 0.3.0 wrote, and
        ``verify_attestation`` reports it as ``unsigned``.
        """
        from opentine.repository._attest import attest

        return attest(
            self,
            target_id,
            claim,
            signer=signer,
            signature=signature,
            evidence_ids=evidence_ids,
            key=key,
            algorithm=algorithm,
            key_id=key_id,
            signed_at=signed_at,
        )

    def verify_attestation(
        self,
        oid: str,
        *,
        hmac_key: bytes | None = None,
        public_key: Any | None = None,
        trust_embedded: bool = False,
    ):
        """Verify one attestation's signature, returning a ``SignatureResult``.

        Fail-closed and never raising a verdict: ``unsigned`` when the object
        carries no signature, ``no-key`` when it carries one this caller holds no
        key for, ``mismatch`` when a key disagrees, ``verified`` only otherwise.
        """
        from opentine.repository._attest import verify_attestation_object

        return verify_attestation_object(
            self,
            oid,
            hmac_key=hmac_key,
            public_key=public_key,
            trust_embedded=trust_embedded,
        )

    def attestations_for(self, run_id: str) -> tuple[str, ...]:
        """The attestation ids targeting *run_id*, sorted."""
        from opentine.repository._attest import attestations_for

        return attestations_for(self, run_id)

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
