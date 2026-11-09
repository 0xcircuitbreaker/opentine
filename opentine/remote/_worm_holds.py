"""Holds and deletes for ``WormObjectStore``: OpenTine holds map to legal holds.

An OpenTine hold (``tine-holds/1`` at ``<holds_root>/.holds/<tenant>``, the
same file the filesystem store reads) is mirrored onto the cloud as a legal
hold on the object and on each of its chunks, so the hold survives anyone who
reaches the bucket without OpenTine. ``delete`` refuses, in this order: an
OpenTine hold, the configured ``RetentionHook``, then the cloud's own
retention date or legal hold. The cloud refuses again if all three pass and it
still disagrees.
"""

from __future__ import annotations

from typing import Any

from opentine.remote._worm import RetentionLocked
from opentine.remote.backend import valid_tenant
from opentine.repository._holds import held_oids


class WormHoldsMixin:
    client: Any
    holds_root: Any
    retention: Any

    def held(self, tenant: str) -> set[str]:
        """OpenTine-held ids in *tenant* (an unreadable holds file raises: fail closed)."""
        if self.holds_root is None:
            return set()
        return held_oids(self.holds_root / ".holds" / valid_tenant(tenant))

    def _chunk_digests(self, tenant: str, oid: str) -> list[str]:
        manifest = self.manifest(tenant, oid)  # type: ignore[attr-defined]
        return [digest for digest, _ in manifest.chunks] if manifest else []

    def set_hold(self, tenant: str, oid: str, on: bool) -> None:
        """Place or clear the cloud legal hold on *oid* and its chunks.

        Clearing leaves a chunk held while another held object still uses it.
        """
        digests = self._chunk_digests(tenant, oid)
        if not on:
            others = self.held(tenant) - {oid}
            keep = {
                d
                for other in others
                if self.has(tenant, other)  # type: ignore[attr-defined]
                for d in self._chunk_digests(tenant, other)
            }
            digests = [d for d in digests if d not in keep]
        self.client.set_legal_hold(self._key(tenant, oid), on)  # type: ignore[attr-defined]
        for digest in digests:
            self.client.set_legal_hold(self._chunk_key(tenant, digest), on)  # type: ignore[attr-defined]

    def sync_holds(self, tenant: str, *, release: bool = False) -> dict[str, list[str]]:
        """Mirror the tenant's holds file onto the cloud.

        Every held, stored object gets a legal hold. With *release*, stored
        objects that carry a legal hold but are no longer held lose it (this
        reads every object's retention, so it is an operator step).
        """
        held = self.held(tenant)
        placed = sorted(oid for oid in held if self.has(tenant, oid))  # type: ignore[attr-defined]
        for oid in placed:
            self.set_hold(tenant, oid, True)
        released: list[str] = []
        if release:
            for oid in self.iter(tenant):  # type: ignore[attr-defined]
                key = self._key(tenant, oid)  # type: ignore[attr-defined]
                if oid not in held and self.client.retention(key).legal_hold:
                    self.set_hold(tenant, oid, False)
                    released.append(oid)
        return {"held": placed, "released": sorted(released)}

    def touch(self, tenant: str, oid: str) -> bool:
        """Object storage keeps no mutable age; report whether *oid* is still stored."""
        return self.has(tenant, oid)  # type: ignore[attr-defined]

    def tombstoned(self, tenant: str, oid: str) -> bool:
        """Tombstones live beside the holds file in the server's state, not the bucket."""
        if self.holds_root is None:
            return False
        from opentine.remote._tombstone_store import has

        return has(self.holds_root, tenant, oid)

    def delete(self, tenant: str, oid: str) -> None:
        tenant = valid_tenant(tenant)
        if oid in self.held(tenant):
            raise RetentionLocked(f"{oid} is held")
        if self.retention:
            self.retention.before_delete(tenant, oid)
        key = self._key(tenant, oid)  # type: ignore[attr-defined]
        try:
            state = self.client.retention(key)
        except KeyError:
            raise FileNotFoundError(oid) from None
        if state.locked():
            raise RetentionLocked(f"{oid} is {state.describe()}")
        digests = self._chunk_digests(tenant, oid)
        self.client.delete(key)
        if not digests:
            return
        self.client.delete(self._key(tenant, oid, "chunked"))  # type: ignore[attr-defined]
        shared = self._chunks_in_use(tenant)
        for digest in set(digests) - shared:
            chunk_key = self._chunk_key(tenant, digest)  # type: ignore[attr-defined]
            try:
                if not self.client.retention(chunk_key).locked():
                    self.client.delete(chunk_key)
            except (KeyError, PermissionError):
                pass  # already gone, or the cloud keeps it: a later sweep's job
            # a chunk still inside retention stays until a later sweep: the cloud
            # would refuse, and its bytes are unreachable without a manifest.

    def _chunks_in_use(self, tenant: str) -> set[str]:
        base = f"{self.prefix}{tenant}/chunked/"  # type: ignore[attr-defined]
        used: set[str] = set()
        for key in self.client.keys(base):
            object_type, _, digest = key[len(base) :].partition("/")
            oid = f"{object_type}:sha256:{digest}"
            if self.has(tenant, oid):  # type: ignore[attr-defined]
                used.update(self._chunk_digests(tenant, oid))
        return used
