"""``PackSet``'s view of its pack indexes (P7, 0.37; see ``_pack_lookup``).

Single lookups go to each index in place; the bulk maps (``where``, ``v3``) are
built only when a bulk walk asks for them.
"""

from __future__ import annotations

from opentine.repository._pack_lookup import LegacyIndex, MappedIndex


class LazyIndexes:
    """``PackSet``'s view of its indexes: single lookups in place, bulk maps lazily.

    ``where`` and ``v3`` (every entry of every pack) are built only when a bulk
    walk asks for them, and they can be assigned (``_pack_write.load_pack``).
    """

    indexes: dict[str, LegacyIndex | MappedIndex]
    blocks: dict[str, list]
    _where: dict[str, tuple[str, int, int, int]] | None
    _v3: dict[str, dict[str, tuple[int, int, int, int, int]]] | None

    @property
    def where(self) -> dict[str, tuple[str, int, int, int]]:
        """Every packed oid -> (pack, block, start, length)."""
        if self._where is None:
            v3 = self.v3  # drops a v3 index whose whole-file rules fail
            where: dict[str, tuple[str, int, int, int]] = {}
            for digest, index in self.indexes.items():
                entries = v3[digest] if index.version == 3 else index.entries()
                for oid, place in entries.items():
                    where.setdefault(oid, (digest, *place[:3]))
            self._where = where
        return self._where

    @where.setter
    def where(self, value: dict) -> None:
        self._where = value

    @property
    def v3(self) -> dict[str, dict[str, tuple[int, int, int, int, int]]]:
        """digest -> oid -> (block, start, length, size, encoding) of each v3 pack."""
        if self._v3 is None:
            self._v3 = {}
            for digest, index in list(self.indexes.items()):
                if index.version != 3:
                    continue
                try:
                    self._v3[digest] = index.entries()
                except ValueError:  # its objects read as missing; fsck names it
                    del self.indexes[digest]
                    self.blocks.pop(digest, None)
        return self._v3

    @v3.setter
    def v3(self, value: dict) -> None:
        self._v3 = value

    def _entry(self, digest: str, oid: str) -> tuple | None:
        """The v3 entry of *oid* in pack *digest* (``None``: not there, or v1)."""
        if self._v3 is not None or digest not in self.indexes:
            return (self._v3 or {}).get(digest, {}).get(oid)
        index = self.indexes[digest]
        return index.find(oid) if index.version == 3 else None

    def typed_oids(self, kinds: set[str] | None) -> list[str]:
        found: set[str] = set()
        for digest, index in list(self.indexes.items()):
            try:
                found.update(index.oids(kinds))
            except ValueError:
                continue  # its objects read as missing; fsck names it
        return sorted(found)

    def _find(self, oid: str) -> tuple[str, int, int, int] | None:
        if self._where is not None:
            return self._where.get(oid)
        for digest, index in self.indexes.items():  # first pack by name wins, as before
            if (place := index.find(oid)) is not None:
                return (digest, *place[:3])
        return None
