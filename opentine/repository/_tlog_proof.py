"""RFC 9162 (§2.1.3, §2.1.4) inclusion and consistency proofs for ``opentine-log/1``.

Proofs are *made* from a :class:`Hashes` reader, which recovers any subtree hash
from the C2SP tlog-tiles hash tiles (``tile/<L>/<N>[.p/<W>]``) of a tree of a
given size -- so the same code proves against an opentine log directory and a
mirrored Rekor v2 tile log. Proofs are *verified* with the RFC 9162 algorithms,
which need nothing but SHA-256: no tiles, no network.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

from opentine.repository._tlog import TILE_WIDTH, LogError, _node, merkle_root, tile_path

MAX_PROOF_HASHES = 64  # 2**64 leaves: anything longer is not an RFC 9162 proof


def _split(n: int) -> int:
    """The largest power of two strictly smaller than ``n`` (``n`` >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


class Hashes:
    """Subtree hashes of a size-``size`` tree, read from its hash tiles via ``read``."""

    def __init__(self, size: int, read: Callable[[str], bytes]) -> None:
        self.size, self._read, self._cache = size, read, {}

    def _tile(self, level: int, index: int) -> bytes:
        stored = self.size >> (8 * level)
        width = min(TILE_WIDTH, stored - index * TILE_WIDTH)
        if width <= 0:
            raise LogError("tile lies beyond the tree")
        key = (level, index)
        if key not in self._cache:
            data = self._read(tile_path(level, index, width))
            if len(data) != 32 * width:
                raise LogError(f"hash tile {tile_path(level, index, width)} has the wrong size")
            self._cache[key] = data
        return self._cache[key]

    def node(self, height: int, index: int) -> bytes:
        """Hash of the full subtree of ``2**height`` leaves starting at ``index << height``."""
        tile_level, rest = divmod(height, 8)
        first = index << rest
        row = []
        for position in range(first, first + (1 << rest)):
            tile = self._tile(tile_level, position // TILE_WIDTH)
            offset = 32 * (position % TILE_WIDTH)
            row.append(tile[offset : offset + 32])
        while len(row) > 1:
            row = [_node(row[i], row[i + 1]) for i in range(0, len(row), 2)]
        return row[0]

    def range(self, lo: int, hi: int) -> bytes:
        """RFC 6962 MTH of leaves ``[lo, hi)`` (``hi`` <= ``size``)."""
        n = hi - lo
        if n <= 0 or hi > self.size:
            raise LogError("hash range is out of bounds")
        if n & (n - 1) == 0 and lo % n == 0:
            return self.node(n.bit_length() - 1, lo // n)
        k = _split(n)
        return _node(self.range(lo, lo + k), self.range(lo + k, hi))

    def root(self) -> bytes:
        return self.range(0, self.size) if self.size else merkle_root([])


def inclusion_proof(hashes: Hashes, index: int, size: int | None = None) -> list[bytes]:
    """RFC 9162 PATH(index, D[0:size])."""
    size = hashes.size if size is None else size
    if not 0 <= index < size <= hashes.size:
        raise LogError("inclusion proof index is out of range")

    def path(m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return [*path(m, lo, lo + k), hashes.range(lo + k, hi)]
        return [*path(m - k, lo + k, hi), hashes.range(lo, lo + k)]

    return path(index, 0, size)


def consistency_proof(hashes: Hashes, old: int, new: int | None = None) -> list[bytes]:
    """RFC 9162 PROOF(old, D[0:new])."""
    new = hashes.size if new is None else new
    if not 0 <= old <= new <= hashes.size:
        raise LogError("consistency proof sizes are out of range")
    if old in (0, new):
        return []

    def subproof(m: int, lo: int, hi: int, complete: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            return [] if complete else [hashes.range(lo, hi)]
        k = _split(n)
        if m <= k:
            return [*subproof(m, lo, lo + k, complete), hashes.range(lo + k, hi)]
        return [*subproof(m - k, lo + k, hi, False), hashes.range(lo, lo + k)]

    return subproof(old, 0, new, True)


def _checked(proof: list[bytes]) -> list[bytes]:
    if len(proof) > MAX_PROOF_HASHES or any(len(h) != 32 for h in proof):
        raise LogError("proof is not a list of SHA-256 hashes")
    return proof


def root_from_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes]) -> bytes:
    """RFC 9162 §2.1.3.2: the root a valid inclusion proof implies, or LogError."""
    if not 0 <= index < size:
        raise LogError("inclusion proof index is out of range")
    fn, sn, r = index, size - 1, leaf
    for p in _checked(proof):
        if sn == 0:
            raise LogError("inclusion proof is too long")
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0:
        raise LogError("inclusion proof is too short")
    return r


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> None:
    if root_from_inclusion(leaf, index, size, proof) != root:
        raise LogError("inclusion proof does not match the checkpoint root")


def verify_consistency(
    old: int, new: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> None:
    """RFC 9162 §2.1.4.2; LogError on a fork, a rollback or a bad proof."""
    proof = _checked(proof)
    if old > new:
        raise LogError(f"rollback: tree shrank from {old} to {new}")
    if old == new:
        if proof or old_root != new_root:
            raise LogError("fork: two different roots for the same tree size")
        return
    if old == 0:
        if proof:
            raise LogError("consistency proof from the empty tree must be empty")
        return
    if old & (old - 1) == 0:
        proof = [old_root, *proof]
    if not proof:
        raise LogError("consistency proof is empty")
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            raise LogError("consistency proof is too long")
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = _node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0 or fr != old_root or sr != new_root:
        raise LogError("fork: the new checkpoint is not consistent with the old one")


def encode(proof: list[bytes]) -> list[str]:
    return [base64.b64encode(h).decode("ascii") for h in proof]


def decode(proof: object) -> list[bytes]:
    if not isinstance(proof, list) or len(proof) > MAX_PROOF_HASHES:
        raise LogError("proof is not a list of base64 hashes")
    try:
        return _checked([base64.b64decode(item, validate=True) for item in proof])
    except (TypeError, ValueError) as exc:
        raise LogError("proof is not a list of base64 hashes") from exc
