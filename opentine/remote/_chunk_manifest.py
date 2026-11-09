"""The chunk manifest: how a chunked object is stored (a stored form, not a kind).

Layout (all integers big-endian)::

    b"TINECDC1"  total_size:u64  count:u32  { sha256:32  size:u32 } * count

The manifest is sealed like any object body, then prefixed with ``MARKER`` so
a reader can tell it from a whole sealed object (``TINEAES3``/``TINEAES4``)
without decrypting. The oid is unchanged: it still names the envelope bytes,
and readers re-hash them after joining the chunks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MAGIC = b"TINECDC1"
#: Prefix of a stored object whose sealed body is a manifest.
MARKER = b"TINECDCM"
MAX_CHUNKS = 1 << 20
_ENTRY = 36


@dataclass(frozen=True)
class Manifest:
    total: int
    chunks: tuple[tuple[str, int], ...]  # (sha256 hex, size)

    @classmethod
    def of(cls, pieces: list[bytes]) -> Manifest:
        entries = tuple((hashlib.sha256(p).hexdigest(), len(p)) for p in pieces)
        return cls(sum(size for _, size in entries), entries)

    def encode(self) -> bytes:
        out = bytearray(MAGIC)
        out += self.total.to_bytes(8, "big") + len(self.chunks).to_bytes(4, "big")
        for digest, size in self.chunks:
            out += bytes.fromhex(digest) + size.to_bytes(4, "big")
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Manifest:
        if len(data) < 20 or not data.startswith(MAGIC):
            raise ValueError("not a chunk manifest")
        total = int.from_bytes(data[8:16], "big")
        count = int.from_bytes(data[16:20], "big")
        if count > MAX_CHUNKS or len(data) != 20 + count * _ENTRY:
            raise ValueError("chunk manifest has the wrong length")
        entries = []
        for index in range(count):
            at = 20 + index * _ENTRY
            size = int.from_bytes(data[at + 32 : at + 36], "big")
            entries.append((data[at : at + 32].hex(), size))
        if sum(size for _, size in entries) != total or any(s <= 0 for _, s in entries):
            raise ValueError("chunk manifest sizes do not add up")
        return cls(total, tuple(entries))

    def span(self, start: int, length: int) -> list[tuple[int, str, int, int]]:
        """Chunks touching ``[start, start+length)`` as (index, digest, offset, size)."""
        out, offset = [], 0
        stop = start + length
        for index, (digest, size) in enumerate(self.chunks):
            if offset < stop and offset + size > start:
                out.append((index, digest, offset, size))
            offset += size
            if offset >= stop:
                break
        return out


def verified(digest: str, data: bytes) -> bytes:
    """*data* when it hashes to *digest*; ``ValueError`` otherwise."""
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"chunk {digest[:12]} does not match its digest")
    return data
