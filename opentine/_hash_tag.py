"""The reserved hash-algorithm tag of a typed object id (SPEC 1.3.1, 0.41, X29).

An oid is ``TYPE ":" HASH ":" HEX``. Every format so far has exactly one
``HASH``, ``sha256``, and ``kernel.OID_RE`` accepts nothing else. The middle
field is the reserved tag: a future format may mint ``sha3-256`` or ``blake3``
oids, but the tag is part of the oid (it is never negotiated), and a reader
that does not implement an algorithm refuses the oid rather than guessing.

The kernel's refusal of such an oid is generic ("invalid typed object id"),
and the kernel is held to its line budget, so this wrapper adds the clear
error: ``parse_oid`` here raises :class:`UnsupportedHashAlgorithm` -- still a
``KernelError`` -- naming the algorithm.
"""

from __future__ import annotations

import re

from opentine.kernel import KernelError
from opentine.kernel import parse_oid as _kernel_parse_oid

#: Algorithms this reader computes. The oid's tag must be one of them.
SUPPORTED_HASH_ALGORITHMS = ("sha256",)
#: Tags reserved for a future format; never valid today, refused by name.
RESERVED_HASH_ALGORITHMS = ("sha3-256", "sha512", "blake3")
_TAGGED = re.compile(r"(blob|event|run|attestation|annotation):([a-z0-9][a-z0-9-]{0,31}):[0-9a-f]+")


class UnsupportedHashAlgorithm(KernelError):
    """A well-formed tagged oid whose hash algorithm this reader does not implement."""


def hash_tag(oid: object) -> str | None:
    """The hash-algorithm tag of a ``TYPE:TAG:HEX`` string, or ``None``."""
    match = _TAGGED.fullmatch(oid) if isinstance(oid, str) else None
    return match.group(2) if match else None


def parse_oid(oid: str) -> tuple[str, str]:
    """``kernel.parse_oid``, with a clear error for an unsupported hash tag."""
    try:
        return _kernel_parse_oid(oid)
    except KernelError:
        tag = hash_tag(oid)
        if tag is None or tag in SUPPORTED_HASH_ALGORITHMS:
            raise
        kind = "reserved" if tag in RESERVED_HASH_ALGORITHMS else "unknown"
        raise UnsupportedHashAlgorithm(
            f"unsupported hash algorithm {tag!r} in object id {oid!r}: the tag is {kind}, "
            f"and this reader implements only {', '.join(SUPPORTED_HASH_ALGORITHMS)} "
            "(SPEC 1.3.1)"
        ) from None


__all__ = [
    "RESERVED_HASH_ALGORITHMS",
    "SUPPORTED_HASH_ALGORITHMS",
    "UnsupportedHashAlgorithm",
    "hash_tag",
    "parse_oid",
]
