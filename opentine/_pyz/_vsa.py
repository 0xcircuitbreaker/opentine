"""SPEC 8.17: check a remote's signed SLSA VSA, stdlib only (0.46).

The pyz runs the vendored :mod:`opentine._vsa_verify` (copied verbatim into the
archive) with Ed25519 from the pure-Python :mod:`._ed25519` instead of
``cryptography``. Returns the class instead of raising.
"""

from __future__ import annotations

from typing import Any

from .. import _vsa_verify  # tine_verify._vsa_verify in the pyz, opentine's in the tree
from . import _ed25519


def _verify(key: bytes, sig: bytes, message: bytes) -> bool:
    try:
        return _ed25519.verify(key, message, sig)
    except ValueError:
        return False


def verify_case(value: dict[str, Any]) -> dict[str, Any]:
    """A conformance ``vsa.verify`` input -> ``{"ok", "class"}``."""
    return _vsa_verify.verify_case(value, verify=_verify)


__all__ = ["verify_case"]
