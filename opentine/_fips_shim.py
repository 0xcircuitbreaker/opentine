"""Keep ``import opentine`` working on a FIPS-only Python.

Under an OpenSSL FIPS provider with no default provider, ``hashlib`` has no
``md5`` attribute at all. httpx builds its Digest-auth table from
``hashlib.md5`` at import time, so every module that imports httpx would fail.
OpenTine never uses MD5; this installs a stand-in that refuses when called, so
only an actual MD5 use (HTTP Digest auth) fails, and it fails loudly.
"""

from __future__ import annotations

import hashlib


def _md5_unavailable(*_args: object, **_kwargs: object) -> None:
    raise ValueError("md5 is not available under the OpenSSL FIPS provider")


def install() -> bool:
    """Add the stand-in when ``hashlib.md5`` is missing; True if it was added."""
    if hasattr(hashlib, "md5"):
        return False
    hashlib.md5 = _md5_unavailable  # type: ignore[attr-defined]
    return True


install()
