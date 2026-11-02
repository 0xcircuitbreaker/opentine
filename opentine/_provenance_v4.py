"""``upgraded_from``: where a format v4 run came from (SPEC 9.3, 9.9).

The record lives *inside* the v3 run payload, so the run oid -- the v4 root --
and every ``tine-sig/3`` over it cover it. It is optional: a run without it
hashes exactly as before, and the v3 reader ignores keys it does not use, so
older readers and the repository validators accept it unchanged.

Shape::

    {"format": "tine/1"|"tine/2"|"tine-repo/3", "digest_algorithm": "sha256",
     "digest": <hex of the source bytes after TINEZ1 unwrap, or the v3 run oid>,
     "integrity_digest": <v2 3.5 digest or null>,
     "signature": {"scheme", "state", "key_fingerprint", "trust_basis"},
     "upgraded_at": <ISO 8601>, "tool": "opentine/<version>"}

The signature block records what ``verify_artifact`` said *at upgrade time*: a
claim the upgrader makes, never re-checked by a reader without the source.

Imports nothing from ``graph`` or ``repository``.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import Any

FORMATS = ("tine/1", "tine/2", "tine-repo/3")
REPO_FORMAT = "tine-repo/3"
KEYS = frozenset(
    {"digest", "digest_algorithm", "format", "integrity_digest", "signature", "tool"}
    | {"upgraded_at"}
)
SIGNATURE_KEYS = frozenset({"key_fingerprint", "scheme", "state", "trust_basis"})
#: The 4.7 states, plus ``not-applicable`` for a repository source (no file signature).
STATES = frozenset(
    {"verified", "verified-tofu", "unsigned", "no-key", "mismatch", "error", "not-applicable"}
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_OID = re.compile(r"^run:sha256:[0-9a-f]{64}$")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_SHORT = 512


def _text(value: Any, *, nullable: bool = True) -> bool:
    if value is None:
        return nullable
    return isinstance(value, str) and len(value) <= _SHORT


def valid_upgraded_from(value: Any) -> bool:
    """True when *value* is a well-formed ``upgraded_from`` record."""
    if not isinstance(value, dict) or set(value) != KEYS:
        return False
    fmt, digest = value["format"], value["digest"]
    if fmt not in FORMATS or value["digest_algorithm"] != "sha256":
        return False
    pattern = _RUN_OID if fmt == REPO_FORMAT else _HEX64
    if not isinstance(digest, str) or not pattern.match(digest):
        return False
    integrity = value["integrity_digest"]
    if integrity is not None and not (isinstance(integrity, str) and _HEX64.match(integrity)):
        return False
    stamp, tool = value["upgraded_at"], value["tool"]
    if not isinstance(stamp, str) or not _ISO.match(stamp):
        return False
    if not (_text(tool, nullable=False) and tool.startswith("opentine/")):
        return False
    block = value["signature"]
    if not isinstance(block, dict) or set(block) != SIGNATURE_KEYS:
        return False
    return (
        block["state"] in STATES
        and _text(block["scheme"])
        and _text(block["key_fingerprint"])
        and _text(block["trust_basis"], nullable=False)
    )


def require_upgraded_from(value: Any) -> dict[str, Any]:
    if not valid_upgraded_from(value):
        raise ValueError("run upgraded_from is malformed (SPEC 9.9)")
    return value


def upgraded_at() -> str:
    """Now in UTC, or ``SOURCE_DATE_EPOCH`` when set, so upgrades can be reproducible."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    moment = datetime.fromtimestamp(int(epoch), UTC) if epoch.isdigit() else datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(
    fmt: str,
    digest: str,
    *,
    integrity_digest: str | None,
    scheme: str | None,
    state: str,
    key_fingerprint: str | None,
    trust_basis: str,
) -> dict[str, Any]:
    """One validated ``upgraded_from`` record stamped with this tool and time."""
    from opentine._version import __version__

    integrity = integrity_digest if isinstance(integrity_digest, str) else None
    if integrity is not None and not _HEX64.match(integrity):
        integrity = None  # a malformed recorded digest is not carried as a claim
    return require_upgraded_from(
        {
            "digest": digest,
            "digest_algorithm": "sha256",
            "format": fmt,
            "integrity_digest": integrity,
            "signature": {
                "key_fingerprint": key_fingerprint,
                "scheme": scheme if isinstance(scheme, str) else None,
                "state": state,
                "trust_basis": trust_basis,
            },
            "tool": f"opentine/{__version__}",
            "upgraded_at": upgraded_at(),
        }
    )


def recorded(payload: Any) -> dict[str, Any] | None:
    """The ``upgraded_from`` record of a run payload, or ``None``."""
    value = payload.get("upgraded_from") if isinstance(payload, dict) else None
    return value if valid_upgraded_from(value) else None


__all__ = [
    "FORMATS",
    "REPO_FORMAT",
    "build",
    "recorded",
    "require_upgraded_from",
    "upgraded_at",
    "valid_upgraded_from",
]
