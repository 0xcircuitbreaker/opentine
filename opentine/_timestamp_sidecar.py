"""RFC 3161 timestamp tokens kept beside a run file, bound to its digest (0.31.0).

A token for ``run.tine`` lives in ``run.tine.timestamps.json``:

    {"entries": [{"bound": "<digest string>", "token": "<base64 DER>"}, ...],
     "kind": "tine-timestamp-sidecar/1"}

canonical JSON, at most :data:`MAX_ENTRIES` entries. ``bound`` is the run's
digest exactly as ``tine verify`` recomputes it -- ``sha256:<hex>`` for a v2/v3
file, the root oid ``run:sha256:<hex>`` for v4 -- and the token's
messageImprint is the hash of those UTF-8 bytes. ``tine timestamp data RUN``
prints them so a TSA query can be built (``openssl ts -query -data``);
fetching the token is the user's job, and opentine never contacts a TSA.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path

from opentine.kernel import canonical_json

KIND = "tine-timestamp-sidecar/1"
SUFFIX = ".timestamps.json"
MAX_ENTRIES = 16
MAX_BYTES = 1024 * 1024


def sidecar_path(run_path: Path) -> Path:
    return run_path.with_name(run_path.name + SUFFIX)


def bound_string(result: object) -> str | None:
    """The digest a token binds to, from a ``Run.verify_integrity`` result."""
    actual = getattr(result, "actual", None)
    if not getattr(result, "ok", False) or not isinstance(actual, str) or not actual:
        return None
    return actual if actual.startswith("run:") else f"sha256:{actual}"


def load(run_path: Path) -> list[tuple[str, bytes]]:
    """Every ``(bound, token DER)``; ``ValueError`` when the sidecar is malformed."""
    path = sidecar_path(run_path)
    if not path.is_file():
        return []
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{path.name} exceeds {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw)
        entries = doc["entries"] if doc.get("kind") == KIND else None
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise ValueError
        return [
            (e["bound"], base64.b64decode(e["token"], validate=True))
            for e in entries
            if isinstance(e["bound"], str)
        ]
    except (AttributeError, KeyError, TypeError, ValueError, binascii.Error, RecursionError):
        raise ValueError(f"{path.name} is malformed") from None


def attach(run_path: Path, bound: str, token: bytes) -> bool:
    """Append *token* for *bound*; ``False`` if it is already stored."""
    entries = load(run_path)
    if (bound, token) in entries:
        return False
    entries.append((bound, token))
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"a run holds at most {MAX_ENTRIES} timestamp tokens")
    document = {
        "entries": [{"bound": b, "token": base64.b64encode(t).decode("ascii")} for b, t in entries],
        "kind": KIND,
    }
    from opentine.repository._paths import atomic_bytes

    atomic_bytes(sidecar_path(run_path), canonical_json(document) + b"\n")
    return True


__all__ = ["KIND", "attach", "bound_string", "load", "sidecar_path"]
