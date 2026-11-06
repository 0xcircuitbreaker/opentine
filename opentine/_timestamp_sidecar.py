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

0.39 (X20): ``bound`` may instead be ``sig:sha256:<hex>``, the SHA-256 of one
stored signature block's canonical JSON. Such a token covers that signature,
not just the content, so its genTime is the *verified signing time*: the
signature existed by then. Root-bound tokens keep verifying as before.
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
SIG_PREFIX = "sig:sha256:"


def sidecar_path(run_path: Path) -> Path:
    return run_path.with_name(run_path.name + SUFFIX)


def bound_string(result: object) -> str | None:
    """The digest a token binds to, from a ``Run.verify_integrity`` result."""
    actual = getattr(result, "actual", None)
    if not getattr(result, "ok", False) or not isinstance(actual, str) or not actual:
        return None
    return actual if actual.startswith("run:") else f"sha256:{actual}"


def signature_bound(block: object) -> str:
    """``sig:sha256:<hex>`` of one signature block's canonical JSON."""
    import hashlib

    return SIG_PREFIX + hashlib.sha256(canonical_json(block)).hexdigest()


def signature_bounds(run_path: Path) -> list[str]:
    """The ``sig:`` binding of every signature block the run file stores, in order."""
    from opentine._artifact_io import artifact_integrity, read_artifact_json
    from opentine._format_v4 import is_v4_artifact

    try:
        data = read_artifact_json(run_path)
    except (OSError, RecursionError, ValueError):
        return []
    if is_v4_artifact(data):
        blocks = data.get("signatures")
        blocks = blocks if isinstance(blocks, list) else []
    else:
        integrity = artifact_integrity(data) if isinstance(data, dict) else None
        blocks = [integrity.get("signature")] if integrity else []
    out = []
    for block in blocks:
        if isinstance(block, dict):
            try:
                out.append(signature_bound(block))
            except ValueError:
                continue
    return out


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


__all__ = [
    "KIND",
    "SIG_PREFIX",
    "attach",
    "bound_string",
    "load",
    "sidecar_path",
    "signature_bound",
    "signature_bounds",
]
