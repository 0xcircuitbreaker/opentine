"""Sign Inspect logs as they are written (0.64): a detached signature beside each log.

``sign_log(path, key)`` writes ``<log>.tine-sig.json``, an
``opentine-inspect-log-sig/1`` record: the log's file name, byte length and
SHA-256, signed with a ``tine-sig/3`` Ed25519 block over the
``opentine.inspect-log-sig.v1:`` domain. ``verify_log`` re-hashes the log and
checks the block; any edit to the log's bytes fails it.

``inspect_ai`` is optional. :func:`register` (call it from an ``inspect_ai``
hooks module, or set ``OPENTINE_INSPECT_KEY`` and import
``opentine._inspect_hook``) registers a ``Hooks`` subclass whose
``on_task_end`` signs the finished log; without ``inspect_ai`` installed it
raises ``ImportError`` and nothing else in OpenTine depends on it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine._signing_pins import key_fingerprint
from opentine._utc import rfc3339_utc

SCHEME = "opentine-inspect-log-sig/1"
DOMAIN = b"opentine.inspect-log-sig.v1:"
SUFFIX = ".tine-sig.json"
KEY_ENV = "OPENTINE_INSPECT_KEY"
MAX_LOG_BYTES = 1 << 30


def _digest(path: Path) -> tuple[str, int]:
    sha, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            size += len(chunk)
            if size > MAX_LOG_BYTES:
                raise ValueError(f"{path.name}: larger than {MAX_LOG_BYTES} bytes")
            sha.update(chunk)
    return "sha256:" + sha.hexdigest(), size


def sign_log(path: str | Path, key: Any, *, signed_at: str | None = None) -> Path:
    """Write and return the detached signature for the log at *path*."""
    from opentine._canon import atomic_write_text
    from opentine._signing_keys import load_ed25519_private

    path = Path(path)
    private = load_ed25519_private(key)
    digest, size = _digest(path)
    when = signed_at or rfc3339_utc()
    body = {"scheme": SCHEME, "log": path.name, "bytes": size, "sha256": digest,
            "signer": key_fingerprint(private.public_key().public_bytes_raw()),
            "signed_at": when}  # fmt: skip
    block = _signed_doc.sign(DOMAIN, body, private, signer=body["signer"], signed_at=when)
    record = {**body, "signature": block}
    out = path.with_name(path.name + SUFFIX)
    atomic_write_text(out, json.dumps(record, indent=2, sort_keys=True) + "\n", newline="\n")
    return out


def verify_log(path: str | Path, *, public_key: bytes | None = None) -> dict[str, Any]:
    """``{ok, reason, signer}`` for the log at *path* and its detached signature."""
    path = Path(path)
    sig_path = path.with_name(path.name + SUFFIX)
    try:
        record = json.loads(sig_path.read_bytes()[: 1 << 20].decode("utf-8"))
        body = {k: record[k] for k in ("scheme", "log", "bytes", "sha256", "signer", "signed_at")}
        block = record["signature"]
        embedded = bytes.fromhex(block["public_key"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {
            "ok": False,
            "reason": f"unreadable signature: {type(exc).__name__}",
            "signer": None,
        }
    if body["scheme"] != SCHEME or key_fingerprint(embedded) != body["signer"]:
        return {"ok": False, "reason": "not an inspect log signature", "signer": None}
    if public_key is not None and bytes(public_key) != embedded:
        return {"ok": False, "reason": "signed by another key", "signer": body["signer"]}
    result = _signed_doc.verify(DOMAIN, body, block, public_key=embedded)
    if not result.ok:
        return {"ok": False, "reason": f"signature {result.state}", "signer": body["signer"]}
    digest, size = _digest(path)
    if (digest, size, path.name) != (body["sha256"], body["bytes"], body["log"]):
        return {"ok": False, "reason": "log bytes changed since signing", "signer": body["signer"]}
    return {"ok": True, "reason": "", "signer": body["signer"]}


def _key(secret: Any) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    if isinstance(secret, (str, Path)) and Path(secret).is_file():
        return ed25519_private_from_file(secret)
    return secret


def register(key: Any | None = None) -> type:
    """Register the signing hook with ``inspect_ai`` (``ImportError`` without it)."""
    from inspect_ai.hooks import Hooks, TaskEnd, hooks  # optional dependency

    secret = key if key is not None else os.environ.get(KEY_ENV)
    if not secret:
        raise ValueError(f"pass a key or set {KEY_ENV} to a private key file")

    @hooks(name="opentine_sign_logs", description="Sign each Inspect log with an OpenTine key")
    class OpenTineSignLogs(Hooks):
        async def on_task_end(self, data: TaskEnd) -> None:
            location = getattr(getattr(data, "log", None), "location", None)
            if location and Path(location).is_file():
                sign_log(location, _key(secret))

    return OpenTineSignLogs


__all__ = ["DOMAIN", "SCHEME", "SUFFIX", "register", "sign_log", "verify_log"]
