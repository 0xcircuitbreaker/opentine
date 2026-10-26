"""The trust state of a run's actions: unsigned, verified, mismatch or unknown-key.

Every state is recomputed from the run and its stored ``tine-actions/1``
manifest; nothing here reads a cached verdict, so a forged row in the action
index cannot make a run look verified.

* ``unsigned``    -- no manifest, or a manifest without a signature.
* ``mismatch``    -- the manifest does not match what this run produces (edited,
  truncated, or moved from another run), the signature disagrees, or the key is
  not the one the run's identity names.
* ``unknown-key`` -- a valid signature by a key nobody pinned or supplied.
* ``verified``    -- a valid signature by a supplied key, a pinned key, or one
  of this user's own agent keys.

Manifests live beside the runs, named by a hash of the run id (never by the id
itself, which is untrusted text): ``<base>/<sha256(run id)>.json``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentine import _actions_manifest as manifest_mod
from opentine._canon import atomic_write_text
from opentine._signing_pins import used_key_fingerprint
from opentine._signing_verify import verify_block
from opentine.kernel import KernelError, canonical_json, validate_json_shape

STATES = ("unsigned", "verified", "mismatch", "unknown-key")
MAX_MANIFEST_BYTES = 16 << 20


@dataclass(frozen=True)
class Trust:
    state: str
    reason: str
    key: str | None = None

    @property
    def verified(self) -> bool:
        return self.state == "verified"


def manifest_path(base: Path, run_id: str) -> Path:
    return Path(base) / (hashlib.sha256(run_id.encode("utf-8")).hexdigest() + ".json")


def save_manifest(base: Path, manifest: dict[str, Any]) -> Path:
    path = manifest_path(base, manifest["body"]["run_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, canonical_json(manifest).decode("utf-8") + "\n")
    return path


def load_manifest(base: Path | None, run_id: str) -> Any:
    """The stored manifest for *run_id*, ``None`` if absent, ``False`` if unreadable."""
    if base is None:
        return None
    path = manifest_path(base, run_id)
    try:
        if path.is_symlink():
            return False
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return False
    try:
        if len(raw) > MAX_MANIFEST_BYTES:
            return False
        validate_json_shape(raw, max_tokens=2_000_000)
        return json.loads(raw)
    except (KernelError, ValueError, RecursionError):
        return False


def _same(left: Any, right: Any) -> bool:
    try:
        return canonical_json(left) == canonical_json(right)
    except (KernelError, TypeError, ValueError):
        return False


def verify(
    stored: Any,
    run: Any,
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    pins: frozenset[str] = frozenset(),
) -> Trust:
    """The trust state of *run* given its *stored* manifest (fail-closed)."""
    if stored is None:
        return Trust("unsigned", "no action manifest")
    if not isinstance(stored, dict) or not isinstance(stored.get("body"), dict):
        return Trust("mismatch", "action manifest is unreadable or malformed")
    try:
        body = manifest_mod.build_body(run)
    except Exception:
        return Trust("mismatch", "run actions cannot be recomputed")
    claimed = stored["body"]
    if claimed.get("run_id") != body["run_id"] or claimed.get("run_digest") != body["run_digest"]:
        return Trust("mismatch", "manifest is bound to a different run")
    if not _same(claimed, body):
        return Trust("mismatch", "manifest does not match the run's actions or identity")
    block = stored.get("signature")
    if block is None:
        return Trust("unsigned", "action manifest is not signed")
    if not isinstance(block, dict) or block.get("signer") != body["agent_ref"]:
        return Trust("mismatch", "signature names another agent")
    result = verify_block(
        block,
        lambda header: manifest_mod.signed_message(body, header),
        schemes=manifest_mod.SCHEMES,
        subject="action manifest",
        hmac_key=hmac_key,
        public_key=public_key,
        trust_embedded=hmac_key is None and public_key is None,
    )
    fpr = used_key_fingerprint(block, public_key)
    if not result.ok:
        state = "unknown-key" if result.state == "no-key" else "mismatch"
        return Trust(state, result.reason, fpr)
    record = body["identity"] or {}
    if record.get("key_fpr") and record["key_fpr"] != fpr:
        return Trust("mismatch", "signed by a key other than the agent identity's", fpr)
    if result.state == "verified" or fpr in pins:
        return Trust("verified", "ok", fpr)
    return Trust("unknown-key", "valid signature by a key that is not pinned", fpr)


__all__ = ["STATES", "Trust", "load_manifest", "manifest_path", "save_manifest", "verify"]
