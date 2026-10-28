"""The ``opentine-agent/1`` record a harness run starts with.

Recorded at capture: the harness name, its model, the digest of the harness's
definition files in the working directory (hashed, never stored), and a fresh
per-run instance nonce. Optional environment, set by whoever launched the agent:

* ``OPENTINE_AGENT_KEY`` -- a ``tine keygen --agent`` name whose key the run
  will be signed with (its fingerprint becomes part of the ref);
* ``OPENTINE_AGENT_PARENT`` / ``OPENTINE_AGENT_PARENT_RUN`` /
  ``OPENTINE_AGENT_SPAWN_STEP`` -- a subagent's claimed parent link.

A malformed value is dropped, never guessed; a resumed run keeps its record.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

from opentine import _agent_identity as identity
from opentine._agent_definition import harness_digest
from opentine.harnesses._types import _jsonable


def _key_fpr() -> str:
    name = os.environ.get("OPENTINE_AGENT_KEY", "")
    if not name:
        return ""
    from opentine._agent_keys import key_paths
    from opentine._signing_pins import key_fingerprint

    try:
        raw = key_paths(name)[1].read_text(encoding="ascii").strip()
        return key_fingerprint(bytes.fromhex(raw))
    except (OSError, ValueError):
        return ""


def _record(name: str, model: str) -> dict[str, Any] | None:
    env = os.environ.get
    try:
        return identity.build(
            harness=name,
            model=model or "",
            definition_digest=harness_digest(name),
            key_fpr=_key_fpr(),
            instance=secrets.token_hex(16),
            parent=env("OPENTINE_AGENT_PARENT", ""),
            parent_run=env("OPENTINE_AGENT_PARENT_RUN", ""),
            spawn_step=env("OPENTINE_AGENT_SPAWN_STEP", ""),
        )
    except identity.IdentityError:
        try:
            return identity.build(harness=name, model=model or "", instance=secrets.token_hex(16))
        except identity.IdentityError:
            return None


def harness_metadata(harness: Any, context: Any, existing: Any = None) -> dict[str, Any]:
    """Run metadata for a harness capture, with its agent identity."""
    meta: dict[str, Any] = {"context": _jsonable(context or {}), "harness": harness.name}
    kept = existing.get("agent_identity") if isinstance(existing, dict) else None
    record = kept or _record(str(harness.name), str(getattr(harness, "model_info", "") or ""))
    if record is not None:
        meta["agent_identity"] = record
    return meta


__all__ = ["harness_metadata"]
