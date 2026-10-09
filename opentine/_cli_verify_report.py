"""What ``tine verify`` reports about a signature beyond the verdict itself.

* ``tine verify RUN`` with no key flag printed ``OK … sha256:…`` for a signed
  artifact without saying the signature was never checked, which reads as
  "authentic". The unarmed verdict (``no-key`` for a present block) is now
  reported as *present but not checked*, and the JSON says so.
* Every Ed25519 verdict names its key by fingerprint (``_signing_pins``), so a
  trust-on-first-use check can at least be compared, and pinned.

The JSON object is ``_cli_json.emit_verify``'s, with three additions:
``signature.key_fingerprint``, and top-level ``signature_present`` and
``signature_checked``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine._artifact_io import read_artifact_json
from opentine._cli_json import emit
from opentine.core import Run


def signature_block(path: str | Path) -> Any:
    """The artifact's stored signature block, or ``None`` if it has none or is unreadable."""
    try:
        data = read_artifact_json(path)
    except (OSError, RecursionError, ValueError):
        return None
    metadata = data.get("metadata") if isinstance(data, dict) else None
    integrity = metadata.get("integrity") if isinstance(metadata, dict) else None
    return integrity.get("signature") if isinstance(integrity, dict) else None


def unchecked_signature(path: str | Path):
    """The unarmed verdict when the artifact carries a signature block, else ``None``."""
    result = Run.verify_signature(path)
    return None if result.state == "unsigned" else result


def emit_verify(
    target: str | Path,
    integrity: Any,
    signature: Any,
    *,
    fingerprint: str | None = None,
    unchecked: Any = None,
) -> None:
    present = signature is not None or unchecked is not None
    emit(
        {
            "command": "verify",
            "path": str(target),
            "ok": bool(integrity.ok and (signature is None or signature.ok)),
            "integrity": {
                "ok": bool(integrity.ok),
                "algorithm": integrity.algorithm,
                "expected": integrity.expected,
                "actual": integrity.actual,
                "reason": integrity.reason,
                "draft": bool(integrity.draft),
            },
            "signature_present": present and (signature is None or signature.state != "unsigned"),
            "signature_checked": signature is not None,
            "signature": None
            if signature is None
            else {
                "ok": bool(signature.ok),
                "state": signature.state,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
                "signer": signature.signer,
                "signed_at": signature.signed_at,
                "key_fingerprint": fingerprint,
                "reason": signature.reason,
            },
        }
    )


__all__ = ["emit_verify", "signature_block", "unchecked_signature"]
