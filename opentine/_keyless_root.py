"""Keyless verification under a Sigstore ``trusted_root.json`` (``--trusted-root``).

The checks are those of ``--rekor-key``/``--fulcio-root``/``--ct-key``; only the
key choice differs: each receipt is checked under the ``tlogs`` key whose
``logId`` it names and whose ``validFor`` holds its ``integratedTime``, the chain
must end at a certificate authority valid at that verified time, and CT keys are
those valid at the leaf's ``notBefore``. When the root lists any CT log
at all, an embedded SCT from a log valid at that time is required (as Sigstore
clients do); ``--require-sct`` also fails closed when it lists none.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any

from opentine._trusted_root import TrustedRoot
from opentine.sigstore_bundle import ReceiptResult, check_entry

__all__ = ["load_root", "refuse_root_conflicts", "root_receipt", "root_scts", "trusted_root_path"]

_NO_LOG = "no tlog in --trusted-root matches the receipt's logId at its integratedTime"


def _claimed(entry: dict) -> tuple[bytes, datetime]:
    key_id = base64.b64decode(str((entry.get("logId") or {}).get("keyId")), validate=True)
    raw = entry.get("integratedTime")
    if isinstance(raw, bool) or not str(raw).isdigit():
        raise ValueError("integratedTime is malformed")
    return key_id, datetime.fromtimestamp(int(str(raw)), tz=UTC)


def root_receipt(root: TrustedRoot, envelope: dict, entries: list, signer: Any) -> ReceiptResult:
    if not entries:
        return ReceiptResult(False, "absent", "attestation carries no transparency-log receipt")
    results = []
    for entry in entries:
        try:
            key_id, when = _claimed(entry)
        except (binascii.Error, ValueError, OverflowError, OSError) as exc:
            results.append(ReceiptResult(False, "invalid", f"receipt is malformed: {exc}"))
            continue
        key = root.rekor_key(key_id, when)
        if key is None:
            results.append(ReceiptResult(False, "no-key", _NO_LOG))
            continue
        results.append(check_entry(entry, envelope, signer, key))
    return next((r for r in results if r.ok), results[0])


def root_scts(root: TrustedRoot, leaf, roots: list, *, required: bool) -> None:
    """Raise ``ValueError`` unless the SCT demand the root (or ``required``) makes holds."""
    from opentine._fulcio_sct import verify_leaf_scts

    keys = root.ct_keys(leaf.not_valid_before_utc)
    if not keys:
        if required or root.ctlogs:
            raise ValueError("--trusted-root lists no CT log valid when the certificate was issued")
        return
    verify_leaf_scts(leaf, roots, keys)


def trusted_root_path(args) -> str | None:
    """``--trusted-root``, else the opted-in TUF copy when no explicit key is given."""
    if getattr(args, "trusted_root", None):
        return args.trusted_root
    if any(getattr(args, d, None) for d in ("rekor_key", "fulcio_root", "ct_key")):
        return None
    from opentine._trusted_root import default_trusted_root

    path = default_trusted_root()
    return str(path) if path else None


def load_root(path: str, envelope: dict, entries: list, signer: Any):
    """``(TrustedRoot, receipt)``, or ``(None, ReceiptResult)`` naming why it is unreadable."""
    from opentine._trusted_root import load_trusted_root

    try:
        root = load_trusted_root(path)
    except (OSError, ValueError) as exc:
        return None, ReceiptResult(False, "no-key", f"cannot read --trusted-root: {exc}")
    return root, root_receipt(root, envelope, entries, signer)


def refuse_root_conflicts(args) -> None:
    """Usage errors: ``--trusted-root`` beside a key file, ``--require-sct`` with no CT key.

    ``--trusted-root`` never combines with ``--rekor-key``/``--fulcio-root``/``--ct-key``:
    a union would let a stray file widen a root's ``validFor``-scoped trust unseen.
    """
    from opentine._cli_common import console

    if getattr(args, "trusted_root", None):
        loose = [d for d in ("rekor_key", "fulcio_root", "ct_key") if getattr(args, d, None)]
        if loose:
            flags = ", ".join(f"--{d.replace('_', '-')}" for d in loose)
            console.print(
                f"[red]--trusted-root and {flags} cannot be combined: the trusted root "
                "already names those keys. Pass one or the other.[/]"
            )
            raise SystemExit(1)
    if getattr(args, "require_sct", False) and not getattr(args, "ct_key", None):
        if not trusted_root_path(args):
            console.print("[red]--require-sct needs --ct-key FILE: the CT log key to check[/]")
            raise SystemExit(1)
