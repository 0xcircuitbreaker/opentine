"""Who may sign Inspect scores (0.65): key roles for ``tine inspect import|verify``.

A self-improving loop holds its optimizer key. Without this check it could
sign its own Inspect scores as eval verdicts (``import --key``) or sign a
forged log (``inspect sign``) that ``inspect verify`` reports as fine. Roles
come only from the owner-pinned trust bundle (:mod:`opentine._key_roles_pin`);
a signer is classified as:

* ``refused``: the key holds the ``optimizer`` role (key separation; unpinned
  roles may still refuse, as everywhere else);
* ``pinned``: roles are pinned and the key holds the ``scorer`` or ``eval``
  role;
* ``unpinned``: anything else. Advisory by default (D12): ``import`` still
  signs but marks the verdicts ``unpinned``; ``verify --strict`` refuses.

A pinned owner with a bad bundle fails closed (:class:`KeyRoleError`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

PINNED, UNPINNED, REFUSED = "pinned", "unpinned", "refused"
SIGNER_ROLES = ("scorer", "eval")


class SignerRefused(ValueError):
    """The signing key may not sign Inspect scores (key separation)."""


def _store(repo_path: str | Path | None) -> Path | None:
    from opentine.repo import Repo

    if repo_path is None:
        return None
    try:
        return Path(Repo.open(repo_path).path)
    except Exception:  # noqa: BLE001 - no repository, so no key roles to apply
        return None


def classify(repo_path: str | Path | None, signer: str | None) -> dict[str, str]:
    """``{"status", "reason"}`` for *signer* (a ``sha256:`` fingerprint)."""
    from opentine._key_roles import OPTIMIZER
    from opentine._key_roles_pin import resolve

    if not signer:
        return {"status": UNPINNED, "reason": "no signer"}
    found = resolve(_store(repo_path))
    roles = found["roles"] or {}
    if signer in roles.get(OPTIMIZER, []):
        return {"status": REFUSED,
                "reason": f"inspect.key-separation: the key {signer} holds the optimizer "
                          "role: an optimizer could sign its own scorer evidence"}  # fmt: skip
    if found["status"] != "pinned":
        return {"status": UNPINNED, "reason": "the scorer role is unpinned "
                                              "(no owner-signed trust bundle)"}  # fmt: skip
    if any(signer in roles.get(role, []) for role in SIGNER_ROLES):
        return {"status": PINNED, "reason": ""}
    return {"status": UNPINNED, "reason": "the signer is not a pinned scorer or eval key"}


def check_import_key(repo_path: str | Path, key: Any) -> dict[str, str]:
    """Classify the ``import --key`` key; raise :class:`SignerRefused` when refused."""
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    private = load_ed25519_private(key)
    signer = key_fingerprint(private.public_key().public_bytes_raw())
    row = classify(repo_path, signer)
    if row["status"] == REFUSED:
        raise SignerRefused(row["reason"])
    return {"signer": signer, **row}


def require_signed(repo_path: str | Path, log: str | Path) -> dict[str, Any]:
    """``--require-signed``: the log's signature verifies and its signer is a pinned scorer."""
    from opentine._inspect_hook import verify_log

    result = verify_log(log)
    if not result["ok"]:
        raise SignerRefused(f"--require-signed: {result['reason']}")
    row = classify(repo_path, result["signer"])
    if row["status"] != PINNED:
        raise SignerRefused(f"--require-signed: {row['reason']}")
    return {**result, "signer_status": PINNED}


__all__ = ["PINNED", "REFUSED", "UNPINNED", "SignerRefused", "check_import_key", "classify",
           "require_signed"]  # fmt: skip
