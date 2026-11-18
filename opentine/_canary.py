"""Canary registration (0.61): a holdout's planted strings, each with a declared entropy.

A canary is a string planted in a holdout so that a later copy of it, or a
model that codes it too cheaply, is evidence the holdout leaked. Registration
is a claim convention on an existing ``attestation`` (no new object kind)::

    {"convention": "opentine.integrity.canary", "canary": TEXT,
     "canary_sha256": HEX, "entropy_bits": N, "holdout": NAME | null}

filed as ``.tine/integrity/canaries/HEX.json`` with target ``sha256:HEX``.
``entropy_bits`` is the declared information content of the string: how many
bits a model that never saw it needs, at least, to code it.

A registration *counts* only when it verifies and its signer holds the
``dataset`` role, and not the ``optimizer`` role, in roles pinned by an
owner-signed trust bundle (:mod:`opentine._key_roles_pin`). Others are listed
with ``counted: false``: ``tine integrity scan`` still looks for them (finding
more never weakens a check), ``tine dataset canary-check`` does not judge by
them, so an optimizer cannot lower a declared entropy by filing its own copy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CANARIES = Path(".tine") / "integrity" / "canaries"
CONVENTION = "opentine.integrity.canary"
MIN_BYTES = 8
MAX_BYTES = 4096
MAX_ENTROPY_BITS = 8 * MAX_BYTES


class CanaryError(ValueError):
    """A canary or a registration that cannot be used."""


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _checked(text: Any, entropy_bits: Any) -> tuple[str, int]:
    if not isinstance(text, str) or "\n" in text or "\r" in text:
        raise CanaryError("a canary is one line of text")
    size = len(text.encode("utf-8"))
    if not MIN_BYTES <= size <= MAX_BYTES:
        raise CanaryError(f"a canary is {MIN_BYTES}..{MAX_BYTES} bytes, not {size}")
    if type(entropy_bits) is not int or not 1 <= entropy_bits <= min(8 * size, MAX_ENTROPY_BITS):
        raise CanaryError(f"entropy_bits is an integer in 1..{8 * size} (8 bits per byte)")
    return text, entropy_bits


def register(root: Path, key: Any, text: str, entropy_bits: int, holdout: str | None,
             at: str) -> dict[str, Any]:  # fmt: skip
    """Sign and file one canary registration; returns its listing row."""
    from opentine._integrity_run import _dump, _sign

    text, entropy_bits = _checked(text, entropy_bits)
    hexdigest = digest(text)
    claim = {"convention": CONVENTION, "canary": text, "canary_sha256": hexdigest,
             "entropy_bits": entropy_bits, "holdout": holdout}  # fmt: skip
    document = _sign(key, claim, f"sha256:{hexdigest}", at)
    path = Path(root) / CANARIES / f"{hexdigest}.json"
    _dump(path, document)
    row = _row(document, _counting_keys(Path(root)))
    assert row is not None
    return {**row, "path": path.as_posix()}


def _counting_keys(root: Path) -> set[str]:
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(root / ".tine")
    except KeyRoleError:
        return set()
    roles = (found["roles"] or {}) if found["status"] == "pinned" else {}
    return set(roles.get("dataset", [])) - set(roles.get("optimizer", []))


def _row(document: Any, counting: set[str]) -> dict[str, Any] | None:
    from opentine._integrity_run import _signer

    claim = document.get("claim") if isinstance(document, dict) else None
    if not (isinstance(claim, dict) and claim.get("convention") == CONVENTION):
        return None
    try:
        text, bits = _checked(claim.get("canary"), claim.get("entropy_bits"))
    except CanaryError:
        return None
    hexdigest = digest(text)
    if (
        claim.get("canary_sha256") != hexdigest
        or document.get("target_id") != f"sha256:{hexdigest}"
    ):
        return None
    signer = _signer(document)
    if signer is None:
        return None
    holdout = claim.get("holdout")
    return {"canary_sha256": hexdigest, "entropy_bits": bits, "bytes": len(text.encode("utf-8")),
            "holdout": holdout if isinstance(holdout, str) else None, "signer": signer,
            "counted": signer in counting, "_text": text}  # fmt: skip


def load(root: Path) -> list[dict[str, Any]]:
    """Every verifying registration, sorted by digest; ``_text`` holds the canary."""
    folder = Path(root) / CANARIES
    counting = _counting_keys(Path(root))
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            document = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        row = _row(document, counting)
        if row is not None and path.stem == row["canary_sha256"]:
            rows[(row["canary_sha256"], row["signer"])] = row
    return [rows[k] for k in sorted(rows)]


def public(row: dict[str, Any]) -> dict[str, Any]:
    """A listing row without the canary text (output never repeats a canary)."""
    return {k: v for k, v in row.items() if not k.startswith("_")}


def set_digest(rows: list[dict[str, Any]]) -> str:
    """One digest over the canary texts a scan looks for (its index key)."""
    texts = sorted({row["_text"] for row in rows})
    return hashlib.sha256("\n".join(texts).encode("utf-8")).hexdigest()


__all__ = ["CANARIES", "CONVENTION", "CanaryError", "digest", "load", "public", "register",
           "set_digest"]  # fmt: skip
