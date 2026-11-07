"""``opentine-fleet/1``: which fleet member produced a run, signed and attested (0.43).

``tine fleet up`` hands every member ``OPENTINE_FLEET_ID``, ``_MEMBER``,
``_ROLE`` and (workers) ``_PARENT`` (``fleet._runner``). Capture reads them into
``metadata.fleet``::

    {"scheme": "opentine-fleet/1", "fleet_id", "member", "role", "parent"}

and, when ``OPENTINE_DELEGATION`` names a JSON file holding an
``opentine-delegation/1`` chain (``_delegation``), copies the chain into
``metadata.delegation``. Like the agent record, ``metadata.fleet`` is a claim;
:func:`sign` makes it evidence: a ``tine-sig/3`` block (``_signed_doc``) under
``opentine.fleet.v1:`` over the record bound to the run's id and digest, so a
signed record cannot be moved to another run. A malformed value is dropped,
never guessed.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine._agent_identity import normalize_name

SCHEME = "opentine-fleet/1"
SIGNED_SCHEME = "opentine-fleet-record/1"
DOMAIN = b"opentine.fleet.v1:"
FIELDS = ("fleet_id", "member", "role", "parent")
ENV = {name: "OPENTINE_FLEET_" + name.removeprefix("fleet_").upper() for name in FIELDS}
_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
MAX_CHAIN_BYTES = 1 << 16


def validate(record: Any) -> dict[str, Any]:
    """*record* checked field by field; ``ValueError`` when it is not ``opentine-fleet/1``."""
    if not isinstance(record, dict) or record.get("scheme") != SCHEME:
        raise ValueError("not an opentine-fleet/1 record")
    if set(record) != {"scheme", *FIELDS}:
        raise ValueError("an opentine-fleet/1 record has exactly scheme and " + ", ".join(FIELDS))
    for name in FIELDS:
        value = record[name]
        if not isinstance(value, str) or value != normalize_name(value):
            raise ValueError(f"fleet field {name!r} must be a normalised short string")
    if not _ID_RE.fullmatch(record["fleet_id"]):
        raise ValueError("fleet_id must be 1..128 of [A-Za-z0-9_.-]")
    return dict(record)


def from_env(environ: Any = None) -> dict[str, Any] | None:
    """The record ``OPENTINE_FLEET_*`` describes, or ``None`` (unset or malformed)."""
    env = os.environ if environ is None else environ
    if not env.get(ENV["fleet_id"]):
        return None
    record = {"scheme": SCHEME, **{name: normalize_name(env.get(ENV[name], "")) for name in FIELDS}}
    try:
        return validate(record)
    except ValueError:
        return None


def delegation_from_env(environ: Any = None) -> list[Any] | None:
    """The chain in the file ``OPENTINE_DELEGATION`` names, or ``None``."""
    env = os.environ if environ is None else environ
    path = env.get("OPENTINE_DELEGATION", "")
    if not path:
        return None
    try:
        raw = Path(path).read_bytes()[: MAX_CHAIN_BYTES + 1]
        chain = json.loads(raw) if len(raw) <= MAX_CHAIN_BYTES else None
    except (OSError, ValueError):
        return None
    if isinstance(chain, dict):  # a single certificate is a chain of one
        chain = [chain]
    return chain if isinstance(chain, list) and chain else None


def capture_metadata(environ: Any = None) -> dict[str, Any]:
    """The ``fleet`` / ``delegation`` metadata keys a capture adds (maybe none)."""
    out: dict[str, Any] = {}
    record = from_env(environ)
    if record is not None:
        out["fleet"] = record
    chain = delegation_from_env(environ)
    if chain is not None:
        out["delegation"] = chain
    return out


def run_record(run: Any) -> dict[str, Any] | None:
    """A run's validated ``metadata.fleet``, or ``None``."""
    metadata = getattr(run, "metadata", None)
    record = metadata.get("fleet") if isinstance(metadata, dict) else None
    try:
        return validate(record) if record is not None else None
    except ValueError:
        return None


def _body(document: dict[str, Any]) -> dict[str, Any]:
    return {key: document[key] for key in ("scheme", "record", "run_id", "run_digest")}


def sign(
    record: dict[str, Any], run_id: str, run_digest: str, key: Any, *, signed_at: str | None = None
) -> dict[str, Any]:
    """A signed fleet record document, bound to *run_id* and *run_digest*."""
    document = {
        "scheme": SIGNED_SCHEME,
        "record": validate(record),
        "run_id": run_id,
        "run_digest": run_digest,
    }
    document["signature"] = _signed_doc.sign(DOMAIN, document, key, signed_at=signed_at)
    return document


def verify(document: Any, public_key: Any | None = None) -> tuple[bool, str]:
    """``(ok, detail)`` for a signed fleet record; without a key the embedded one is TOFU."""
    if not isinstance(document, dict) or document.get("scheme") != SIGNED_SCHEME:
        return False, f"not an {SIGNED_SCHEME} document"
    try:
        validate(document.get("record"))
        body = _body(document)
    except (KeyError, ValueError) as exc:
        return False, str(exc)
    block = document.get("signature")
    verdict = _signed_doc.verify(DOMAIN, body, block, public_key=public_key)
    if not verdict.ok:
        return False, f"signature {verdict.state}: {verdict.reason}"
    return True, _signed_doc.basis(block, public_key)


__all__ = [
    "SCHEME",
    "SIGNED_SCHEME",
    "capture_metadata",
    "delegation_from_env",
    "from_env",
    "run_record",
    "sign",
    "validate",
    "verify",
]
