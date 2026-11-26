"""Signed provenance sidecars for produced artifacts (0.84).

``tine provenance embed ARTIFACT --run RUN --key KEY`` writes
``ARTIFACT.provenance.json``, a signed file convention (not an object kind)::

    {"convention": "opentine.artifact-provenance/1", "subject": "artifact" |
     "model-card" | "dataset", "artifact": {"name", "media", "digest", "size"},
     "run": RUN, "pointer": "png-text" | "jpeg-comment" | "pdf-info" | null,
     "c2pa": bool, "dataset_version": ATTESTATION | null, "signer": FINGERPRINT,
     "created_at": "YYYY-MM-DDTHH:MM:SSZ", "signature": {tine-sig/3 Ed25519}}

The signature covers every field but ``signature`` under the domain
``opentine.artifact-provenance.v1:``. ``artifact.digest`` is the digest of the
canonical bytes (:mod:`opentine._artifact_trailer`), so the embedded pointer and
a C2PA manifest do not change it. The same body is signed onto the run as a held
attestation (``custody:provenance:``), and the run itself is held, so a loop
cannot delete the record or the run it names.

The signer counts only as the key that signed (``used_key_fingerprint``) and as
verified only as a pinned ``runner`` key that is not an ``optimizer`` key.
``created_at`` is now in UTC, or ``SOURCE_DATE_EPOCH`` when set.
"""

from __future__ import annotations

import re
from typing import Any

from opentine import _signed_doc

CONVENTION = "opentine.artifact-provenance/1"
DOMAIN = b"opentine.artifact-provenance.v1:"
HOLD = "custody:provenance:"
SUFFIX = ".provenance.json"
SUBJECTS = ("artifact", "model-card", "dataset")
POINTERS = ("png-text", "jpeg-comment", "pdf-info")
FIELDS = ("convention", "subject", "artifact", "run", "pointer", "c2pa", "dataset_version",
          "signer", "created_at")  # fmt: skip
MAX_SIDECAR = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_ATT = re.compile(r"attestation:sha256:[0-9a-f]{64}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_NAME = re.compile(r"[^/\\\x00-\x1f]{1,255}")


class SidecarInvalid(ValueError):
    """A sidecar that is not a well-formed ``opentine.artifact-provenance/1`` document."""


def body(doc: Any) -> dict[str, Any]:
    """The signed part of *doc*, checked field by field (:class:`SidecarInvalid`)."""
    if not isinstance(doc, dict) or set(doc) != {*FIELDS, "signature"}:
        raise SidecarInvalid(f"a sidecar has exactly the fields {', '.join(FIELDS)}, signature")
    m = {k: doc[k] for k in FIELDS}
    art = m["artifact"]
    checks = (
        (m["convention"] == CONVENTION, f"convention is {CONVENTION}"),
        (m["subject"] in SUBJECTS, f"subject is one of {', '.join(SUBJECTS)}"),
        (
            isinstance(art, dict) and set(art) == {"name", "media", "digest", "size"},
            "artifact is {name, media, digest, size}",
        ),  # fmt: skip
        (isinstance(m["run"], str) and _RUN.fullmatch(m["run"]), "run is run:sha256:<hex>"),
        (m["pointer"] is None or m["pointer"] in POINTERS, "pointer is a known slot or null"),
        (type(m["c2pa"]) is bool, "c2pa is a boolean"),
        (
            m["dataset_version"] is None
            or (isinstance(m["dataset_version"], str) and _ATT.fullmatch(m["dataset_version"])),
            "dataset_version is an attestation id",
        ),  # fmt: skip
        (isinstance(m["signer"], str) and _DIGEST.fullmatch(m["signer"]), "signer is sha256:"),
        (
            isinstance(m["created_at"], str) and _TIME.fullmatch(m["created_at"]),
            "created_at is YYYY-MM-DDTHH:MM:SSZ",
        ),  # fmt: skip
    )
    for ok, why in checks:
        if not ok:
            raise SidecarInvalid(why)
    if not (isinstance(art["name"], str) and _NAME.fullmatch(art["name"])
            and art["media"] in ("png", "jpeg", "pdf", "other")
            and isinstance(art["digest"], str) and _DIGEST.fullmatch(art["digest"])
            and type(art["size"]) is int and art["size"] >= 0):  # fmt: skip
        raise SidecarInvalid("artifact fields are malformed")
    return m


def make(private_key: Any, **fields: Any) -> dict[str, Any]:
    """A signed sidecar; the signer is the signing key's fingerprint."""
    from opentine._containment_records import fingerprint
    from opentine._provenance_v4 import upgraded_at

    doc = {"convention": CONVENTION, "created_at": upgraded_at(), **fields,
           "signer": fingerprint(private_key), "signature": None}  # fmt: skip
    checked = body(doc)
    doc["signature"] = _signed_doc.sign(DOMAIN, checked, private_key, signer=checked["signer"],
                                        signed_at=checked["created_at"])  # fmt: skip
    return doc


def signature_ok(doc: dict[str, Any]) -> tuple[bool, str]:
    """Whether the signature verifies and was made by the key ``signer`` names."""
    from opentine._signing_pins import used_key_fingerprint

    checked = body(doc)
    block = doc.get("signature")
    if used_key_fingerprint(block) != checked["signer"]:
        return False, "the signer field does not name the key that signed"
    result = _signed_doc.verify(DOMAIN, checked, block)
    return (True, "ok") if result.ok else (False, f"signature {result.state}")


def record(repo: Any, doc: dict[str, Any], key: Any) -> str:
    """Sign the sidecar body onto its run as a held attestation; hold the run too."""
    from opentine import _containment_records as records
    from opentine.repository._holds import edit_holds, holds_path

    checked = body(doc)
    hexd = checked["artifact"]["digest"].removeprefix("sha256:")
    row = {"oid": checked["run"], "target": f"{HOLD}{hexd}:run"}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    claim = {k: v for k, v in checked.items() if k not in ("signer",)}
    return records.record(repo, checked["run"], claim, key, f"{HOLD}{hexd}:{checked['run'][-16:]}")


def held(repo: Any, artifact_digest: str) -> list[dict[str, Any]]:
    """The held records for *artifact_digest* whose signature binds their signer."""
    from opentine import _containment_records as records

    prefix = f"{HOLD}{artifact_digest.removeprefix('sha256:')}:"
    return [row for target, row in records.held(repo, prefix)
            if not target.endswith(":run") and row["signed"] and row["claim"]
            and row["claim"].get("convention") == CONVENTION]  # fmt: skip


__all__ = ["CONVENTION", "DOMAIN", "HOLD", "POINTERS", "SUBJECTS", "SUFFIX", "SidecarInvalid",
           "body", "held", "make", "record", "signature_ok"]  # fmt: skip
