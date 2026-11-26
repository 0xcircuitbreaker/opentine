"""JSON Schemas for artifact provenance (0.84).

``tine-cli-provenance-1`` is the ``tine provenance ... --json`` output. The
sidecar ``opentine-artifact-provenance-1`` is a signed file convention whose
body is also a claim on an attestation (an existing object kind), not an object
kind (docs/PROVENANCE.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-provenance/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_RUN = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_POINTER = opt({"enum": ["png-text", "jpeg-comment", "pdf-info"]})
_TIME = {"type": "string", "pattern": "^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$"}
_SUBJECT = {"enum": ["artifact", "model-card", "dataset"]}
_CODES = ["artifact.sidecar-missing", "artifact.sidecar-invalid", "artifact.bad-signature",
          "artifact.signer-unverified", "artifact.digest-mismatch", "artifact.pointer-stripped",
          "artifact.pointer-repointed", "artifact.run-missing", "artifact.c2pa-invalid",
          "artifact.c2pa-stripped", "artifact.dataset-version-unknown"]  # fmt: skip
_FINDING = closed(["code", "message"], {"code": {"enum": _CODES}, "message": STR})
_ARTIFACT = closed(["name", "media", "digest", "size"], {
    "name": STR, "media": {"enum": ["png", "jpeg", "pdf", "other"]}, "digest": _DIGEST,
    "size": INT})  # fmt: skip
_SIDECAR = {"subject": _SUBJECT, "artifact": _ARTIFACT, "run": _RUN, "pointer": _POINTER,
            "c2pa": opt(_DIGEST), "dataset_version": opt(_ATT),
            "created_at": _TIME}  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "artifact", "sidecar", "record", "digest", "run", "pointer",
            "c2pa", "subject", "signer"], {
        **_HEAD, "command": {"const": "provenance embed"}, "artifact": STR, "sidecar": STR,
        "record": _ATT, "digest": _DIGEST, "run": _RUN, "pointer": _POINTER, "c2pa": BOOL,
        "subject": _SUBJECT, "signer": _DIGEST}),
    closed(["command", "schema", "ok", "artifact", "sidecar", "digest", "run", "signer",
            "verification", "pointer", "c2pa", "held", "findings"], {
        **_HEAD, "command": {"const": "provenance verify"}, "ok": BOOL, "artifact": STR,
        "sidecar": STR, "digest": opt(_DIGEST), "run": opt(_RUN), "signer": opt(STR),
        "verification": opt(STR), "pointer": _POINTER,
        "c2pa": opt({"enum": ["absent", "unchecked", "valid", "invalid"]}), "held": BOOL,
        "findings": {"type": "array", "items": _FINDING}}),
]  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-provenance-1": doc("tine-cli-provenance-1", "tine provenance ... --json",
        "Embedding a run pointer and signed sidecar in a produced artifact, and checking it.",
        {"anyOf": _SHAPES}),
    "opentine-artifact-provenance-1": doc("opentine-artifact-provenance-1",
        "opentine.artifact-provenance/1 sidecar",
        "A signed sidecar binding an artifact's canonical digest to the run that produced it. "
        "A signed file convention, also held as an attestation claim; not an object kind.",
        closed(["convention", *_SIDECAR, "signer", "signature"], {
            "convention": {"const": "opentine.artifact-provenance/1"}, **_SIDECAR,
            "signer": _DIGEST, "signature": {"type": "object"}})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"provenance {verb}": "tine-cli-provenance-1" for verb in ("embed", "verify")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
