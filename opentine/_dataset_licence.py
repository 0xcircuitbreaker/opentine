"""Licence and consent annotations for contributed runs (0.75).

An annotation is an **attestation** (an existing object kind) on the public
run of a contributed bundle, under the claim convention
``opentine-dataset/licence/1``::

    {"convention": "opentine-dataset/licence/1",
     "run": "run:sha256:...",            # the public run, the attestation target
     "spdx": "CC-BY-4.0",                # one SPDX licence id, no expression
     "relicensing_grant": false,         # opt-in: curators may relicense
     "contributor": "sha256:<fingerprint of the signing Ed25519 key>",
     "annotated_at": "YYYY-MM-DDTHH:MM:SSZ"}

It counts only when its Ed25519 signature holds, the payload ``signer`` and
the claim's ``contributor`` are the key that signed (``used_key_fingerprint``),
and that key also signed the bundle's ``opentine.redacted-copy`` record.

:func:`scan` is the file-level licence scan of a bundle's objects: an
``SPDX-License-Identifier:`` tag naming an id outside the allow-list, or a
proprietary notice, makes the bundle dirty. No object kind and no ``tine
verify`` code is added (docs/DATASET_CONTRIBUTORS.md).
"""

from __future__ import annotations

import re
from typing import Any

CONVENTION = "opentine-dataset/licence/1"
DEFAULT_ALLOW = (
    "CC0-1.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
    "CDLA-Permissive-2.0",
    "ODC-By-1.0",
    "MIT",
    "Apache-2.0",
)
FIELDS = ("convention", "run", "spdx", "relicensing_grant", "contributor", "annotated_at")
SPDX_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_FP = re.compile(r"sha256:[0-9a-f]{64}")
_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TAG = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+()-][A-Za-z0-9.+() -]*)")
NOTICES = (
    "all rights reserved",
    "proprietary and confidential",
    "confidential and proprietary",
    "not for redistribution",
    "do not distribute",
)


def allow_list(values: list[str] | None) -> tuple[str, ...]:
    """The allow-list: *values* when given (each a valid SPDX id), else the default."""
    if not values:
        return DEFAULT_ALLOW
    bad = [v for v in values if not SPDX_ID.fullmatch(v)]
    if bad:
        raise ValueError(f"not an SPDX licence id: {bad[0]!r}")
    return tuple(sorted(set(values)))


def check_claim(claim: Any, allow: tuple[str, ...]) -> list[str]:
    """Problems with *claim* as a licence annotation (none: valid and allowed)."""
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return [f"not an {CONVENTION} claim"]
    if set(claim) != set(FIELDS):
        return ["wrong set of fields"]
    problems = []
    if not isinstance(claim["run"], str) or not _RUN.fullmatch(claim["run"]):
        problems.append("run is a run id")
    if not isinstance(claim["spdx"], str) or not SPDX_ID.fullmatch(claim["spdx"]):
        problems.append("spdx is one SPDX licence id")
    elif claim["spdx"] not in allow:
        problems.append(f"licence {claim['spdx']} is not on the allow-list")
    if not isinstance(claim["relicensing_grant"], bool):
        problems.append("relicensing_grant is true or false")
    if not isinstance(claim["contributor"], str) or not _FP.fullmatch(claim["contributor"]):
        problems.append("contributor is a key fingerprint")
    if not isinstance(claim["annotated_at"], str) or not _AT.fullmatch(claim["annotated_at"]):
        problems.append("annotated_at is YYYY-MM-DDTHH:MM:SSZ")
    return problems


def envelope(run: str, spdx: str, grant: bool, key: Any, at: str, allow: tuple[str, ...]) -> Any:
    """The signed annotation attestation on *run*, as an object envelope (not stored)."""
    from opentine import _containment_records as records
    from opentine._v3_guards import guarded_redaction
    from opentine.attest_signing import sign_attestation
    from opentine.kernel import ObjectEnvelope

    signer = records.fingerprint(key)
    claim = {
        "convention": CONVENTION,
        "run": run,
        "spdx": spdx,
        "relicensing_grant": grant,
        "contributor": signer,
        "annotated_at": at,
    }
    problems = check_claim(claim, allow)
    if problems:
        raise ValueError(f"refusing the licence annotation: {problems[0]}")
    payload = {"claim": claim, "evidence_ids": [], "signer": signer, "target_id": run}
    payload = guarded_redaction(payload, where="v3 'attestation'")
    signature = sign_attestation(payload, key, algorithm="ed25519")
    return ObjectEnvelope.create("attestation", {**payload, "signature": signature})


def annotations(
    objects: dict[str, Any], run: str, contributor: str | None, allow: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Every licence annotation among *objects* ``{oid: envelope}`` with its state."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    out = []
    for oid, env in sorted(objects.items()):
        if env.object_type != "attestation":
            continue
        payload = env.payload()
        claim = payload.get("claim") if isinstance(payload, dict) else None
        if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
            continue
        result = verify_attestation(payload, trust_embedded=True)
        used = used_key_fingerprint(payload.get("signature"))
        problems = check_claim(claim, allow)
        if not (result.ok and result.algorithm == "ed25519" and used == payload.get("signer")):
            state = "unverified: the signature does not hold or names another key"
        elif claim.get("contributor") != used:
            state = "unverified: the contributor is not the key that signed"
        elif used != contributor:
            state = "unverified: not signed by the bundle's contributor key"
        elif payload.get("target_id") != run or claim.get("run") != run:
            state = "unverified: the annotation names another run"
        else:
            state = f"unverified: {problems[0]}" if problems else "verified"
        out.append(
            {
                "record": oid,
                "spdx": claim.get("spdx"),
                "relicensing_grant": claim.get("relicensing_grant"),
                "contributor": claim.get("contributor"),
                "state": state,
            }
        )
    return out


def _texts(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _texts(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _texts(item)


def scan(objects: dict[str, Any], allow: tuple[str, ...]) -> list[dict[str, str]]:
    """File-level licence findings in *objects*; licence annotations themselves are skipped."""
    found = []
    for oid, env in sorted(objects.items()):
        if env.encoding == "raw":
            texts = [env.body.decode("utf-8", errors="replace")]
        else:
            payload = env.payload()
            claim = payload.get("claim") if isinstance(payload, dict) else None
            if isinstance(claim, dict) and claim.get("convention") == CONVENTION:
                continue
            texts = list(_texts(payload))
        for text in texts:
            for tag in _TAG.finditer(text):
                ids = [i for i in re.split(r"[\s()]+", tag.group(1)) if i]
                ids = [i for i in ids if i not in ("AND", "OR", "WITH")]
                for spdx in ids:
                    if spdx not in allow:
                        found.append({"object": oid, "finding": f"licence tag {spdx}"})
            low = text.casefold()
            found.extend({"object": oid, "finding": f"notice: {n}"} for n in NOTICES if n in low)
    return found


__all__ = [
    "CONVENTION",
    "DEFAULT_ALLOW",
    "allow_list",
    "annotations",
    "check_claim",
    "envelope",
    "scan",
]
