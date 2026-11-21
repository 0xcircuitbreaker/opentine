"""``tine bom export``: what an AI-BOM says about one lineage node (0.78).

:func:`collect` reads a lineage folder (:mod:`opentine._lineage`) and returns a
plain model of one variant: the variant and its ancestry (each record's
artifacts, mutation run, signer and signing time), every justifying eval
(dataset digest, scorer, pass count, the keys that signed the verdicts), the
dataset versions given with ``--dataset ROLE=FILE`` (digest, signer, taint
filter, licence) and the model's licence. :mod:`opentine._aibom_cdx` and
:mod:`opentine._aibom_spdx` render that model as CycloneDX 1.6 and SPDX 3.0.1.

Nothing is trusted for being in the folder: the variant must pass
``tine lineage check`` (records signed, evals present and signed) or the export
is refused, and a dataset version must be an Ed25519-signed attestation whose
claim names a ``dataset`` digest. The model holds no wall-clock value: the
documents' times are the records' signing times, so reruns are byte-identical.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._lineage import DIGEST_RE, loads, signed
from opentine.kernel import canonical_json

ROLES = ("training", "eval")
LICENCE_MAX = 256
VERSION = "opentine.dataset-version/1"


class BomError(ValueError):
    """The export is refused (the node does not check, or an input is unusable)."""


def _verdicts(files: dict[str, bytes], digest: str) -> list[dict[str, Any]]:
    raw = files.get(f"evals/{digest[7:]}.jsonl", b"")
    return [loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def _eval(files: dict[str, bytes], row: dict[str, str]) -> dict[str, Any]:
    rows = _verdicts(files, row["eval"])
    first = rows[0] if rows else {}
    keys = ("dataset", "scorer", "scorer_version", "threshold")
    if any(not isinstance(r, dict) or any(r.get(k) != first.get(k) for k in keys)
           for r in rows):  # fmt: skip
        raise BomError(f"eval {row['eval']} has verdicts for more than one dataset or scorer")
    return {
        "eval": row["eval"],
        "verdicts_sha256": row["verdicts_sha256"],
        "dataset": first.get("dataset", ""),
        "scorer": first.get("scorer", ""),
        "scorer_version": first.get("scorer_version", ""),
        "threshold": first.get("threshold", ""),
        "items": len(rows),
        "passed": sum(1 for r in rows if r.get("passed") is True),
        "signers": sorted({r.get("signer", "") for r in rows}),
    }


def _node(files: dict[str, bytes], variant: str) -> dict[str, Any]:
    payload = loads(files[f"variants/{variant[7:]}.json"])
    claim = payload["claim"]
    return {
        "variant": variant,
        "artifacts": dict(sorted(claim["artifacts"].items())),
        "parents": list(claim["parents"]),
        "mutation_run": claim["mutation_run"],
        "signer": payload["signer"],
        "signed_at": payload["signature"].get("signed_at") or "",
        "selector": claim["selector"],
        "loop": claim["loop"],
        "policy": claim["policy"],
        "decision": (claim["decision"] or {}).get("sha256"),
        "evals": [_eval(files, row) for row in claim["evals"]],
    }


def check_licence(value: str | None) -> str | None:
    """An SPDX licence expression, kept verbatim (printable, no control characters)."""
    if value is None:
        return None
    if not value.strip() or len(value) > LICENCE_MAX or not value.isprintable():
        raise BomError("a licence is a printable SPDX expression of 1..256 characters")
    return value.strip()


def curators(repo: Path) -> set[str]:
    """Pinned ``curator`` keys that are not ``optimizer`` keys; refuses when unpinned."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(Path(repo) / ".tine")
    except KeyRoleError as exc:
        raise BomError(f"key-role policy: {exc}") from exc
    if found["status"] != "pinned":
        raise BomError("dataset versions need pinned curator keys (no owner-signed trust bundle)")
    roles = found["roles"] or {}
    return set(roles.get("curator", [])) - set(roles.get("optimizer", []))


def read_dataset(
    spec: str, counting: set[str] | None = None, current: Any = None
) -> dict[str, Any]:
    """``ROLE=FILE``: a signed dataset version attestation, as a BOM dataset entry.

    *counting* is :func:`curators`: the signer must be one of them. *current*,
    given the claim, returns the repository's verification of it now
    (``verified`` or ``unverified: why``); anything but ``verified`` is refused.
    """
    role, sep, name = spec.partition("=")
    if not sep or role not in ROLES or not name:
        raise BomError(f"--dataset takes ROLE=FILE with ROLE one of {', '.join(ROLES)}")
    raw = Path(name).read_bytes()
    try:
        payload = loads(raw)
    except ValueError as exc:
        raise BomError(f"dataset version {name} is not JSON") from exc
    claim = payload.get("claim") if isinstance(payload, dict) else None
    if not isinstance(claim, dict) or not signed(payload):
        raise BomError(f"dataset version {name} is not an Ed25519-signed attestation")
    if claim.get("convention") != VERSION:
        raise BomError(f"dataset version {name} is not an {VERSION} claim")
    from opentine._dataset_claims import offline

    found = offline(payload)  # the curation check: shape, digest, filter, curator binding
    if not found["ok"]:
        why = found["problems"][0] if found["problems"] else found["signature"]
        raise BomError(f"dataset version {name} fails its offline check: {why}")
    if payload["signer"] not in (counting or set()):
        raise BomError(f"dataset version {name} is not signed by a pinned curator key")
    state = current(claim) if current is not None else "verified"
    if state != "verified":
        raise BomError(f"dataset version {name} is {state}")
    digest = claim.get("members_digest")
    if not (isinstance(digest, str) and DIGEST_RE.fullmatch(digest)):
        raise BomError(f"dataset version {name} names no sha256: members digest")
    members = claim.get("members")
    if (
        not isinstance(members, list)
        or digest[7:] != hashlib.sha256(canonical_json(members)).hexdigest()
    ):
        raise BomError(f"dataset version {name}: members_digest is not its members' digest")
    taint = claim.get("taint_filter")
    if not isinstance(taint, dict):
        raise BomError(f"dataset version {name} records no taint filter")
    label = claim.get("name")
    return {
        "role": role,
        "dataset": digest,
        "name": label if isinstance(label, str) and label else f"dataset-{digest[7:19]}",
        "convention": str(claim.get("convention", "")),
        "record_sha256": hashlib.sha256(raw).hexdigest(),
        "signer": payload["signer"],
        "signed_at": payload["signature"].get("signed_at") or "",
        "taint_filter": taint,
        "taint_filter_sha256": None
        if taint is None
        else hashlib.sha256(canonical_json(taint)).hexdigest(),
        "licence": check_licence(
            claim.get("licence") if isinstance(claim.get("licence"), str) else None
        ),  # fmt: skip
    }


def _datasets(nodes: list[dict[str, Any]], given: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every dataset by (role, digest): the given versions, then eval datasets they miss."""
    out = {(d["role"], d["dataset"]): d for d in given}
    if len(out) != len(given):
        raise BomError("a dataset version is given twice for the same role")
    for node in nodes:
        for ev in node["evals"]:
            if DIGEST_RE.fullmatch(ev["dataset"]) and ("eval", ev["dataset"]) not in out:
                out[("eval", ev["dataset"])] = {
                    "role": "eval", "dataset": ev["dataset"],
                    "name": f"dataset-{ev['dataset'][7:19]}", "convention": "",
                    "record_sha256": None, "signer": None, "signed_at": "",
                    "taint_filter": None, "taint_filter_sha256": None, "licence": None,
                }  # fmt: skip
    return [out[k] for k in sorted(out)]


def collect(
    files: dict[str, bytes],
    row: dict[str, Any],
    *,
    name: str | None = None,
    licence: str | None = None,
    datasets: list[dict[str, Any]] = (),
) -> dict[str, Any]:
    """The BOM model of ``row["variant"]``; *row* is its ``tine lineage check`` result."""
    if not row["ok"]:
        codes = ", ".join(sorted({f["code"] for f in row["findings"]}))
        raise BomError(f"{row['variant']} does not pass tine lineage check ({codes})")
    variants = [row["variant"], *row["ancestors"]]
    nodes = [_node(files, v) for v in variants]
    return {
        "variant": row["variant"],
        "name": name or f"variant-{row['variant'][7:19]}",
        "licence": check_licence(licence),
        "signers": row["signers"],
        "nodes": nodes,
        "datasets": _datasets(nodes, list(datasets)),
    }


def used_by(node: dict[str, Any], datasets: list[dict[str, Any]], *,
            head: bool) -> list[dict[str, Any]]:  # fmt: skip
    """The datasets *node* used: training versions (the exported node only) and its evals'."""
    scored = {ev["dataset"] for ev in node["evals"]}
    return [d for d in datasets if (d["role"] == "training" and head)
            or (d["role"] == "eval" and d["dataset"] in scored)]  # fmt: skip


def digest_uuid(data: bytes) -> str:
    """A name-based UUID (version 8 layout) over *data*: stable for a stable document."""
    raw = bytearray(hashlib.sha256(data).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80
    raw[8] = (raw[8] & 0x3F) | 0x80
    h = raw.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def render(document: dict[str, Any]) -> bytes:
    """Sorted keys, two-space indent, LF, trailing newline: the bytes written."""
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


__all__ = ["ROLES", "VERSION", "BomError", "check_licence", "collect", "curators",
           "digest_uuid", "read_dataset",
           "render", "used_by"]  # fmt: skip
