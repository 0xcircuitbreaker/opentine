"""Interpretability artifact custody (0.83): graphs, feature dashboards and probes.

An interpretability artifact (an attribution graph, an SAE feature dashboard or
the weights of a probe) is stored as a content-addressed **blob** and named by
the ``sha256:`` digest of its bytes. It is keyed to the ``sha256:`` digest of
the checkpoint it was computed from. The record of it is an **attestation** (an
existing object kind) whose claim names the convention
``opentine.interp-artifact/1``::

    {"convention", "kind", "digest", "blob", "size", "checkpoint", "layer",
     "name", "tags", "recorded_at"}

and is kept, with its blob, by a ``custody:interp:`` hold that ``tine hold
release`` refuses, so a loop cannot delete the record or the bytes.

Custody follows the 0.72 rules. An artifact is **tagged** when its record
carries the ``model-organism`` tag, or when its own digest or its checkpoint's
digest is tagged by ``tine organism tag``; a registry that cannot be read counts
as tagged (fail closed). Reading a tagged artifact (:func:`export`) needs a
valid ``tine organism approve`` record binding that run to the artifact or to
its checkpoint; every read of a tagged artifact, allowed or refused, is held in
the ``opentine.organism-access/1`` log. Records count as signed only when the
signer is the key that signed (``used_key_fingerprint``) and as verified only
for a pinned ``runner`` key that is not an ``optimizer`` key.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from opentine import _containment_records as records

CONVENTION = "opentine.interp-artifact/1"
HOLD = "custody:interp:"
KINDS = ("attribution-graph", "sae-dashboard", "probe-weights")
TAGS = ("model-organism",)
MAX_BYTES = 256 * 1024 * 1024
MISMATCH = "digest.mismatch"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}")


class CustodyDenied(PermissionError):
    """A read of a tagged artifact without an approval bound to the run."""


class DigestMismatch(ValueError):
    """Bytes or a checkpoint that do not match a recorded digest (``digest.mismatch``)."""

    code = MISMATCH


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check(kind: str, checkpoint: str, layer: Any, name: str | None, tags: list[str],
           size: int) -> None:  # fmt: skip
    if kind not in KINDS:
        raise ValueError(f"unknown interpretability kind {kind!r}; one of {', '.join(KINDS)}")
    if not _DIGEST.fullmatch(checkpoint):
        raise ValueError("a checkpoint is named by its sha256:<64 lowercase hex> digest")
    if layer is not None and (type(layer) is not int or not 0 <= layer < 1 << 20):
        raise ValueError("a layer is a non-negative integer")
    if kind == "probe-weights" and layer is None:
        raise ValueError("probe weights name the layer they read")
    if name is not None and not _NAME.fullmatch(name):
        raise ValueError(f"name {name!r} is not [A-Za-z0-9._/@+-], 1..200 chars")
    if any(t not in TAGS for t in tags):
        raise ValueError(f"unknown tag; one of {', '.join(TAGS)}")
    if size > MAX_BYTES:
        raise ValueError(f"an interpretability artifact is at most {MAX_BYTES} bytes")


def store(repo: Any, data: bytes, *, kind: str, checkpoint: str, key: Any,
          layer: int | None = None, name: str | None = None, tags: list[str] | None = None,
          now: float | None = None) -> dict[str, Any]:  # fmt: skip
    """Store *data* as a blob, sign and hold its record; ``{"record", "claim"}``."""
    from opentine.repository._holds import edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    tags = sorted(set(tags or []))
    _check(kind, checkpoint, layer, name, tags, len(data))
    blob = repo.put("blob", bytes(data), redact=False)
    touch_links(repo, [blob])
    hexd = digest(data).removeprefix("sha256:")
    row = {"oid": blob, "target": f"{HOLD}{hexd}:blob"}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    claim = {
        "convention": CONVENTION,
        "kind": kind,
        "digest": "sha256:" + hexd,
        "blob": blob,
        "size": len(data),
        "checkpoint": checkpoint,
        "layer": layer,
        "name": name,
        "tags": tags,
        "recorded_at": records.rfc3339(time.time() if now is None else now),
    }
    target = records.anchor(repo, "interp", f"{CONVENTION} {claim['digest']}")
    oid = records.record(repo, target, claim, key, f"{HOLD}{hexd}:{blob[-16:]}")
    return {"record": oid, "claim": claim}


def _valid(claim: Any) -> bool:
    return (isinstance(claim, dict) and claim.get("convention") == CONVENTION
            and claim.get("kind") in KINDS and isinstance(claim.get("digest"), str)
            and _DIGEST.fullmatch(claim["digest"]) is not None
            and isinstance(claim.get("checkpoint"), str)
            and isinstance(claim.get("blob"), str))  # fmt: skip


def artifacts(repo: Any, checkpoint: str | None = None) -> list[dict[str, Any]]:
    """Every held record, newest digest order; each with signer and verification."""
    out = []
    for target, row in records.held(repo, HOLD):
        if target.endswith(":blob") or not _valid(row["claim"]):
            continue
        claim = row["claim"]
        if checkpoint is not None and claim["checkpoint"] != checkpoint:
            continue
        state = (
            records.role_state(repo, row["signer"], "runner")
            if row["signed"]
            else ("unverified: not signed by the key its signer field names")
        )
        out.append(
            {
                "record": row["oid"],
                "signer": row["signer"],
                "verification": state,
                **{
                    k: claim.get(k)
                    for k in (
                        "kind",
                        "digest",
                        "blob",
                        "size",
                        "checkpoint",
                        "layer",
                        "name",
                        "tags",
                        "recorded_at",
                    )
                },
            }
        )
    return sorted(out, key=lambda r: (r["digest"], r["record"]))


def find(repo: Any, artifact: str) -> dict[str, Any]:
    """The record of *artifact*; a verified one first. ``KeyError`` when none is held."""
    rows = [r for r in artifacts(repo) if r["digest"] == artifact]
    if not rows:
        raise KeyError(f"no interpretability artifact {artifact} is held")
    return sorted(rows, key=lambda r: r["verification"] != "verified")[0]


def tagged(repo: Any, row: dict[str, Any]) -> list[str]:
    """Why *row* is under model-organism custody (empty: it is not)."""
    from opentine._organism_registry import RegistryUnreadable, registry

    # Any held record of these bytes, or any artifact keyed to the same checkpoint,
    # carrying the tag counts: a second untagged record or a re-encoded copy does
    # not launder custody.
    rows = [r for r in artifacts(repo) if row["digest"] == r["digest"]
            or r["checkpoint"] == row["checkpoint"]]  # fmt: skip
    why = ["record tag"] if any("model-organism" in (r.get("tags") or []) for r in rows) else []
    try:
        known = registry(repo)
    except (RegistryUnreadable, OSError, ValueError) as exc:
        return [*why, f"registry unreadable ({exc})"]
    for what in ("digest", "checkpoint"):
        if (known.get(row[what]) or {}).get("tagged"):
            why.append(f"{what} tagged")
    return why


def read_bytes(repo: Any, row: dict[str, Any]) -> bytes:
    """The stored bytes of *row*, checked against its digest (:class:`DigestMismatch`)."""
    data = bytes(repo.get(row["blob"]).body)
    if digest(data) != row["digest"]:
        raise DigestMismatch(f"{MISMATCH}: stored bytes of {row['digest']} do not match it")
    return data


def _quorum(repo: Any, row: dict[str, Any], requester: str | None, tool: str) -> None:
    from opentine import _custody_quorum
    from opentine._organism import now
    from opentine._weight_custody_review import log_refusal

    try:
        _custody_quorum.require(repo, operation="export", digest=row["digest"],
                                checkpoint=row["checkpoint"], requester=requester)  # fmt: skip
    except _custody_quorum.QuorumError as exc:
        log_refusal(repo, row["digest"], str(exc), tool, now())
        raise CustodyDenied(str(exc)) from exc


def export(repo: Any, artifact: str, *, run: str | None = None, tool: str = "tine interp export",
           requester: str | None = None,
           quorum: bool = True) -> tuple[bytes, dict[str, Any]]:  # fmt: skip
    """The bytes of *artifact* and its record, under custody; :class:`CustodyDenied`.

    0.91: an export (*quorum*, not an internal read such as a probe calibration)
    also needs the k-of-n custodian approvals of :mod:`opentine._custody_quorum`
    for *requester* once custodian keys are pinned."""
    from opentine._organism import now
    from opentine._organism_registry import approval_for, log_access

    row = find(repo, artifact)
    if quorum:
        _quorum(repo, row, requester, tool)
    why = tagged(repo, row)
    if not why:
        return read_bytes(repo, row), row
    approval = None
    if run:
        for subject in (row["digest"], row["checkpoint"]):
            try:
                approval = approval or approval_for(repo, subject, run)
            except Exception:  # noqa: BLE001 - an unreadable approval approves nothing
                approval = None
    entry = {"artifact": row["digest"], "run": run or "", "tool": tool, "approval": approval,
             "outcome": "allowed" if approval else "refused", "at": now()}  # fmt: skip
    log_access(repo, entry)
    if not approval:
        raise CustodyDenied(f"custody.denied: {artifact} is under model-organism custody "
                            f"({', '.join(why)}); it needs a tine organism approve record "
                            "binding this run to the artifact or its checkpoint")  # fmt: skip
    return read_bytes(repo, row), row


__all__ = ["CONVENTION", "HOLD", "KINDS", "MISMATCH", "TAGS", "CustodyDenied", "DigestMismatch",
           "artifacts", "digest", "export", "find", "read_bytes", "store", "tagged"]  # fmt: skip
