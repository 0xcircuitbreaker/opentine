"""Model-organism tags (0.72): access control for trained-to-misbehave artifacts.

A model organism is a checkpoint or weight file trained to misbehave on purpose
(for alignment research). It is named by its sha256 digest only; the weights
are never stored or uploaded. Every record below is an **attestation** (an
existing object kind) on a small anchor run naming ``sha256:HEX`` (an
attestation targets a run), kept by a ``tine hold`` row whose target starts
with ``organism:`` (``tine hold release`` refuses it):

* ``opentine.organism-tag/1`` -- ``{"artifact", "names", "reason", "tagged_at"}``,
  signed by a ``policy`` or ``curator`` key of the owner-pinned key roles that
  is not an ``optimizer`` key (hold ``organism:tag:HEX``);
* ``opentine.organism-approval/1`` -- ``{"artifact", "run", "why",
  "approved_at"}``: one run may load the artifact. Signed by a pinned
  ``approver`` key holding no ``optimizer``, ``monitor`` or ``scorer`` role
  (hold ``organism:approval:HEX``);
* ``opentine.organism-untag/1`` -- ``{"artifact", "releases", "untagged_at"}``:
  ``releases`` names tag records. It takes effect only while the oversight item
  ``organism:attestation:sha256:...`` of each released tag is ``approved`` by
  the k-of-n oversight policy (0.64) (hold ``organism:untag:HEX``);
* ``opentine.organism-access/1`` -- one held blob per gated access, allowed or
  refused (hold ``organism:access:HEX``): the access log.

An artifact is tagged while any tag record names it that no effective untag
releases. A tag record that does not verify still tags (stricter is the safe
direction); ``tine organism status`` reports its verification.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from opentine import _containment_records as records
from opentine._utc import rfc3339_utc

ARTIFACT = "opentine.organism-artifact/1"
TAG = "opentine.organism-tag/1"
APPROVAL = "opentine.organism-approval/1"
UNTAG = "opentine.organism-untag/1"
ACCESS = "opentine.organism-access/1"
HOLD = "organism:"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_ROLES = ("policy", "curator")
BANNED_APPROVER = ("optimizer", "monitor", "scorer")


class OrganismError(ValueError):
    """A model-organism operation that is refused."""


def now() -> str:
    return rfc3339_utc()


def digest_of(value: str) -> str:
    """``sha256:HEX`` given as such, or the sha256 of the file at *value* (streamed)."""
    if DIGEST_RE.match(value.strip().lower()):
        return value.strip().lower()
    path = Path(value)
    if not path.is_file():
        raise OrganismError(f"{value!r} is neither a sha256:HEX digest nor a file")
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def hold_target(kind: str, artifact: str) -> str:
    return f"{HOLD}{kind}:{artifact.removeprefix('sha256:')}"


def anchor(repo: Any, artifact: str) -> str:
    """A small run the record attaches to (the artifact itself is never stored)."""
    return records.anchor(repo, "organism", f"{ARTIFACT} {artifact}")


def item(tag_record: str) -> str:
    """The oversight item an untag of *tag_record* needs approved."""
    return f"organism:{tag_record}"


def _roles(repo: Any) -> tuple[dict[str, list[str]], str]:
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        raise OrganismError(f"organism.roles: key roles: {exc}") from exc
    return found["roles"] or {}, found["status"]


def verification(repo: Any, row: dict[str, Any], roles: tuple[str, ...],
                 banned: tuple[str, ...] = ("optimizer",)) -> str:  # fmt: skip
    """``verified`` when the record is signed by a pinned key in *roles* and none of *banned*."""
    if not row["signed"]:
        return "unverified: not signed by the key its signer field names"
    try:
        held, status = _roles(repo)
    except OrganismError as exc:
        return f"unverified: {exc}"
    if status != "pinned":
        return "unverified: key roles are unpinned (no owner-signed trust bundle)"
    who = row["signer"]
    if any(who in held.get(r, []) for r in banned):
        return f"unverified: the signer holds a {'/'.join(banned)} role"
    if not any(who in held.get(r, []) for r in roles):
        return f"unverified: the signer is not a pinned {'/'.join(roles)} key"
    return "verified"


def _require(repo: Any, key: Any, roles: tuple[str, ...], banned: tuple[str, ...]) -> None:
    row = {"signed": True, "signer": records.fingerprint(key)}
    state = verification(repo, row, roles, banned)
    if state != "verified":
        raise OrganismError(f"organism.role: {row['signer']}: {state.removeprefix('unverified: ')}")


def _write(repo: Any, artifact: str, kind: str, claim: dict[str, Any], key: Any) -> str:
    return records.record(repo, anchor(repo, artifact), claim, key, hold_target(kind, artifact))


def tag(repo: Any, artifact: str, key: Any, *, names: list[str], reason: str,
        at: str | None = None) -> str:  # fmt: skip
    _require(repo, key, TAG_ROLES, ("optimizer",))
    if not DIGEST_RE.match(artifact) or not reason.strip():
        raise OrganismError("organism.tag: a sha256:HEX artifact and a --reason are required")
    clean = sorted({n.replace("\\", "/") for n in names if n.strip()})
    claim = {"convention": TAG, "artifact": artifact, "names": clean, "reason": reason,
             "tagged_at": at or now()}  # fmt: skip
    return _write(repo, artifact, "tag", claim, key)


def approve(repo: Any, artifact: str, run: str, key: Any, *, why: str,
            at: str | None = None) -> str:  # fmt: skip
    _require(repo, key, ("approver",), BANNED_APPROVER)
    if not run.strip() or not why.strip():
        raise OrganismError("organism.approve: --run and --why are required")
    if not tagged(repo, artifact)["tagged"]:
        raise OrganismError(f"organism.approve: {artifact} is not tagged")
    claim = {"convention": APPROVAL, "artifact": artifact, "run": run, "why": why,
             "approved_at": at or now()}  # fmt: skip
    return _write(repo, artifact, "approval", claim, key)


def untag(repo: Any, artifact: str, key: Any, *, at: str | None = None) -> str:
    """Release every live tag of *artifact*; each needs its oversight item approved."""
    from opentine._organism_registry import oversight_state

    _require(repo, key, TAG_ROLES, ("optimizer",))
    live = tagged(repo, artifact)["live"]
    if not live:
        raise OrganismError(f"organism.untag: {artifact} is not tagged")
    short = [t for t in live if oversight_state(repo, t) != "approved"]
    if short:
        raise OrganismError("organism.untag-unapproved: untagging needs k-of-n oversight "
                            "approval of " + ", ".join(item(t) for t in short)
                            + " (tine oversight request|approve ITEM)")  # fmt: skip
    claim = {"convention": UNTAG, "artifact": artifact, "releases": sorted(live),
             "untagged_at": at or now()}  # fmt: skip
    return _write(repo, artifact, "untag", claim, key)


def tagged(repo: Any, artifact: str) -> dict[str, Any]:
    from opentine._organism_registry import registry

    entry = registry(repo).get(artifact)
    return entry or {"tagged": False, "live": [], "tags": [], "names": []}


__all__ = ["ACCESS", "APPROVAL", "ARTIFACT", "BANNED_APPROVER", "DIGEST_RE", "HOLD",
           "OrganismError", "TAG", "TAG_ROLES", "UNTAG", "anchor", "approve", "digest_of",
           "hold_target", "item", "now", "tag", "tagged", "untag", "verification"]  # fmt: skip
