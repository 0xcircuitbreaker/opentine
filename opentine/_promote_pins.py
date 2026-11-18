"""What pins a promotion to its inputs (0.57): signed policy, bound approvals, loop.

* **Signed policy.** When the key roles name a ``policy`` role (0.59: from an
  owner-signed trust bundle, :mod:`opentine._key_roles_pin`; a ``policy`` role
  in an unsigned ``.tine/key-roles.toml`` alone refuses every policy),
  ``tine promote`` accepts only a ``[promote]`` policy (and the label admission
  policy it names) covered by an attestation whose claim follows
  ``opentine.promotion-policy/1``::

      {"schema": "opentine.promotion-policy/1", "policy_sha256": HEX,
       "label_policy_sha256": HEX}

  signed with Ed25519 by a ``policy``-role key that is neither the promoting
  key nor an ``optimizer`` key. Otherwise ``promote.policy-unsigned``. The
  attestation is an existing kind (``tine promote POLICY --sign-policy``).
* **Bound approvals.** An ``opentine.promotion-approval/1`` claim names the
  candidate, the label, the holder it replaces (``previous``) and the label
  state's ``sequence`` (its history length). Every move appends to the history,
  so an approval counts once: after a revert it is ``promote.approval-stale``.
* **Loop.** A candidate run whose metadata names ``opentine.loop`` (or an
  ``opentine.task`` that is a loop generation) belongs to that loop, so a
  stopped loop is refused without ``--loop``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from opentine._promote_checks import APPROVAL, refusal

POLICY = "opentine.promotion-policy/1"


def _who(doc: dict[str, Any]) -> str | None:
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import verify_attestation

    result = verify_attestation(doc, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return None
    who = key_fingerprint(bytes.fromhex(doc["signature"]["public_key"]))
    return who if doc.get("signer") == who else None


def _read(path: Path) -> tuple[bytes, dict[str, Any] | None]:
    raw = Path(path).read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    claim = doc.get("claim") if isinstance(doc, dict) else None
    return raw, (doc if isinstance(claim, dict) else None)


def approvals(paths: list[Path], candidate: str, label: str, policy: dict[str, Any],
              exclude: frozenset[str] = frozenset(), *, previous: str | None = None,
              sequence: int = 0) -> tuple[list, int]:  # fmt: skip
    """``(valid, stale)``: listed approvers' approvals that count, and how many do not.

    *exclude* (promoter, eval signers) never counts. A stale approval is signed
    by a listed approver for this candidate and label but names another
    holder or sequence (a move since: a revert, or a promotion it was used for).
    """
    found: dict[str, str] = {}
    stale = 0
    for path in paths:
        raw, doc = _read(path)
        if doc is None or doc["claim"].get("schema") != APPROVAL:
            continue
        claim = doc["claim"]
        who = _who(doc)
        if (claim.get("candidate"), claim.get("label")) != (candidate, label):
            continue
        if who not in policy["approvers"] or who in exclude:
            continue
        bound = (claim.get("previous", "-"), claim.get("sequence"))
        if bound != (previous, sequence) or type(claim.get("sequence")) is not int:
            stale += 1
            continue
        found[who] = hashlib.sha256(raw).hexdigest()  # the file's bytes
    return sorted(found.items()), stale


def sign_policy(key: Any, policy: dict[str, Any], at: str) -> dict[str, Any]:
    """The ``opentine.promotion-policy/1`` attestation over a loaded policy."""
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    claim = {"schema": POLICY, "policy_sha256": policy["sha256"],
             "label_policy_sha256": policy["label_policy_sha256"]}  # fmt: skip
    payload = {"claim": claim, "evidence_ids": [], "target_id": f"sha256:{policy['sha256']}",
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def role_state(repo_path: Path | None) -> dict[str, Any]:
    """:func:`opentine._key_roles_pin.resolve` for a repository (``absent`` without one)."""
    from opentine._key_roles_pin import resolve
    from opentine.repo import Repo

    if repo_path is None:
        return resolve(None)
    try:
        store = Repo.open(repo_path).path
    except Exception:  # noqa: BLE001 - no repository, so no key-role policy
        return resolve(None)
    return resolve(store)


def roles(repo_path: Path | None) -> dict[str, list[str]] | None:
    """The key roles that may grant powers: only pinned ones (0.59), else ``None``."""
    found = role_state(repo_path)
    return found["roles"] if found["status"] == "pinned" else None


def policy_pin(repo_path: Path | None, policy: dict[str, Any], promoter: str,
               files: list[Path]) -> tuple[dict | None, list]:  # fmt: skip
    """``(row, refusals)``: the attestation that pins *policy*, when a policy role exists."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import UNPINNED

    try:
        found = role_state(repo_path)
    except KeyRoleError as exc:
        return None, [refusal("promote.policy-unsigned", f"key-role policy: {exc}")]
    held = found["roles"]
    if not held or not held.get("policy"):
        return None, []
    if found["status"] != "pinned":  # a policy role in an unsigned file grants nothing
        return None, [refusal("promote.policy-unsigned", f"{UNPINNED}; no policy key counts")]
    want = (policy["sha256"], policy["label_policy_sha256"])
    banned = {promoter, *held.get("optimizer", [])}
    for path in files:
        raw, doc = _read(path)
        claim = doc["claim"] if doc else {}
        if claim.get("schema") != POLICY:
            continue
        if (claim.get("policy_sha256"), claim.get("label_policy_sha256")) != want:
            continue
        who = _who(doc)
        if who in held["policy"] and who not in banned:
            return {"signer": who, "sha256": hashlib.sha256(raw).hexdigest()}, []
    return None, [refusal("promote.policy-unsigned",
                          "no opentine.promotion-policy/1 attestation from a policy-role key "
                          "(not the promoting or an optimizer key) covers this policy "
                          "and its label policy")]  # fmt: skip


def run_loops(repo_path: Path | None, candidate: str) -> set[str]:
    """The loops the candidate run's metadata names (``opentine.loop``/``opentine.task``)."""
    from opentine.coord._store import read
    from opentine.coord._tasks import KIND, ref_name
    from opentine.repo import Repo

    if repo_path is None:
        return set()
    try:
        repo = Repo.open(repo_path)
        meta = repo.load_run(candidate).metadata
    except Exception:  # noqa: BLE001 - not stored here: --loop is the only source
        return set()
    loops = {meta["opentine.loop"]} if isinstance(meta.get("opentine.loop"), str) else set()
    task = meta.get("opentine.task")
    if isinstance(task, str):
        try:
            value = read(repo, ref_name(task), KIND)[1] or {}
        except ValueError:
            value = {}
        loops |= {value["loop"]} if value.get("loop") else set()
    return loops


__all__ = ["POLICY", "approvals", "policy_pin", "role_state", "roles", "run_loops", "sign_policy"]
