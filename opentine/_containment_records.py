"""Signed, held claim records for containment evidence (0.69).

Every record is an **attestation** (an existing object kind) whose claim names
its ``convention``; it is kept by a ``tine hold`` row whose target starts with
``containment:`` and that ``tine hold release`` refuses, so a loop cannot
delete a sandbox policy or a finding.

A record counts as signed only when its Ed25519 signature verifies and the
payload ``signer`` names the key that actually signed (``used_key_fingerprint``).
Whether that signer holds a role comes only from the owner-pinned trust bundle
(:mod:`opentine._key_roles_pin`); an unpinned role reports ``unverified``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def rfc3339(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint(key: Any) -> str:
    from opentine._signing_pins import key_fingerprint

    return key_fingerprint(key.public_key().public_bytes_raw())


def record(repo: Any, target: str, claim: dict[str, Any], key: Any, hold: str) -> str:
    """Sign *claim* onto the object *target*, hold it as *hold*; the attestation id."""
    from opentine.repository._attest import attest
    from opentine.repository._holds import edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    oid = attest(repo, target, claim, signer=fingerprint(key), key=key, algorithm="ed25519")
    touch_links(repo, [oid])
    row = {"oid": oid, "target": hold}
    edit_holds(holds_path(repo), lambda rows: [*(r for r in rows if r != row), row])
    return oid


def anchor(repo: Any, name: str, text: str) -> str:
    """A small run that records hold no tool output of their own attach to."""
    import secrets

    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet

    run = Run(id=f"{name}-{secrets.token_hex(8)}", model_info=f"opentine/{name}",
              user_prompt=text, policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": text})
    return repo.put_run(run).run_id


def read(repo: Any, oid: str) -> dict[str, Any]:
    """``{"oid", "target", "signer", "signed", "claim"}`` for one record."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - an unreadable record is reported unsigned
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    result = verify_attestation(payload, trust_embedded=True) if payload else None
    used = used_key_fingerprint(payload.get("signature")) if payload else None
    signed = bool(result and result.ok and result.algorithm == "ed25519"
                  and used is not None and used == payload.get("signer"))  # fmt: skip
    claim = payload.get("claim")
    return {"oid": oid, "target": payload.get("target_id"), "signer": payload.get("signer"),
            "signed": signed, "claim": claim if isinstance(claim, dict) else None}  # fmt: skip


def held(repo: Any, prefix: str) -> list[tuple[str, dict[str, Any]]]:
    """``[(hold target, record)]`` for every held record under *prefix*, sorted."""
    from opentine.repository._holds import holds_path, read_holds

    rows = [r for r in read_holds(holds_path(repo)) if r["target"].startswith(prefix)]
    return [(r["target"], read(repo, r["oid"]))
            for r in sorted(rows, key=lambda r: (r["target"], r["oid"]))]  # fmt: skip


def role_state(repo: Any, signer: Any, role: str) -> str:
    """``verified`` when *signer* holds *role* in the owner-pinned key roles."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return f"unverified: key-role policy: {exc}"
    if found["status"] != "pinned":
        return f"unverified: the {role} role is unpinned (no owner-signed trust bundle)"
    roles = found["roles"] or {}
    if signer in roles.get("optimizer", []):
        return "unverified: the signer is an optimizer key"
    if signer not in roles.get(role, []):
        return f"unverified: the signer is not a pinned {role} key"
    return "verified"


__all__ = ["anchor", "fingerprint", "held", "read", "record", "rfc3339", "role_state"]
