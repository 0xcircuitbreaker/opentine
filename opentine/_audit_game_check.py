"""``tine auditor check``: judge blind audit games offline from their held records.

Findings follow D12: ``fail:`` is a fact about the records (a reveal that does
not open the seal, a reveal made before the verdict, an unsigned record) and
exits 1; ``advisory:`` (findings by a key outside the pinned ``auditor`` role,
a game not yet revealed) is reported and blocks only with ``--strict``.
"""

from __future__ import annotations

from typing import Any

from opentine import _audit_game as game


def auditors(repo: Any) -> tuple[set[str], str]:
    """The pinned ``auditor`` fingerprints and why another signer is not one."""
    from opentine._key_roles import AUDITOR, KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return set(), f"key-role policy: {exc}"
    if found["status"] != "pinned":
        return set(), "the auditor role is unpinned (no owner-signed trust bundle)"
    keys = set((found["roles"] or {}).get(AUDITOR, []))
    return keys, "the signer is not a pinned auditor key" if keys else "no auditor key is pinned"


def _finding(level: str, code: str, name: str, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:audit-game.{code}", "game": name,
            "message": message}  # fmt: skip


def judge(name: str, rows: list[dict[str, Any]], pinned: tuple[set[str], str]) -> dict:
    """One game's state and findings."""
    found: list[dict[str, Any]] = []
    for row in rows:
        if not row["signed"] or game.check_claim(row["claim"]):
            found.append(_finding("fail", "unsigned", name,
                                  f"{row['oid']} is not a signed audit-game record"))  # fmt: skip
    seal = game.latest(rows, "seal")
    findings = game.latest(rows, "findings")
    reveal = game.latest(rows, "reveal")
    state = "revealed" if reveal else "submitted" if findings else "sealed" if seal else "empty"
    if seal is None:
        found.append(_finding("fail", "unsealed", name, "the game has no signed seal"))
    if findings is not None:
        keys, why = pinned
        if findings["signer"] not in keys:
            found.append(_finding("advisory", "auditor-unpinned", name, f"findings: {why}"))
        if seal is not None and findings["claim"].get("seal") != seal["oid"]:
            found.append(_finding("fail", "commitment-mismatch", name,
                                  "the findings name another seal"))  # fmt: skip
    if reveal is None:
        found.append(_finding("advisory", "unrevealed", name, "the target is still sealed"))
    else:
        claim = reveal["claim"]
        opens = seal is not None and claim.get("seal") == seal["oid"]
        if seal is not None and not (
            opens and game.commitment(claim) == seal["claim"]["commitment"]
        ):
            found.append(_finding("fail", "commitment-mismatch", name,
                                  "the reveal does not open the seal"))  # fmt: skip
        # Every signed reveal must follow the verdict, not just the latest one.
        reveals = [r for r in rows if r["signed"] and (r["claim"] or {}).get("step") == "reveal"]
        early = any(
            findings is None
            or r["claim"].get("findings") != findings["oid"]
            or findings["claim"]["at"] > r["claim"]["at"]
            for r in reveals
        )
        if early:
            why = "the target was revealed before the auditor's verdict"
            found.append(_finding("fail", "reveal-before-verdict", name, why))
    out = {"game": name, "state": state, "records": len(rows),
           "seal": seal["oid"] if seal else None,
           "findings": findings["oid"] if findings else None,
           "verdict": findings["claim"].get("verdict") if findings else None,
           "reveal": reveal["oid"] if reveal else None,
           "target": reveal["claim"].get("target") if reveal else None}  # fmt: skip
    return {**out, "findings_list": found}


def check(repo: Any, name: str | None = None, *, strict: bool = False) -> dict[str, Any]:
    pinned = auditors(repo)
    games = []
    findings: list[dict[str, Any]] = []
    for gname, rows in sorted(game.records(repo, name).items()):
        row = judge(gname, rows, pinned)
        findings += row.pop("findings_list")
        games.append(row)
    blocking = [f for f in findings if f["level"] == "fail" or strict]
    return {"ok": not blocking, "strict": strict, "blocking": len(blocking), "games": games,
            "findings": findings}  # fmt: skip


__all__ = ["auditors", "check", "judge"]
