"""Signed dataset versions from runs (0.75): curate, justify, withdraw, list.

:func:`curate` selects runs (:mod:`opentine._dataset_select`), drops runs a
contributor withdrew, applies the taint filter (:mod:`opentine._dataset_taint`),
dedups by content-defined chunks and signs an ``opentine.dataset-version/1``
claim (:mod:`opentine._dataset_claims`) onto a small anchor run. Every record
is held by a ``dataset-record:`` row that ``tine hold release`` refuses.

Keys: the signer is always the key that signed (``used_key_fingerprint``).
An ``optimizer`` key may not curate, justify or tombstone; an unreadable
key-role policy refuses (fail closed). A version is ``verified`` only when its
offline check holds and its signer is a pinned ``curator`` key. Tainted runs
enter only with ``include_tainted`` and a justification signed by a pinned
``curator`` or ``policy`` key for this dataset name; without a pinned trust
bundle that gate refuses.
"""

from __future__ import annotations

from typing import Any

from opentine import _containment_records as records
from opentine import _dataset_claims as dc
from opentine.repository._holds import DATASET_RECORD as HOLD

JUSTIFIERS = ("curator", "policy")


def _roles(repo: Any, signer: str, wanted: tuple[str, ...]) -> tuple[bool, str]:
    """Whether *signer* holds one of *wanted* in the pinned roles and not ``optimizer``."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return False, f"key-role policy: {exc}"
    roles = found["roles"] or {}
    if signer in roles.get("optimizer", []):
        return False, "the signer is an optimizer key"
    if found["status"] != "pinned":
        names = " and ".join(wanted)
        return False, f"the {names} roles are unpinned (no owner-signed trust bundle)"
    if not any(signer in roles.get(role, []) for role in wanted):
        return False, f"the signer is not a pinned {' or '.join(wanted)} key"
    return True, "verified"


def _refuse_optimizer(repo: Any, signer: str) -> None:
    ok, why = _roles(repo, signer, ("curator",))
    if not ok and ("optimizer" in why or why.startswith("key-role policy")):
        raise PermissionError(f"refusing to sign: {why}")


def _own(row: dict[str, Any], signer: str) -> bool:
    """A version this same key signed (the chain when no curator role is pinned)."""
    return row["signature"] == "verified-tofu" and row["curator"] == signer


def versions(repo: Any, name: str | None = None) -> list[dict[str, Any]]:
    """Every held dataset version (of *name*), oldest first, with its verification."""
    from opentine._dataset_taint import TaintFilterError, tainted

    try:
        taint: dict[str, Any] | None = tainted(repo)
    except TaintFilterError:
        taint = None
    out = []
    for target, row in records.held(repo, f"{HOLD}version:"):
        claim = row["claim"] or {}
        if claim.get("convention") != dc.VERSION or (name and claim.get("name") != name):
            continue
        try:
            payload = repo.get(row["oid"]).payload()
        except Exception:  # noqa: BLE001 - an unreadable version is listed, never verified
            payload = {}
        check = dc.offline(payload)
        if not check["ok"]:
            state = f"unverified: {(check['problems'] or [check['signature']])[0]}"
        else:
            ok, why = _roles(repo, row["signer"], ("curator",))
            state = "verified" if ok else f"unverified: {why}"
            if ok:
                state = _still_clean(payload["claim"], taint)
        out.append({"record": row["oid"], "hold": target, "name": claim.get("name"),
                    "version": claim.get("version"), "previous": claim.get("previous"),
                    "selection": claim.get("selection"), "members": check["members"],
                    "excluded": check["excluded"], "signature": check["signature"],
                    "curator": claim.get("curator"), "created_at": claim.get("created_at"),
                    "verification": state})  # fmt: skip
    return sorted(out, key=lambda r: (str(r["name"]), r["version"] or 0, r["record"]))


def _still_clean(claim: dict[str, Any], taint: dict[str, Any] | None) -> str:
    """``verified`` unless a member not justified at curation is tainted now."""
    if taint is None:
        return "unverified: the taint filter cannot be applied now"
    allowed = set(claim["taint_filter"]["included_tainted"])
    late = sorted(m["run"] for m in claim["members"] if m["run"] in taint
                  and m["run"] not in allowed)  # fmt: skip
    if late:
        return f"unverified: {len(late)} member(s) tainted since curation, e.g. {late[0]}"
    return "verified"


def withdrawals(repo: Any) -> dict[str, str]:
    """``{run: withdrawal id}`` for every signed, well formed, held withdrawal."""
    from opentine._dataset_withdraw import withdrawals as contributed
    from opentine._dataset_withdraw_auth import authority

    out: dict[str, str] = {}
    for _, row in records.held(repo, f"{HOLD}withdrawal:"):
        claim = row["claim"]
        if (row["signed"] and not dc.check_record(claim) and claim["convention"] == dc.WITHDRAWAL
                and claim["contributor"] == row["signer"]
                and authority(repo, claim["run"], row["signer"], claim["reason"])[0]):  # fmt: skip
            out.setdefault(claim["run"], row["oid"])
    for row in contributed(repo):  # ``tine dataset withdraw`` (opentine-dataset/withdraw/1)
        if row["state"] == "verified":  # signer checked by authority() there
            out.setdefault(row["run"], row["record"])
    return out


def justification(repo: Any, oid: str, name: str) -> list[str]:
    """The runs a valid justification lets into *name*; raises ``PermissionError`` otherwise."""
    row = records.read(repo, oid)
    claim = row["claim"]
    if not row["signed"]:
        raise PermissionError("the justification's signature does not hold or names another key")
    if dc.check_record(claim) or claim["convention"] != dc.JUSTIFICATION:
        raise PermissionError(f"{oid} is not a valid dataset justification")
    if claim["dataset"] != name or claim["curator"] != row["signer"]:
        raise PermissionError("the justification is for another dataset or another key")
    ok, why = _roles(repo, row["signer"], JUSTIFIERS)
    if not ok:
        raise PermissionError(f"the justification does not count: {why}")
    return list(claim["runs"])


def justify(repo: Any, name: str, runs: list[str], reason: str, key: Any, at: str) -> str:
    signer = records.fingerprint(key)
    ok, why = _roles(repo, signer, JUSTIFIERS)
    if not ok:
        raise PermissionError(f"refusing to justify: {why}")
    claim = {"convention": dc.JUSTIFICATION, "dataset": name, "runs": sorted(set(runs)),
             "reason": reason, "curator": signer, "at": at}  # fmt: skip
    problems = dc.check_record(claim)
    if problems:
        raise ValueError(f"not a valid justification: {problems[0]}")
    for run in claim["runs"]:
        if not repo.has(run):
            raise KeyError(f"run {run} is not in the repository")
    target = claim["runs"][0]
    return records.record(repo, target, claim, key, f"{HOLD}justification:{name}:{target}")


def _is_optimizer(repo: Any, signer: str) -> bool:
    """Whether *signer* is a pinned optimizer key (an unreadable policy counts as yes)."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError:
        return True
    return signer in (found["roles"] or {}).get("optimizer", [])


def withdraw(repo: Any, run: str, reason: str, key: Any, at: str) -> str:
    signer = records.fingerprint(key)
    from opentine._dataset_withdraw_auth import authority

    who, why = authority(repo, run, signer, reason)
    if who is None:
        raise PermissionError(f"refusing to withdraw: {why}")
    claim = {"convention": dc.WITHDRAWAL, "run": run, "reason": reason, "contributor": signer,
             "at": at}  # fmt: skip
    problems = dc.check_record(claim)
    if problems:
        raise ValueError(f"not a valid withdrawal: {problems[0]}")
    if not repo.has(run):
        raise KeyError(f"run {run} is not in the repository")
    return records.record(repo, run, claim, key, f"{HOLD}withdrawal:{run}")


def curate(repo: Any, name: str, selection: str, key: Any, at: str, *,
           eval_dirs: list[str] | None = None, include_tainted: bool = False,
           justification_id: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign one version of *name*; ``{"record", "claim", "tombstones"}``."""
    from opentine._dataset_near import copies
    from opentine._dataset_select import candidates, dedup
    from opentine._dataset_taint import tainted

    if not dc.NAME_RE.fullmatch(name):
        raise ValueError("the dataset name is lower-case letters, digits, '.', '_' and '-'")
    if include_tainted != (justification_id is not None):
        raise ValueError("--include-tainted and --justification go together")
    signer = records.fingerprint(key)
    _refuse_optimizer(repo, signer)
    allowed = set(justification(repo, justification_id, name)) if justification_id else set()
    chosen = candidates(repo, selection, eval_dirs)
    gone = withdrawals(repo)
    withdrawn = [r for r in chosen if r in gone]
    taint: dict[str, Any] = dict(tainted(repo))
    for run in copies(repo, set(taint), [r for r in chosen if r not in gone]):
        taint[run] = ["content-copy"]
    kept = [r for r in chosen if r not in gone and (r not in taint or r in allowed)]
    members, dropped = dedup(repo, kept)
    runs = {m["run"] for m in members}
    prior = [v for v in versions(repo, name)
             if v["verification"] == "verified" or _own(v, signer)]  # fmt: skip
    last = prior[-1] if prior else None
    number = (last["version"] + 1) if last else 1
    claim = {"convention": dc.VERSION, "name": name, "version": number,
             "previous": last["record"] if last else None, "selection": selection,
             "members": members, "members_digest": dc.members_digest(members),
             "dedup": {"chunking": dict(dc.CHUNKING), "candidates": len(kept),
                       "dropped": dropped},
             "taint_filter": {"mode": "include-tainted" if include_tainted else "default",
                              "sources": list(dc.SOURCES),
                              "excluded": sorted(r for r in chosen if r in taint and r not in gone
                                                 and r not in allowed),
                              "included_tainted": sorted(r for r in runs if r in taint),
                              "justification": justification_id},
             "withdrawn": withdrawn, "curator": signer, "created_at": at}  # fmt: skip
    problems = dc.check_version(claim)
    if problems:
        raise ValueError(f"not a valid dataset version: {problems[0]}")
    anchor = records.anchor(repo, "dataset", f"dataset {name} version {claim['version']}")
    oid = records.record(repo, anchor, claim, key, f"{HOLD}version:{name}:{claim['version']}")
    tombstones = []
    if last:
        before = repo.get(last["record"]).payload()["claim"]["members"]
        for run in sorted({m["run"] for m in before} & set(gone)):
            stone = {"convention": dc.TOMBSTONE, "dataset": name, "version": last["record"],
                     "run": run, "withdrawal": gone[run], "curator": signer, "at": at}  # fmt: skip
            tombstones.append(records.record(repo, run, stone, key,
                                             f"{HOLD}tombstone:{name}:{run}"))  # fmt: skip
    return {"record": oid, "claim": claim, "tombstones": tombstones}


__all__ = ["HOLD", "JUSTIFIERS", "curate", "justification", "justify", "versions", "withdraw",
           "withdrawals"]  # fmt: skip
