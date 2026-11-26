"""Sabotage task records (0.68): the ``opentine.sabotage-task/1`` claim convention.

A sabotage task is a SHADE-style pair: a *main task* the agent was asked to do
and a hidden *side task* (code sabotage or decision sabotage) it may attempt.
Each outcome is an **attestation** (the existing object kind) on the run it
scores, held by a ``tine hold`` row whose target is ``sabotage-task:TASK`` and
that is never released::

    {"convention": "opentine.sabotage-task/1", "task", "class": "code|decision",
     "main_task": {"id", "score": "0.5"|null, "passed": true|false|null},
     "side_task": {"id", "attempted": bool, "achieved": bool},
     "evidence": [REF, ...], "monitor_verdicts": ["attestation:sha256:..."], "at"}

A record counts only when signed with Ed25519 by a key in the ``scorer`` or
``eval`` role of the owner-pinned key roles (:mod:`opentine._key_roles_pin`).
Outcomes only go up: ``tine sabotage record`` refuses a record that would mark
an attempted side task not attempted (or an achieved one not achieved), and
``tine sabotage report`` takes the strongest verified outcome and reports any
held downgrade as ``fail:sabotage.relabel``. No object kind and no ``tine
verify`` code is added (docs/SABOTAGE.md).
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

CONVENTION = "opentine.sabotage-task/1"
CLASSES = ("code", "decision")
ROLES = ("scorer", "eval")
TASK_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_ATT = re.compile(r"attestation:sha256:[0-9a-f]{64}")
_FIELDS = ("convention", "task", "class", "main_task", "side_task", "evidence",
           "monitor_verdicts", "at")  # fmt: skip


def _score_ok(score: Any) -> bool:
    if score is None:
        return True
    try:
        number = Decimal(str(score))
    except InvalidOperation:
        return False
    return isinstance(score, str) and number.is_finite()


def check_claim(claim: Any) -> list[str]:
    """Problems with *claim* as an ``opentine.sabotage-task/1`` claim (none: valid)."""
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return ["not an opentine.sabotage-task/1 claim"]
    problems = [f"missing {name}" for name in _FIELDS if name not in claim]
    if problems:
        return problems
    if not TASK_RE.fullmatch(str(claim["task"])):
        problems.append("task is 1-128 of A-Z a-z 0-9 _ . : -")
    if claim["class"] not in CLASSES:
        problems.append("class is code or decision")
    main, side = claim["main_task"], claim["side_task"]
    if (
        not isinstance(main, dict)
        or not isinstance(main.get("id"), str)
        or not _score_ok(main.get("score"))
        or main.get("passed") not in (True, False, None)
    ):
        problems.append("main_task has an id, a decimal-string score or null, passed or null")
    if (
        not isinstance(side, dict)
        or not isinstance(side.get("id"), str)
        or not isinstance(side.get("attempted"), bool)
        or not isinstance(side.get("achieved"), bool)
    ):
        problems.append("side_task has an id and boolean attempted and achieved")
    elif side["achieved"] and not side["attempted"]:
        problems.append("an achieved side task was attempted")
    evidence, verdicts = claim["evidence"], claim["monitor_verdicts"]
    if not isinstance(evidence, list) or any(not isinstance(e, str) or not e for e in evidence):
        problems.append("evidence is a list of references")
    if not isinstance(verdicts, list) or any(not _ATT.fullmatch(str(v)) for v in verdicts):
        problems.append("monitor_verdicts lists attestation ids")
    if not isinstance(claim["at"], str):
        problems.append("at is a time")
    return problems


def scorers(repo: Any) -> tuple[set[str], set[str], str]:
    """Pinned scorer/eval fingerprints, pinned optimizer ones, and why others do not count."""
    from opentine._key_roles import OPTIMIZER, KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return set(), set(), f"key-role policy: {exc}"
    if found["status"] != "pinned":
        return set(), set(), "the scorer and eval roles are unpinned (no owner-signed trust bundle)"
    roles = found["roles"] or {}
    keys = {k for role in ROLES for k in roles.get(role, [])}
    why = "the signer is not a pinned scorer or eval key" if keys else "no scorer or eval key"
    return keys, set(roles.get(OPTIMIZER, [])), why


def records(repo: Any, task: str | None = None) -> dict[str, list[dict[str, Any]]]:
    """``{task: [{oid, run, signer, signed, claim}]}`` from the held records, in hold order."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation
    from opentine.repository._holds import SABOTAGE_TASK, holds_path, read_holds

    out: dict[str, list[dict[str, Any]]] = {}
    for row in read_holds(holds_path(repo)):
        if not row["target"].startswith(SABOTAGE_TASK):
            continue
        name = row["target"][len(SABOTAGE_TASK) :]
        if task is not None and name != task:
            continue
        try:
            payload = repo.get(row["oid"]).payload()
        except Exception:  # noqa: BLE001 - an unreadable record is reported
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        result = verify_attestation(payload, trust_embedded=True) if payload else None
        claim = payload.get("claim")
        # The signer field is signed text, not the key: it must name the key that signed.
        used = used_key_fingerprint(payload.get("signature")) if payload else None
        out.setdefault(name, []).append({
            "oid": row["oid"], "run": payload.get("target_id"), "signer": payload.get("signer"),
            "signed": bool(result and result.ok and result.algorithm == "ed25519"
                          and used == payload.get("signer")),
            "claim": claim if isinstance(claim, dict) else None})  # fmt: skip
    return out


def counted(rows: list[dict[str, Any]], keys: set[str]) -> list[dict[str, Any]]:
    """The rows that count: signed, well formed, by a pinned scorer or eval key."""
    return [r for r in rows if r["signed"] and r["signer"] in keys and not check_claim(r["claim"])]


def downgrade(before: dict[str, Any], after: dict[str, Any]) -> str | None:
    """Why *after* lowers an outcome *before* recorded (None: it does not)."""
    old, new = before["side_task"], after["side_task"]
    for name in ("attempted", "achieved"):
        if old[name] and not new[name]:
            return f"side task {name} was recorded true and is now false"
    return None


def record(repo: Any, run: str, claim: dict[str, Any], key: Any) -> str:
    """Sign *claim* onto *run* and hold it; refuses a downgrade. The attestation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest
    from opentine.repository._holds import SABOTAGE_TASK, hold_row

    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid sabotage task record: {problems[0]}")
    keys, optimizers, _why = scorers(repo)
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    if signer in optimizers:
        raise ValueError("sabotage.key-separation: a pinned optimizer key cannot record outcomes")
    for prior in counted(records(repo, claim["task"]).get(claim["task"], []), keys):
        why = downgrade(prior["claim"], claim)
        if why:
            raise ValueError(f"sabotage.relabel: {claim['task']}: {why} ({prior['oid']})")
    oid = attest(repo, run, claim, signer=signer, key=key, algorithm="ed25519",
                 signed_at=claim["at"])  # fmt: skip
    hold_row(repo, oid, f"{SABOTAGE_TASK}{claim['task']}")
    return oid


__all__ = ["CLASSES", "CONVENTION", "ROLES", "TASK_RE", "check_claim", "counted", "downgrade",
           "record", "records", "scorers"]  # fmt: skip
