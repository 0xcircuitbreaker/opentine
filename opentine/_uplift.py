"""Uplift records (0.73): the ``opentine.uplift-suite/1`` and ``opentine.uplift-record/1``
claim conventions.

Each record is an **attestation** (an existing object kind) on a run, held by a
``tine hold`` row whose target is ``uplift:SUITE`` (the suite digest's hex) and
that is never released, so a loop cannot delete a result it dislikes::

    suite:  {"convention": "opentine.uplift-suite/1", "digest": "sha256:..",
             "suite": {"name", "version", "scoring", "tasks": [{"id", "minutes"}]}, "at"}
    record: {"convention": "opentine.uplift-record/1", "record": "baseline|run|speed",
             "suite": "sha256:..", "task", "subject", "condition", "success",
             "minutes", "perceived_minutes", "generation", "at"}

The suite digest is ``sha256:`` over ``opentine.uplift-suite/1`` + NUL + the
canonical JSON of the ``suite`` object, so a suite is addressed by its task
list, lengths and scoring. A ``baseline`` is a human (``condition: human``)
attempt; a ``run`` is an ``ai``, ``ai-assisted`` or ``unassisted`` attempt; a
``speed`` record pairs perceived and measured minutes. Records count only when
signed with Ed25519 by a key in the ``scorer`` or ``eval`` role of the
owner-pinned key roles, by the key the signer field names; a pinned optimizer
key is refused. No object kind and no ``tine verify`` code is added
(docs/UPLIFT.md).
"""

from __future__ import annotations

import hashlib
import re
from decimal import Decimal
from typing import Any

from opentine._sabotage import ROLES, scorers
from opentine.kernel import canonical_json

SUITE = "opentine.uplift-suite/1"
RECORD = "opentine.uplift-record/1"
KINDS = ("baseline", "run", "speed")
CONDITIONS = ("human", "ai", "ai-assisted", "unassisted")
ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MINUTES_RE = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?")
_REC_FIELDS = ("convention", "record", "suite", "task", "subject", "condition", "success",
               "minutes", "perceived_minutes", "generation", "at")  # fmt: skip


def minutes_ok(value: Any) -> bool:
    """A positive plain decimal string: up to 9 integer and 6 fractional digits, no exponent,
    sign or spaces, so every length is finite and non-zero as a float (no inf, NaN or 0)."""
    if not isinstance(value, str) or not MINUTES_RE.fullmatch(value):
        return False
    return Decimal(value) > 0


def suite_digest(suite: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(SUITE.encode() + b"\0" + canonical_json(suite)).hexdigest()


def check_suite(suite: Any) -> list[str]:
    """Problems with a suite body (none: valid)."""
    if not isinstance(suite, dict) or set(suite) != {"name", "version", "scoring", "tasks"}:
        return ["a suite has exactly name, version, scoring and tasks"]
    if not all(isinstance(suite[k], str) and suite[k] for k in ("name", "version", "scoring")):
        return ["name, version and scoring are non-empty strings"]
    tasks = suite["tasks"]
    if not isinstance(tasks, list) or not tasks:
        return ["tasks is a non-empty list"]
    seen: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict) or set(task) != {"id", "minutes"}:
            return ["each task has exactly id and minutes"]
        if not ID_RE.fullmatch(str(task["id"])) or task["id"] in seen:
            return [f"task id {task['id']!r} is invalid or repeated"]
        if not minutes_ok(task["minutes"]):
            return [f"task {task['id']}: minutes is a positive decimal string"]
        seen.add(task["id"])
    return []


def check_claim(claim: Any) -> list[str]:
    """Problems with *claim* as a suite or record claim (none: valid)."""
    if isinstance(claim, dict) and claim.get("convention") == SUITE:
        if set(claim) != {"convention", "digest", "suite", "at"}:
            return ["a suite claim has convention, digest, suite and at"]
        problems = check_suite(claim["suite"])
        if not problems and claim["digest"] != suite_digest(claim["suite"]):
            problems = ["digest does not match the suite"]
        return problems
    if not isinstance(claim, dict) or claim.get("convention") != RECORD:
        return ["not an opentine.uplift-suite/1 or opentine.uplift-record/1 claim"]
    if set(claim) != set(_REC_FIELDS):
        return [f"a record has exactly {', '.join(_REC_FIELDS)}"]
    problems: list[str] = []
    kind, cond = claim["record"], claim["condition"]
    if kind not in KINDS:
        problems.append("record is baseline, run or speed")
    if not DIGEST_RE.fullmatch(str(claim["suite"])):
        problems.append("suite is a sha256: digest")
    for name in ("task", "subject"):
        if not ID_RE.fullmatch(str(claim[name])):
            problems.append(f"{name} is 1-128 of A-Z a-z 0-9 _ . : -")
    if cond not in CONDITIONS or (kind == "baseline") != (cond == "human"):
        problems.append("a baseline is condition human; a run or speed record is not")
    if not isinstance(claim["success"], (bool, type(None))) or (
        kind != "speed" and claim["success"] is None
    ):
        problems.append("success is a boolean (null only on a speed record)")
    for name in ("minutes", "perceived_minutes"):
        if claim[name] is not None and not minutes_ok(claim[name]):
            problems.append(f"{name} is a positive decimal string or null")
    if kind == "baseline" and claim["minutes"] is None:
        problems.append("a baseline records measured minutes")
    if (kind == "speed") != (claim["perceived_minutes"] is not None) or (
        kind == "speed" and claim["minutes"] is None
    ):
        problems.append("a speed record (and only it) has perceived and measured minutes")
    gen = claim["generation"]
    if gen is not None and (isinstance(gen, bool) or not isinstance(gen, int) or gen < 0):
        problems.append("generation is a non-negative integer or null")
    if not isinstance(claim["at"], str):
        problems.append("at is a time")
    return problems


def hold_target(digest: str) -> str:
    from opentine.repository._holds import UPLIFT

    return f"{UPLIFT}{digest.removeprefix('sha256:')}"


def rows(repo: Any, digest: str | None = None) -> list[dict[str, Any]]:
    """``[{oid, run, signer, signed, claim}]`` of the held records, in hold order."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation
    from opentine.repository._holds import UPLIFT, holds_path, read_holds

    out: list[dict[str, Any]] = []
    for row in read_holds(holds_path(repo)):
        if not row["target"].startswith(UPLIFT):
            continue
        if digest is not None and row["target"] != hold_target(digest):
            continue
        try:
            payload = repo.get(row["oid"]).payload()
        except Exception:  # noqa: BLE001 - an unreadable record is reported
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        result = verify_attestation(payload, trust_embedded=True) if payload else None
        used = used_key_fingerprint(payload.get("signature")) if payload else None
        claim = payload.get("claim")
        out.append({
            "oid": row["oid"], "run": payload.get("target_id"), "signer": payload.get("signer"),
            "signed": bool(result and result.ok and result.algorithm == "ed25519"
                          and used == payload.get("signer")),
            "claim": claim if isinstance(claim, dict) else None})  # fmt: skip
    return out


def record(repo: Any, run: str, claim: dict[str, Any], key: Any) -> str:
    """Sign *claim* onto *run* and hold it under its suite. The attestation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest
    from opentine.repository._holds import edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid uplift record: {problems[0]}")
    _keys, optimizers, _why = scorers(repo)
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    if signer in optimizers:
        raise ValueError("uplift.key-separation: a pinned optimizer key cannot sign uplift records")
    digest = claim["digest"] if claim["convention"] == SUITE else claim["suite"]
    if claim["convention"] == RECORD:
        from opentine._uplift_export import suite_of

        suite = suite_of(repo, digest)
        if suite is None:
            raise ValueError(f"uplift.unknown-suite: no counted suite {digest}")
        if claim["task"] not in {t["id"] for t in suite["tasks"]}:
            raise ValueError(f"uplift.unknown-task: {claim['task']} is not in suite {digest}")
    oid = attest(repo, run, claim, signer=signer, key=key, algorithm="ed25519",
                 signed_at=claim["at"])  # fmt: skip
    touch_links(repo, [oid])
    row = {"oid": oid, "target": hold_target(digest)}
    edit_holds(holds_path(repo), lambda held: [*(r for r in held if r != row), row])
    return oid


__all__ = ["CONDITIONS", "KINDS", "RECORD", "ROLES", "SUITE", "check_claim", "check_suite",
           "hold_target", "minutes_ok", "record", "rows", "scorers", "suite_digest"]  # fmt: skip
