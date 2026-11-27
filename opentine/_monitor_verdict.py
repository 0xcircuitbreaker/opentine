"""Monitor verdicts (0.63): the ``opentine.monitor-verdict/1`` claim convention.

A monitor verdict is an **attestation** (the existing object kind) whose claim
records one decision an inline monitor made about one proposed action::

    {"convention": "opentine.monitor-verdict/1",
     "monitor": {"id", "kind": "rule|command|http|probe", "model_digest"},
     "input_digest": "sha256:<hex>",        # the redacted action, see input_digest()
     "reasoning": {"state": "captured|redacted|unavailable", "digest"},
     "tool", "session", "score", "threshold",
     "action": "allow|flag|resample|defer|block",
     "enforced", "mode": "advisory|gate", "decided_by", "latency_ms",
     "deadline_ms", "fail_closed", "trajectories", "chosen", "stop", "decided_at"}

It is signed with an Ed25519 key; ``verified`` needs the signer in the
``monitor`` role of the owner-pinned key roles (:mod:`opentine._key_roles_pin`).
A verdict that is not ``allow`` is kept by a ``tine hold`` row whose target
starts ``monitor-verdict:`` and is never released, so a loop cannot delete the
record of what blocked it. No object kind and no ``tine verify`` code is added
(docs/MONITORS.md).
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine.kernel import canonical_json

CONVENTION = "opentine.monitor-verdict/1"
ACTIONS = ("allow", "flag", "resample", "defer", "block")
REASONING = ("captured", "redacted", "unavailable")
DECIDED_BY = ("monitor", "deadline", "error", "stop-token", "alternate")
KINDS = ("rule", "command", "http", "probe")
MODES = ("advisory", "gate")
ROLES = ("original", "resample", "trusted")
_FIELDS = ("convention", "monitor", "input_digest", "reasoning", "tool", "session", "score",
           "threshold", "action", "enforced", "mode", "decided_by", "latency_ms", "deadline_ms",
           "fail_closed", "trajectories", "chosen", "stop", "decided_at")  # fmt: skip


def digest(value: Any) -> str:
    """``sha256:`` of the canonical JSON of *value*."""
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def input_digest(method: str, params: Any) -> str:
    """The digest of an action as a proxy run records it: redacted, ``_meta`` mark removed.

    ``tine mcp-proxy`` stores each request's ``method`` and ``params`` after
    redaction, so an offline check recomputes this from the step alone.
    """
    from opentine.redaction import redact_value

    if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
        meta = {k: v for k, v in params["_meta"].items() if k != META_KEY}
        params = {**params, "_meta": meta} if meta else {
            k: v for k, v in params.items() if k != "_meta"}  # fmt: skip
    return digest(redact_value({"method": method, "params": params}))


#: The ``params._meta`` key a forwarded alternate action carries (its verdict).
META_KEY = "opentine/monitor"


def check_claim(claim: Any) -> list[str]:
    """Problems with *claim* as an ``opentine.monitor-verdict/1`` claim (none: valid)."""
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return ["not an opentine.monitor-verdict/1 claim"]
    problems = [f"missing {name}" for name in _FIELDS if name not in claim]
    if problems:
        return problems
    monitor, reasoning = claim["monitor"], claim["reasoning"]
    if not isinstance(monitor, dict) or monitor.get("kind") not in KINDS or not monitor.get("id"):
        problems.append("monitor needs an id and a kind (rule, command, http, probe)")
    if not isinstance(reasoning, dict) or reasoning.get("state") not in REASONING:
        problems.append("reasoning.state is captured, redacted or unavailable")
    elif (reasoning["state"] == "unavailable") != (reasoning.get("digest") is None):
        problems.append("reasoning.digest is present exactly when text was seen")
    if claim["action"] not in ACTIONS:
        problems.append(f"action is one of {', '.join(ACTIONS)}")
    if claim["mode"] not in MODES or claim["decided_by"] not in DECIDED_BY:
        problems.append("unknown mode or decided_by")
    if claim["enforced"] and claim["mode"] != "gate" and claim["decided_by"] != "stop-token":
        problems.append("only gate mode (or a stop token) enforces a verdict")
    trajectories = claim["trajectories"]
    if (
        not isinstance(trajectories, list)
        or not trajectories
        or any(not isinstance(t, dict) or t.get("role") not in ROLES for t in trajectories)
    ):
        problems.append("trajectories list the original and any alternate")
    elif trajectories[0].get("digest") != claim["input_digest"]:
        problems.append("the first trajectory is the original action")
    return problems


def monitors(repo: Any) -> tuple[set[str], str]:
    """The pinned ``monitor`` fingerprints and why another signer is unverified."""
    from opentine._key_roles import MONITOR
    from opentine._key_roles_pin import granting

    return granting(repo.path, MONITOR)


def verify(repo: Any, oid: str, pinned: tuple[set[str], str] | None = None) -> dict[str, Any]:
    """``{"verdict", "claim", "signed", "verification", "problems"}`` for one verdict."""
    from opentine.attest_signing import verify_attestation

    row: dict[str, Any] = {"verdict": oid, "claim": None, "problems": [], "signed": False}
    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - a missing or malformed verdict is reported
        return {**row, "verification": "unverified: the verdict cannot be read",
                "problems": ["the verdict cannot be read"]}  # fmt: skip
    claim = payload.get("claim") if isinstance(payload, dict) else None
    row["claim"], row["problems"] = claim, check_claim(claim)
    result = verify_attestation(payload, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return {**row, "verification": f"unverified: {result.state}"}
    from opentine._signing_pins import used_key_fingerprint

    if used_key_fingerprint(payload.get("signature")) != payload.get("signer"):
        return {**row, "verification": "unverified: the signer is not the key that signed"}
    row["signed"] = True
    keys, why = pinned if pinned is not None else monitors(repo)
    ok = payload.get("signer") in keys
    return {**row, "verification": "verified" if ok else f"unverified: {why}"}


def record(repo: Any, target: str, claim: dict[str, Any], key: Any) -> str:
    """Sign *claim* onto *target*; hold it unless it is ``allow``. The verdict id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest

    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid monitor verdict: {problems[0]}")
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    oid = attest(repo, target, claim, signer=signer, key=key, algorithm="ed25519")
    if claim["action"] != "allow" or claim["enforced"]:
        hold(repo, oid, claim["session"])
    return oid


def hold(repo: Any, oid: str, session: str) -> None:
    from opentine.repository._holds import MONITOR_VERDICT, hold_row

    hold_row(repo, oid, f"{MONITOR_VERDICT}{session}")


def held(repo: Any) -> list[str]:
    """Every held verdict id (raises ``HoldError`` on an unreadable holds file)."""
    from opentine.repository._holds import MONITOR_VERDICT, holds_path, read_holds

    rows = read_holds(holds_path(repo))
    return sorted({r["oid"] for r in rows if r["target"].startswith(MONITOR_VERDICT)})


__all__ = ["ACTIONS", "CONVENTION", "META_KEY", "REASONING", "check_claim", "digest", "held",
           "hold", "input_digest", "monitors", "record", "text_digest", "verify"]  # fmt: skip
