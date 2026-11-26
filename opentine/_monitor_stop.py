"""Signed stop tokens (0.63): ``tine hold`` extended to a kill switch hooks check.

``tine monitor stop --scope SCOPE --key KEY`` writes an attestation (the
existing object kind) whose claim follows ``opentine.monitor-stop/1``::

    {"convention": "opentine.monitor-stop/1", "scope": SCOPE,
     "reason": TEXT, "stopped_at": "YYYY-MM-DDTHH:MM:SSZ"}

``SCOPE`` is ``*`` (every gated action), ``agent:NAME`` or ``session:ID``.
The token is kept by a hold row ``{"oid": TOKEN, "target":
"monitor-stop:SCOPE"}`` that ``tine hold release`` refuses: there is no
un-stop, and deleting a ref cannot lift it. The MCP proxy and the hook path
read the holds before every gated action and block a stopped scope in either
mode (a stop is an operator decision, not an advisory finding). An unreadable
holds file counts as a stop (fail closed). ``verification`` says whether the
token's Ed25519 signer is in the owner-pinned ``stopper`` role; an unverified
token still stops, as a loop stop does (:mod:`opentine.coord._loop_stop`).
"""

from __future__ import annotations

import re
import secrets
import time
from datetime import UTC, datetime
from typing import Any

CONVENTION = "opentine.monitor-stop/1"
SCOPE = re.compile(r"^(\*|agent:[A-Za-z0-9._-]{1,64}|session:[A-Za-z0-9._:-]{1,128})$")
MAX_REASON = 1024


def _rfc3339(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def scopes(agent: str | None, session: str | None) -> list[str]:
    """The scopes a gated action falls under."""
    return [
        "*",
        *([f"agent:{agent}"] if agent else []),
        *([f"session:{session}"] if session else []),
    ]


def stop(repo: Any, scope: str, key: Any, *, reason: str = "", now: float | None = None) -> str:
    """Sign, store and hold a stop token for *scope*; its attestation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet
    from opentine.repository._attest import attest
    from opentine.repository._holds import MONITOR_STOP, hold_row

    if not isinstance(scope, str) or not SCOPE.fullmatch(scope):
        raise ValueError(f"invalid stop scope {scope!r}: *, agent:NAME or session:ID")
    if not isinstance(reason, str) or len(reason.encode("utf-8")) > MAX_REASON:
        raise ValueError(f"a stop reason is text of at most {MAX_REASON} bytes")
    at = _rfc3339(time.time() if now is None else now)
    run = Run(id=f"monitor-stop-{secrets.token_hex(8)}", model_info="opentine/monitor-stop",
              user_prompt=f"stop {scope}", policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": reason or f"{scope} stopped"})
    target = repo.put_run(run).run_id
    claim = {"convention": CONVENTION, "scope": scope, "reason": reason, "stopped_at": at}
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    oid = attest(repo, target, claim, signer=signer, key=key, algorithm="ed25519")
    hold_row(repo, oid, MONITOR_STOP + scope)
    return oid


def verify_token(repo: Any, oid: str, scope: str) -> str:
    """``verified`` when *oid* is a pinned-stopper-signed token for *scope*."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation
    from opentine.coord._loop_stop import _stopper

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - a missing token is reported, still a stop
        return "unverified: the stop token cannot be read"
    claim = payload.get("claim") if isinstance(payload, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return "unverified: not an opentine.monitor-stop/1 claim"
    if claim.get("scope") != scope:
        return "unverified: the token names another scope"
    result = verify_attestation(payload, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return f"unverified: {result.state}"
    if used_key_fingerprint(payload.get("signature")) != payload.get("signer"):
        return "unverified: the signer field does not name the key that signed"
    return _stopper(repo, payload.get("signer"))


def tokens(repo: Any) -> list[dict[str, Any]]:
    """Every stop token the holds keep: ``{"scope", "token", "verification"}``.

    An unreadable holds file is one ``*`` stop with ``token`` ``None``.
    """
    from opentine.repository._holds import MONITOR_STOP, HoldError, holds_path, read_holds

    try:
        rows = [r for r in read_holds(holds_path(repo)) if r["target"].startswith(MONITOR_STOP)]
    except HoldError as exc:
        return [{"scope": "*", "token": None, "verification": f"unverified: {exc}"}]
    out = []
    for row in sorted(rows, key=lambda r: (r["target"], r["oid"])):
        scope = row["target"][len(MONITOR_STOP) :]
        out.append({"scope": scope, "token": row["oid"],
                    "verification": verify_token(repo, row["oid"], scope)})  # fmt: skip
    return out


def active(repo: Any, names: list[str]) -> dict[str, Any] | None:
    """The first stop token covering any of *names*, or ``None``."""
    from opentine.repository._holds import MONITOR_STOP, HoldError, holds_path, read_holds

    try:
        rows = read_holds(holds_path(repo))
    except HoldError as exc:
        return {"scope": "*", "token": None, "verification": f"unverified: {exc}"}
    wanted = {MONITOR_STOP + n for n in names}
    hit = sorted((r["target"], r["oid"]) for r in rows if r["target"] in wanted)
    if not hit:
        return None
    scope = hit[0][0][len(MONITOR_STOP) :]
    return {"scope": scope, "token": hit[0][1], "verification": None}


__all__ = ["CONVENTION", "SCOPE", "active", "scopes", "stop", "tokens", "verify_token"]
