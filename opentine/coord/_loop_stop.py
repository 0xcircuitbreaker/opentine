"""The loop kill switch (0.58): a signed stop that lease fencing honours.

``tine loop stop LOOP`` writes an **attestation** (the existing object kind)
whose claim follows the ``opentine.loop-stop/1`` convention::

    {"convention": "opentine.loop-stop/1", "loop": LOOP,
     "reason": TEXT, "stopped_at": "YYYY-MM-DDTHH:MM:SSZ"}

signed with an Ed25519 key, ``signer`` the key's ``sha256:`` fingerprint. Its
target is a small control run recording the stop (or ``--run RUN``, the run
that prompted it). The attestation is indexed by the ``opentine-coord/1``
record ``coord/loops/<LOOP>`` (``{"loop", "status": "stopped", "stop":
ATTESTATION, "signer", "updated_ms"}``, the attestation kept in
``evidence_ids``), the same annotation chain every coord record uses.

Fencing (:mod:`opentine.coord._tasks`): a task added with ``loop=LOOP`` (a
loop generation) can no longer be **claimed** or **heartbeated** once the
record exists. The check reads the record, never a clock, so a fleet with
skewed clocks is refused at once on every member; the generation already
holding a lease cannot extend it, so it ends within one lease period by the
holder's own clock. ``done`` stays allowed so a holder can close its work.
The fence is fail-safe: a stop record whose signature does not verify still
refuses (``loop_state`` reports it as ``unverified``), and so does one signed
by a key outside the optional ``stopper`` role of ``.tine/key-roles.toml``.
There is no un-stop: a stopped loop restarts under a new loop id. The stop is
also kept by a ``tine hold`` that cannot be released
(:mod:`opentine.coord._loop_hold`), so deleting or rewriting the coord record
does not un-stop the loop. A task in a loop's namespace (``LOOP.*``) is fenced
even when it was added without ``loop=``.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

from opentine.coord import _loop_hold
from opentine.coord._store import history, read, swap

KIND = "loop"
PREFIX = "coord/loops/"
CONVENTION = "opentine.loop-stop/1"
LOOP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_REASON = 1024


class LoopStopped(ValueError):
    """A generation's lease refused because its loop was stopped."""


def ref_name(loop: str) -> str:
    if not isinstance(loop, str) or not LOOP_ID.fullmatch(loop):
        raise ValueError(f"invalid loop id: {loop!r} (lowercase [a-z0-9._-], at most 64)")
    return PREFIX + loop


def _rfc3339(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _control_run(repo: Any, loop: str, reason: str) -> str:
    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet

    run = Run(id=f"loop-stop-{loop}", model_info="opentine/loop-stop",
              user_prompt=f"stop loop {loop}", policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": reason or f"loop {loop} stopped"})
    return repo.put_run(run).run_id


def _stop_record(repo: Any, loop: str) -> tuple[str | None, dict[str, Any] | None]:
    """``(head oid, stop value)``: the oldest stopped version in the record's chain.

    A later version that drops ``status: stopped`` (a hand-written coord swap)
    cannot un-stop the loop: the fence reads the whole chain, so the first stop
    stands as the docstring above promises.
    """
    oid, value = read(repo, ref_name(loop), KIND)
    stops = [r for r in history(repo, oid) if r.get("status") == "stopped"] if value else []
    return oid, (stops[-1] if stops else _loop_hold.held_stop(repo, loop))


def stop(
    repo: Any, loop: str, key: Any, *, reason: str = "", run: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Sign and record a stop for *loop*; the coord record's value.

    *key* is an Ed25519 private key. Stopping a stopped loop returns the
    existing record unchanged (the first stop stands).
    """
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest

    name = ref_name(loop)
    if not isinstance(reason, str) or len(reason.encode("utf-8")) > MAX_REASON:
        raise ValueError(f"a stop reason is text of at most {MAX_REASON} bytes")
    oid, value = _stop_record(repo, loop)
    if value is not None:
        if value.get("source") != "hold" and isinstance(value.get("stop"), str):
            _loop_hold.record(repo, loop, value["stop"])  # a stop from before the hold
        return value
    moment = int(time.time() * 1000) if now is None else now
    raw = key.public_key().public_bytes_raw()
    signer = key_fingerprint(raw)
    target = run or _control_run(repo, loop, reason)
    claim = {"convention": CONVENTION, "loop": loop, "reason": reason,
             "stopped_at": _rfc3339(moment)}  # fmt: skip
    attestation = attest(repo, target, claim, signer=signer, key=key, algorithm="ed25519")
    new = {"loop": loop, "status": "stopped", "stop": attestation, "signer": signer,
           "updated_ms": moment}  # fmt: skip
    _loop_hold.record(repo, loop, attestation)  # first: a lost race still leaves a stop
    if swap(repo, name, KIND, new, oid, links=[attestation]) is None:
        return stop(repo, loop, key, reason=reason, run=run, now=now)  # a racing stop
    return new


def loop_state(repo: Any, loop: str) -> dict[str, Any]:
    """``{"loop", "status": "running"|"stopped", ...}`` with the stop's verification."""
    _, value = _stop_record(repo, loop)
    if value is None:
        return {"loop": loop, "status": "running"}
    return {**value, "verification": verify_stop(repo, loop, value.get("stop"))}


def verify_stop(repo: Any, loop: str, oid: Any) -> str:
    """``verified`` when *oid* is an Ed25519-signed ``opentine.loop-stop/1`` for *loop*."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - a missing or malformed stop is reported, not raised
        return "unverified: the stop attestation cannot be read"
    claim = payload.get("claim") if isinstance(payload, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return "unverified: not an opentine.loop-stop/1 claim"
    if claim.get("loop") != loop:
        return "unverified: the stop names another loop"
    result = verify_attestation(payload, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return f"unverified: {result.state}"
    if used_key_fingerprint(payload.get("signature")) != payload.get("signer"):
        return "unverified: the signer field does not name the key that signed"
    return _stopper(repo, payload.get("signer"))


def _stopper(repo: Any, signer: Any) -> str:
    from opentine._key_roles import STOPPER, KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return f"unverified: key-role policy: {exc}"
    roles = found["roles"]
    if roles and roles.get(STOPPER) and found["status"] != "pinned":
        return "unverified: the stopper role is unpinned (no owner-signed trust bundle)"
    if roles and roles.get(STOPPER) and signer not in roles[STOPPER]:
        return "unverified: the signer is not a stopper key"
    return "verified"


def fence(repo: Any, task: dict[str, Any]) -> None:
    """Refuse (:class:`LoopStopped`) a lease on a generation of a stopped loop."""
    loops = [task["loop"]] if task.get("loop") else _loop_hold.namespace(task.get("task", ""))
    for loop in loops:
        _, value = _stop_record(repo, loop)
        if value is not None:
            state = verify_stop(repo, loop, value.get("stop"))
            raise LoopStopped(f"loop {loop} was stopped by {value.get('signer')} ({state}); "
                              f"no further generation may take or extend a lease")  # fmt: skip


def loop_history(repo: Any, loop: str) -> list[dict[str, Any]]:
    return history(repo, repo.read_ref(ref_name(loop)))


__all__ = ["CONVENTION", "KIND", "LoopStopped", "fence", "loop_history", "loop_state",
           "ref_name", "stop", "verify_stop"]  # fmt: skip
