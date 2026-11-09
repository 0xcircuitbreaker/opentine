"""Where ``tine verify --offline`` checks a run's delegation chain (X32).

A run captured with ``OPENTINE_DELEGATION`` carries an ``opentine-delegation/1``
chain in ``metadata.delegation`` (``_fleet_record``). When it does, the report
gains a ``delegation`` check: the chain must verify (``_delegation_verify``) for
the key the signature verdict rests on, at the verified signing time (else the
claimed one), for the run's agent (its ``agt_`` ref, harness, fleet member or
role) and for every tool the run used. The detail names the chain, root first.
The root is trusted only when it is one of ``--pin``; otherwise the check says
so in its trust basis.

0.48: the key-lifecycle registry (``tine key revoke``, a trusted agents.toml, a
trust policy's ``key_lifecycle``) applies to every key on the chain: one
revoked at or before the verified signing time refuses the chain with
``delegation.revoked``, and without a verified time any revocation does.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._verify_report import Check

NAME = "delegation"


def agent_names(run: Any) -> list[str]:
    from opentine._agent_identity import run_agent_ref, run_identity
    from opentine._fleet_record import run_record

    names = [run_agent_ref(run)]
    identity = run_identity(run)
    if identity is not None:
        names.append(identity["harness"])
    record = run_record(run)
    if record is not None:
        names += [value for value in (record["member"], record["role"]) if value]
    return names


def tool_names(run: Any) -> list[str]:
    from opentine._graph_types import StepKind

    found: set[str] = set()
    steps = getattr(run, "steps", None) or {}
    for step in steps.values() if isinstance(steps, dict) else steps:
        if step.kind != StepKind.tool:
            continue
        for source in (step.tool_info, step.inputs):
            name = source.get("name") if isinstance(source, dict) else None
            if isinstance(name, str) and name:
                found.add(name)
                break
    return sorted(found)


def revocations(args: argparse.Namespace) -> dict[str, str]:
    """``{fingerprint: earliest revoked_at}`` across every lifecycle source."""
    from opentine._key_lifecycle import parse_time
    from opentine._key_lifecycle_verify import sources

    out: dict[str, str] = {}
    for table in sources(args):
        for fpr, window in table.items():
            at = window.get("revoked_at")
            if at and (fpr not in out or parse_time(at) < parse_time(out[fpr])):
                out[fpr] = at
    return out


def delegation_check(
    args: argparse.Namespace, path: Path, run: Any, signature: Check, verified: str | None
) -> Check | None:
    """The ``delegation`` check, or ``None`` when the run claims no delegation."""
    from opentine._delegation import DelegationError
    from opentine._delegation_verify import verify_chain
    from opentine._key_lifecycle_verify import signer
    from opentine._signing_keys import SignatureError
    from opentine._signing_pins import normalize_pin

    metadata = getattr(run, "metadata", None)
    chain = metadata.get("delegation") if isinstance(metadata, dict) else None
    if chain is None:
        return None
    if signature.outcome != "pass":
        detail = "the run claims a delegation chain but its signature did not verify"
        return Check(NAME, "fail", "delegation.unsigned", detail, "none", required=True)
    try:
        fpr, claimed = signer(args, path)
        at = verified or claimed
        if fpr is None or at is None:
            raise DelegationError("delegation.wrong-signer", "no Ed25519 signer or signing time")
        result = verify_chain(chain, signer=fpr, at=at, agent=agent_names(run),
                              actions=tool_names(run), revoked=revocations(args),
                              time_verified=verified is not None)  # fmt: skip
    except (DelegationError, OSError, SignatureError, ValueError) as exc:
        code = getattr(exc, "code", "delegation.malformed")
        return Check(NAME, "fail", code, str(exc), "none", required=True)
    pins = set()
    for value in getattr(args, "pin", None) or ():
        try:
            pins.add(normalize_pin(value))
        except SignatureError:
            continue
    root = result["root"]
    links = " -> ".join([root, *result["links"]])
    detail = f"{len(result['links'])} link(s): {links}; leaf {fpr}"
    if root in pins:
        return Check(
            NAME, "pass", "delegation.verified", detail, f"pinned root {root}", authenticates=True
        )
    return Check(
        NAME, "pass", "delegation.verified", detail, f"unpinned root {root} (pin it with --pin)"
    )


__all__ = ["NAME", "agent_names", "delegation_check", "revocations", "tool_names"]
