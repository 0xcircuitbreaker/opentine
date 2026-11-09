"""Assurance tiers (X21): how much of a run anything other than the agent saw.

* **T0** -- self-reported: an imported transcript or trace the agent wrote.
* **T1** -- hook-captured: ``tine hook capture`` saw each turn as it happened.
* **T2** -- witnessed: the record proxy or ``tine mcp-proxy`` relayed the traffic
  and signed the run (``tine-sig/3``, Ed25519) with the **proxy key**, a key
  made by ``tine proxy keygen`` and kept apart from every agent key.
* **T3** -- T2 plus an RFC 3161 timestamp token over the run's digest.

The tier a capture *claims* is recorded beside the run (``metadata.capture`` or a
hook step attribute), but that claim is the run's own word. The *verified* tier
is computed here from what can be checked: a proxy signature that a trusted
proxy key verifies, and a timestamp token that a trusted TSA root verifies. A
claim alone never lifts a run above T1.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._proxy_key import key_paths, keygen, signing_key

TIERS = ("T0", "T1", "T2", "T3")
#: Metadata ``capture.method`` values whose runs a proxy saw (and signs).
PROXY_METHODS = frozenset({"mcp-proxy", "record-proxy"})
HOOK_ATTRIBUTE = "opentine.hook.protocol"
CLAIM_ATTRIBUTE = "opentine.capture.claimed_tier"
SIGNER = "opentine-proxy"


def rank(tier: str) -> int:
    return TIERS.index(tier)


def proxy_marker(method: str) -> dict[str, Any]:
    """The ``metadata.capture`` a proxy records: a T2 *claim*, checked at verify time."""
    return {"method": method, "claimed_tier": "T2", "agent_writable": False}


def witness_save(run: Any, path: Path) -> bool:
    """Save *run* signed with the proxy key; False (saved unsigned) without one."""
    key = signing_key()
    if key is None:
        run.save(path)
        return False
    from opentine._signing_pins import key_fingerprint

    fpr = key_fingerprint(key.public_key().public_bytes_raw())
    run.save(path, sign_key=key, sign_algorithm="ed25519", key_id=fpr, signer=SIGNER)
    return True


def proxy_witnesses(extra: list[str] | None = None) -> list[tuple[str, Any]]:
    """``(fingerprint, public key)`` of every proxy key trusted here.

    This user's own proxy key plus each ``--proxy-pubkey FILE``. A key that is
    also one of this user's agent keys is never a proxy key: the agent holds it.
    """
    from opentine._agent_keys import local_fingerprints
    from opentine._proxy_key import retired_publics
    from opentine._signing_pins import key_fingerprint
    from opentine.signing import SignatureError, ed25519_public_from_file

    own = [key_paths()[1], *retired_publics()]
    paths = [*own, *(Path(p) for p in extra or [])]
    agents = local_fingerprints()
    found: list[tuple[str, Any]] = []
    for path in paths:
        try:
            public = ed25519_public_from_file(path)
        except (OSError, SignatureError):
            if path in own:
                continue
            raise
        fpr = key_fingerprint(public.public_bytes_raw())
        if fpr not in agents and all(fpr != seen for seen, _ in found):
            found.append((fpr, public))
    return found


def claimed_tier(run: Any) -> str:
    """The tier the capture claims, from what was recorded with it."""
    metadata = getattr(run, "metadata", None) or {}
    capture = metadata.get("capture") if isinstance(metadata, dict) else None
    if isinstance(capture, dict) and capture.get("claimed_tier") in TIERS:
        return str(capture["claimed_tier"])
    if isinstance(capture, dict) and capture.get("method") in PROXY_METHODS:
        return "T2"
    if isinstance(metadata, dict) and ("mcp_proxy" in metadata or "record" in metadata):
        return "T2"
    for step in getattr(run, "steps", None) or ():
        attributes = getattr(step, "attributes", None) or {}
        if isinstance(attributes, dict) and (
            attributes.get(CLAIM_ATTRIBUTE) == "T1" or HOOK_ATTRIBUTE in attributes
        ):
            return "T1"
    return "T0"


def _witness(data: Any, keys: list[tuple[str, Any]]) -> tuple[str | None, str]:
    from opentine.core import Run

    if not keys:
        return None, "no trusted proxy key (run `tine proxy keygen`, or pass --proxy-pubkey)"
    reason = "no signature"
    for fpr, public in keys:
        verdict = Run.verify_signature(data, public_key=public)
        if verdict.ok:
            return fpr, "signed by a trusted proxy key"
        reason = f"proxy signature did not verify ({verdict.state}: {verdict.reason})"
    return None, reason


def _timestamped(path: Path, integrity: Any, args: Any) -> tuple[bool, str]:
    from opentine import _timestamp_sidecar as sidecar
    from opentine._verify_timestamp import _roots

    try:
        entries = sidecar.load(path)
    except (OSError, ValueError) as exc:
        return False, f"timestamp sidecar unreadable: {exc}"
    bound = sidecar.bound_string(integrity)
    if not entries or bound is None:
        return False, "no timestamp token"
    if not getattr(args, "tsa_roots", None) and not getattr(args, "trusted_root", None):
        return False, "timestamp token present but not checked: pass --tsa-roots"
    from opentine._tsp_verify import verify_token

    roots, windowed, _ = _roots(args)
    for stored, token in entries:
        if stored == bound and verify_token(token, bound.encode("utf-8"), roots, windowed).ok:
            return True, "RFC 3161 timestamp verified"
    return False, "no timestamp token verified against the TSA roots"


def assess(path: str | Path, args: Any = None) -> dict[str, Any]:
    """The run's ``assurance`` object: claimed and verified tier, and why."""
    from opentine._cli_verify_report import read_once
    from opentine._graph_serde import load_run_data
    from opentine.core import Run

    args = args or argparse.Namespace()
    witnesses = proxy_witnesses(getattr(args, "witness_files", None))  # bad --proxy-pubkey fails
    source = read_once(path)
    integrity = Run.verify_integrity(source if isinstance(source, dict) else path)
    try:
        run = load_run_data(source, Run) if isinstance(source, dict) else None
    except (KeyError, RecursionError, TypeError, ValueError):
        run = None
    claimed = claimed_tier(run)
    verified, witness, reasons = ("T1" if claimed == "T1" else "T0"), None, []
    if not integrity.ok:
        reasons.append("integrity failed: no tier above the claim's floor")
        verified = "T0"
    elif claimed in ("T2", "T3") and isinstance(source, dict):
        witness, why = _witness(source, witnesses)
        reasons.append(why)
        if witness:
            verified = "T2"
            stamped, why = _timestamped(Path(path), integrity, args)
            reasons.append(why)
            verified = "T3" if stamped else "T2"
    else:
        reasons.append(f"claimed {claimed}: no proxy witnessed this capture")
    found = {"claimed": claimed, "verified": verified, "witness": witness, "reasons": reasons}
    from opentine._oms_factor import factors

    extra = factors(args)  # 0.48: factors beside the tier (an OMS model signature)
    return {**found, "factors": extra} if extra else found


def line(assurance: dict[str, Any]) -> str:
    """One human line for a report."""
    from rich.markup import escape

    style = "green" if rank(assurance["verified"]) >= 2 else "yellow"
    why = "; ".join(assurance.get("reasons") or [])
    text = f"[{style}]assurance {assurance['verified']}[/] (claimed {assurance['claimed']})" + (
        f" [dim]{escape(why)}[/]" if why else ""
    )
    for factor in assurance.get("factors") or []:
        mark = "[green]ok[/]" if factor["ok"] else f"[red]FAILED {escape(factor['reason'])}[/]"
        text += f"\n{escape(factor['factor'])} {mark} [dim]{escape(factor['detail'])}[/]"
    return text


__all__ = [
    "CLAIM_ATTRIBUTE",
    "PROXY_METHODS",
    "TIERS",
    "assess",
    "claimed_tier",
    "keygen",
    "key_paths",
    "line",
    "proxy_marker",
    "rank",
    "signing_key",
    "proxy_witnesses",
    "witness_save",
]
