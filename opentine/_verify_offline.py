"""The checks ``tine verify RUN --offline`` chains, each a :class:`Check`.

Every check reuses the online command's own verifier (``Run.verify_integrity``,
``_cli_security.signature_result``, ``_actions_verdict.verify``,
``_actions_policy.evaluate``); this module only decides what each verdict
*means* offline and what it rests on. A check whose key or root was not
supplied is ``unavailable-offline``, never a pass. The attestation, receipt and
certificate checks live in :mod:`opentine._verify_offline_attest`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._verify_report import INTERNAL_ONLY, Check

_DIGEST_REASONS = (
    ("ok", "digest.match"),
    ("digest mismatch", "digest.mismatch"),
    ("invalid artifact", "artifact.malformed-json"),
    ("file not found", "digest.unreadable"),
    ("read error", "digest.unreadable"),
    ("unsupported .tine format_version", "digest.unsupported-format"),
    ("missing integrity", "digest.missing"),
    ("malformed digest", "digest.malformed"),
    ("unsupported algorithm", "digest.unsupported-algorithm"),
)
_RECOMPUTED = f"{INTERNAL_ONLY} (sha256 recomputed from the file's own bytes)"


def digest_check(path: Path) -> tuple[Check, Any]:
    from opentine.core import Run

    result = Run.verify_integrity(path)
    reason = next(
        (code for prefix, code in _DIGEST_REASONS if (result.reason or "").startswith(prefix)),
        "digest.unreadable",
    )
    detail = f"sha256:{result.actual}" if result.ok else str(result.reason)
    if not result.ok and result.expected and result.actual:
        detail += f" (expected {result.expected}, actual {result.actual})"
    if result.ok and result.draft:
        detail += " (draft / autosave checkpoint)"
    outcome = "pass" if result.ok else "fail"
    return Check("digest", outcome, reason, detail, _RECOMPUTED, required=True), result


def signature_check(args: argparse.Namespace, path: Path, integrity_ok: bool) -> Check:
    from opentine._cli_security import signature_requested, signature_result
    from opentine.core import Run

    if not integrity_ok:
        return Check(
            "signature",
            "not-applicable",
            "signature.integrity-failed",
            "not checked: the digest already failed",
            "none",
            required=True,
        )
    if not signature_requested(args):
        unarmed = Run.verify_signature(path)
        if unarmed.state == "unsigned":
            detail, reason = "the run carries no signature", "signature.unsigned"
        else:
            detail = (
                f"signature present (alg={unarmed.algorithm}) but no trusted key was given: "
                "pass --pubkey, --pin, --key-file or --key-env"
            )
            reason = "signature.no-key"
        basis = "none: no trusted key supplied"
        return Check("signature", "unavailable-offline", reason, detail, basis, required=True)
    verdict, fpr = signature_result(args, path)
    state = verdict.state or "error"
    if not verdict.ok:
        outcome = "unavailable-offline" if state in ("no-key", "unsigned") else "fail"
        return Check(
            "signature",
            outcome,
            f"signature.{state}",
            str(verdict.reason),
            _basis(args, fpr),
            required=True,
        )
    tofu = "tofu" in state
    detail = (
        f"alg={verdict.algorithm} key_id={verdict.key_id or '-'} signer={verdict.signer or '-'}"
    )
    return Check(
        "signature",
        "pass",
        f"signature.{state}",
        detail + (" (self-asserted key: consistency, not authorship)" if tofu else ""),
        _basis(args, fpr, tofu=tofu),
        required=True,
        authenticates=not tofu,
    )


def _basis(args: argparse.Namespace, fpr: str | None, *, tofu: bool = False) -> str:
    if getattr(args, "key_env", None) or getattr(args, "key_file", None):
        return "shared HMAC secret (--key-env/--key-file)"
    if getattr(args, "pubkey", None):
        return f"supplied key {fpr or '-'} (--pubkey)"
    if getattr(args, "pin", None) and not tofu:
        return f"pinned key {fpr or '-'} (--pin)"
    return f"embedded key {fpr or '-'}, trust-on-first-use: {INTERNAL_ONLY}"


def actions_checks(args: argparse.Namespace, run: Any) -> list[Check]:
    """The action-manifest verdict and, with ``--action-policy``, the policy verdict."""
    return [_manifest_check(args, run), _policy_check(args, run)]


def _manifest_check(args: argparse.Namespace, run: Any) -> Check:
    from opentine import _cli_who_trust as who_trust
    from opentine._actions_verdict import Trust, load_manifest, verify
    from opentine._agent_keys import trusted_fingerprints
    from opentine._key_hygiene import hmac_key
    from opentine._signing_pins import normalize_pins
    from opentine.signing import ed25519_public_from_file

    if run is None:
        return Check("action-manifest", "not-applicable", "actions.no-run", "run did not load")
    _, base, agents = who_trust.scope_paths(args)
    stored = load_manifest(base, run.id)
    if stored is None:
        return Check("action-manifest", "not-applicable", "actions.absent", "no action manifest")
    key_env, key_file = getattr(args, "key_env", None), getattr(args, "key_file", None)
    secret = hmac_key(key_env, key_file) if key_env or key_file else None
    pubkey = getattr(args, "pubkey", None)
    public = ed25519_public_from_file(pubkey) if pubkey else None
    pins = normalize_pins(getattr(args, "pin", None)) | trusted_fingerprints(agents)
    if stored is False:
        trust = Trust("mismatch", "action manifest is unreadable")
    else:
        trust = verify(stored, run, hmac_key=secret, public_key=public, pins=pins)
    outcome = {"verified": "pass", "mismatch": "fail", "unknown-key": "unavailable-offline"}
    basis = INTERNAL_ONLY if trust.state != "verified" else f"key {trust.key or 'HMAC secret'}"
    return Check(
        "action-manifest",
        outcome.get(trust.state, "not-applicable"),
        f"actions.{trust.state}",
        trust.reason,
        basis,
        authenticates=False,
    )


def _policy_check(args: argparse.Namespace, run: Any) -> Check:
    import hashlib

    from opentine._actions_db import ActionIndex, Source
    from opentine._actions_policy import evaluate, load_policy

    file = getattr(args, "action_policy", None)
    if not file:
        return Check("action-policy", "not-applicable", "policy.none", "no --action-policy given")
    if run is None:
        return Check("action-policy", "fail", "policy.no-run", "run did not load", required=True)
    try:
        rules = load_policy(file)
        digest = hashlib.sha256(Path(file).read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        return Check("action-policy", "fail", "policy.unreadable", str(exc), "none", required=True)
    with ActionIndex(":memory:") as index:
        index.sync([Source(key="run", stamp="offline", load=lambda: run)])
        violations = evaluate(index, rules)
    deny = [v for v in violations if v.rule.level == "deny"]
    names = sorted({v.rule.id for v in violations})
    detail = f"{len(rules)} rule(s); violated: {', '.join(names) or 'none'}"
    reason = "policy.deny" if deny else ("policy.warn" if violations else "policy.ok")
    basis = f"action policy {Path(file).name} sha256 {digest}"
    return Check("action-policy", "fail" if deny else "pass", reason, detail, basis, required=True)


__all__ = ["actions_checks", "digest_check", "signature_check"]
