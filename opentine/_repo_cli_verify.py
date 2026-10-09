"""``tine repo-verify``: check the ``tine-attest/1`` signature on v3 attestations.

The v3 twin of ``tine verify``'s authenticity half, and prefixed for the same
reason ``repo-fork`` is: ``verify`` is a legacy ``.tine`` verb. There is no
integrity half to mirror — a v3 object is content-addressed and ``fsck`` already
recomputes every digest — so this verb answers only the question content
addressing cannot: *was this claim actually made by the holder of a key?*

**One attestation, or every attestation on a run.** The argument resolves like
every other v3 verb: an ``attestation:sha256:…`` oid checks that one object, and
a run oid or a ref (``heads/main``, ``promotions/prod``) checks every attestation
targeting that run. The second form is the operator's real question — "is this
release approved, and by whom?" — and it is the one a promotion gate scripts.

**Fail-closed, exactly as ``tine verify`` is.** Supplying any key
(``--key-env`` / ``--key-file`` / ``--pubkey``), ``--trust-embedded-key``, or
``--require-signature`` *arms* the check, and an armed run exits non-zero unless
every attestation reported ``verified``. ``--require-signature`` additionally
refuses a run carrying **no** attestation at all: "nothing to check" is not a
pass when the operator asked for a valid signature. With nothing armed the verb
is a report — it prints each state and exits 0 — because an unarmed check has
verified nothing and must not look like it has.

**Scope the gate to the claim it is about.** Unscoped, every attestation on
the run must verify -- so any writer could block a release with one unsigned
note, and a verified *rejection* passed exactly as an approval did, because the
check never looked at what was signed. ``--signer NAME`` (repeatable) and
``--claim JSON`` (the attestation's claim must contain these keys with these
values) select the attestations the gate is about; it then passes when at least
one selected attestation verifies, and the rest are reported but neither pass
nor block it. Either flag arms the check. Each row carries its ``claim``.

**The verdict vocabulary is artifact signing's**, unchanged: ``verified``,
``verified-tofu``, ``unsigned``, ``no-key``, ``mismatch``, ``error``. Only the
first two carry ``ok``.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_claim import parse_claim
from opentine._repo_cli_keys import verification_armed, verification_keys
from opentine._repo_cli_render import _short_oid
from opentine.attest_signing import verify_attestation
from opentine.kernel import parse_oid
from opentine.repo import Repo
from opentine.repository.ops import resolve_target

#: A state's colour in the human output. Anything unlisted is a refusal state.
_STATE_STYLE = {"verified": "green", "verified-tofu": "yellow", "unsigned": "yellow"}


def _targets(repo: Repo, value: str) -> tuple[str, list[str]]:
    """Resolve *value* to the attestations it names: itself, or a run's whole set."""
    try:
        oid = resolve_target(repo, value)
    except KeyError:
        raise KeyError(f"cannot resolve {value}: no such ref or object in {repo.path}") from None
    kind = parse_oid(oid)[0]
    if kind not in {"attestation", "run"}:
        raise ValueError(f"{value} resolves to {oid}, which is neither a run nor an attestation")
    if not repo.has(oid):
        raise KeyError(f"cannot resolve {value}: no such ref or object in {repo.path}")
    if kind == "attestation":
        return oid, [oid]
    return oid, list(repo.attestations_for(oid))


def _row(repo: Repo, oid: str, keys: dict[str, Any]) -> dict[str, Any]:
    """Verify one attestation and flatten its verdict into the JSON row shape."""
    payload = repo.get(oid).payload()
    result = verify_attestation(payload if isinstance(payload, dict) else None, **keys)
    claimed = payload.get("signer") if isinstance(payload, dict) else None
    return {
        "attestation_id": oid,
        "target_id": payload.get("target_id") if isinstance(payload, dict) else None,
        "signer": claimed if isinstance(claimed, str) else None,
        "state": result.state,
        "ok": result.ok,
        "algorithm": result.algorithm,
        "key_id": result.key_id,
        "signed_at": result.signed_at,
        "scheme": (payload.get("signature") or {}).get("scheme")
        if isinstance(payload.get("signature"), dict)
        else None,
        "reason": result.reason,
        "claim": payload.get("claim") if isinstance(payload, dict) else None,
    }


def _selects(row: dict[str, Any], signers: list[str], claim: dict[str, Any] | None) -> bool:
    if signers and row["signer"] not in signers:
        return False
    held = row["claim"] if isinstance(row["claim"], dict) else {}
    return claim is None or all(key in held and held[key] == claim[key] for key in claim)


def _render(console, rows: list[dict[str, Any]], target: str, scoped: bool) -> None:
    for row in rows:
        style = _STATE_STYLE.get(row["state"], "red")
        aside = "" if row["selected"] or not scoped else " [dim](not selected)[/]"
        console.print(
            f"[{style}]{row['state']}[/] {_short_oid(row['attestation_id'])} "
            f"signer={_terminal(row['signer'] or '-')} "
            f"alg={_terminal(row['algorithm'] or '-')} "
            f"key_id={_terminal(row['key_id'] or '-')}{aside}"
        )
        if not row["ok"]:
            console.print(f"  [dim]{_terminal(row['reason'])}[/]")
    verified = sum(1 for row in rows if row["ok"])
    console.print(f"{verified} of {len(rows)} attestation(s) verified on {_short_oid(target)}")
    if scoped:
        chosen = [row for row in rows if row["selected"]]
        good = sum(1 for row in chosen if row["ok"])
        console.print(f"{good} of {len(chosen)} selected attestation(s) verified")


def cmd_repo_verify(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    target_id, oids = _targets(repo, args.target)
    keys = verification_keys(args)
    signers = list(getattr(args, "signer", None) or [])
    claim = parse_claim(args) if getattr(args, "claim", None) else None
    scoped = bool(signers) or claim is not None
    rows = [_row(repo, oid, keys) for oid in oids]
    for row in rows:
        row["selected"] = _selects(row, signers, claim)
    require = bool(getattr(args, "require_signature", False))
    if scoped:
        ok = any(row["ok"] for row in rows if row["selected"])
    else:
        # Vacuous truth is not a pass: --require-signature on a run with no
        # attestation asked for a valid signature and found none.
        ok = all(row["ok"] for row in rows) and not (require and not rows)
    if getattr(args, "json", False):
        emit(
            {
                "command": "repo-verify",
                "repo": str(repo.path),
                "target": args.target,
                "target_id": target_id,
                "require_signature": require,
                "signers": signers,
                "claim": claim,
                "selected": sum(1 for row in rows if row["selected"]),
                "count": len(rows),
                "verified": sum(1 for row in rows if row["ok"]),
                "ok": ok,
                "attestations": rows,
            }
        )
    else:
        _render(console, rows, args.target, scoped)
        if require and not rows:
            console.print("[red]--require-signature[/]: no attestation targets this run")
        if scoped and not ok:
            console.print("[red]no selected attestation verified[/]")
    if (verification_armed(args) or scoped) and not ok:
        raise SystemExit(1)


__all__ = ["cmd_repo_verify"]
