"""``tine promote TARGET --baseline LABEL``: signed promotion, revert, canary (0.58)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_errors import ERROR, fail


def add_signed_promote_args(p: Any) -> None:
    """``tine promote TARGET --baseline LABEL ...`` on the existing ``promote`` verb."""
    p.add_argument("--baseline", metavar="LABEL", help="Signed promotion: the label to move")
    p.add_argument("--key", metavar="KEY", help="Ed25519 private key that signs (--baseline)")
    p.add_argument("--policy", metavar="TOML", help="Promotion policy ([promote] table)")
    p.add_argument("--baseline-evals", metavar="DIR", help="The baseline's eval folder")
    p.add_argument("--evals", metavar="DIR", help="The candidate's eval folder")
    p.add_argument("--holdout", nargs=2, metavar=("BASE_DIR", "CAND_DIR"),
                   help="Holdout eval folders: baseline, then candidate")  # fmt: skip
    p.add_argument("--approval", action="append", default=[], metavar="FILE",
                   help="A signed approval (--approve); repeatable")  # fmt: skip
    p.add_argument("--policy-attestation", action="append", default=[], metavar="FILE",
                   help="A signed policy (--sign-policy), for a 'policy' role")  # fmt: skip
    p.add_argument("--spent", metavar="USD", help="Spend to check against the cap (required)")
    p.add_argument("--sealed-holdout", action="append", default=[], metavar="DIR",
                   help="A sealed holdout whose exposure budget must hold (0.60)")  # fmt: skip
    p.add_argument("--canary-lengths", metavar="FILE",
                   help="Canary code lengths; a failed canary-check refuses")  # fmt: skip
    p.add_argument("--require-admission", action="append", default=[], metavar="POLICY",
                   help="A policy (name, ./file or sha256: digest) that must have admitted "
                   "TARGET (tine policy check --key); repeatable (0.75)")  # fmt: skip
    p.add_argument("--admission-param", action="append", default=[], metavar="NAME=VALUE",
                   help="A policy param for the --require-admission input (as tine policy "
                   "check --param); repeatable")  # fmt: skip
    p.add_argument("--loop", metavar="LOOP", help="Refuse when LOOP is stopped (tine loop stop)")
    p.add_argument("--state", metavar="DIR", help="Label state (default REPO/.tine/promotion)")
    p.add_argument("--out", metavar="DIR", help="Where decisions go (a FILE for --approve)")
    p.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--approve", action="store_true", help="Sign an approval for TARGET")
    mode.add_argument("--sign-policy", action="store_true",
                      help="Sign TARGET, a [promote] policy file")  # fmt: skip
    mode.add_argument("--revert", action="store_true", help="Revert LABEL from TARGET")
    mode.add_argument("--canary", metavar="DIR", help="Canary eval folder; revert on regression")
    p.add_argument("--reason", default="manual", help="Why --revert (recorded, signed)")


def _run(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _promote as promotion
    from opentine._promote_checks import load_policy
    from opentine._signing_keys import ed25519_private_from_file

    if not args.key:
        raise ValueError("--baseline needs --key KEY")
    key = ed25519_private_from_file(args.key, signer=False)
    state = Path(args.state) if args.state else Path(args.repo) / promotion.STATE
    if args.approve or args.sign_policy:
        if not args.out:
            raise ValueError("--approve and --sign-policy need --out FILE")
        if args.sign_policy:
            from opentine._promote_pins import sign_policy

            document = sign_policy(key, load_policy(Path(args.target)), args.at or promotion._now())
        else:
            document = promotion.approve(key, args.target, args.baseline, state=state, at=args.at)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
        action = "sign-policy" if args.sign_policy else "approve"
        row = {"action": action, "candidate": args.target, "out": args.out, "refusals": []}
        return row | ({"label": args.baseline} if args.baseline else {})
    if not (args.policy and args.out):
        raise ValueError("--policy and --out are required")
    policy = load_policy(Path(args.policy))
    common = {"state": state, "out": Path(args.out),
              "at": args.at}  # fmt: skip
    if args.revert:
        return promotion.revert(key, policy, args.target, args.baseline, reason=args.reason,
                                **common)  # fmt: skip
    if not args.baseline_evals:
        raise ValueError("--baseline-evals is required")
    if args.canary:
        return promotion.canary(key, policy, args.target, args.baseline,
                                baseline=Path(args.baseline_evals),
                                canary_evals=Path(args.canary), **common)  # fmt: skip
    if not args.evals:
        raise ValueError("--evals is required")
    if args.spent is None:
        raise ValueError("--spent USD is required: the budget cap is checked against it")
    holdout = (Path(args.holdout[0]), Path(args.holdout[1])) if args.holdout else None
    from opentine._promote import PromotionRefused
    from opentine._promote_admission import refusals

    if not_admitted := refusals(
        Path(args.repo), args.target, args.require_admission, args.admission_param
    ):
        raise PromotionRefused(not_admitted)  # before the gate can move the label
    return promotion.promote(key, policy, args.target, args.baseline,
                             baseline=Path(args.baseline_evals), evals=Path(args.evals),
                             holdout=holdout, approvals=[Path(a) for a in args.approval],
                             spent=args.spent, repo_path=Path(args.repo),
                             loop=args.loop, **common, policy_attestations=[
                                 Path(a) for a in args.policy_attestation],
                             sealed_holdouts=[Path(d) for d in args.sealed_holdout],
                             canary_lengths=Path(args.canary_lengths) if args.canary_lengths
                             else None)  # fmt: skip


def cmd_signed_promote(args: argparse.Namespace) -> None:
    from opentine._cli_common import console
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable
    from opentine._promote import PromotionRefused
    from opentine._signing_keys import SignatureError

    try:
        row = {"ok": True, **_run(args)}
    except PromotionRefused as exc:
        row = {"ok": False, "action": "refused", "label": args.baseline,
               "candidate": args.target, "refusals": exc.refusals}  # fmt: skip
    except (PassphraseUnavailable, SignatureError, OSError, ValueError, KeyError) as exc:
        fail(exc, ERROR, prefix="promote: ", cause=exc)
    if args.json:
        emit({"command": "promote", **row})
    elif row["ok"]:
        holder = row.get("current", row["candidate"])
        label = row.get("label", "policy")
        console.print(f"{row['action'].upper()} {label}: {holder}", markup=False)
    else:
        console.print(f"REFUSED {args.baseline} -> {args.target}", highlight=False, markup=False)
        for item in row["refusals"]:
            console.print(f"  {item['code']}: {item['detail']}", highlight=False, markup=False)
    if not row["ok"]:
        raise SystemExit(1)


__all__ = ["add_signed_promote_args", "cmd_signed_promote"]
