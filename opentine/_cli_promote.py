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
    p.add_argument("--spent", default="0", metavar="USD", help="Spend to check against the cap")
    p.add_argument("--state", metavar="DIR", help="Label state (default REPO/.tine/promotion)")
    p.add_argument("--out", metavar="DIR", help="Where decisions go (a FILE for --approve)")
    p.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--approve", action="store_true", help="Sign an approval for TARGET")
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
    if args.approve:
        if not args.out:
            raise ValueError("--approve needs --out FILE")
        document = promotion.approve(key, args.target, args.baseline, at=args.at)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
        return {"action": "approve", "label": args.baseline, "candidate": args.target,
                "out": args.out, "refusals": []}  # fmt: skip
    if not (args.policy and args.out):
        raise ValueError("--policy and --out are required")
    policy = load_policy(Path(args.policy))
    state = Path(args.state) if args.state else Path(args.repo) / promotion.STATE
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
    holdout = (Path(args.holdout[0]), Path(args.holdout[1])) if args.holdout else None
    return promotion.promote(key, policy, args.target, args.baseline,
                             baseline=Path(args.baseline_evals), evals=Path(args.evals),
                             holdout=holdout, approvals=[Path(a) for a in args.approval],
                             spent=args.spent, **common)  # fmt: skip


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
        console.print(f"{row['action'].upper()} {row['label']}: {holder}", markup=False)
    else:
        console.print(f"REFUSED {args.baseline} -> {args.target}", highlight=False, markup=False)
        for item in row["refusals"]:
            console.print(f"  {item['code']}: {item['detail']}", highlight=False, markup=False)
    if not row["ok"]:
        raise SystemExit(1)


__all__ = ["add_signed_promote_args", "cmd_signed_promote"]
