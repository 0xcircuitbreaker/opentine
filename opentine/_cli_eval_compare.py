"""``tine eval compare --ci``: the statistical comparison's CLI half (0.58)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def compare_ci(args: argparse.Namespace, public_key: bytes | None) -> dict[str, Any]:
    from opentine._canon import atomic_write_text
    from opentine._eval_compare import attest, statistical
    from opentine._signing_keys import ed25519_private_from_file

    if args.attest and not args.out:
        raise ValueError("--attest needs --out FILE")
    row = statistical(Path(args.left), Path(args.right), method=args.ci, alpha=args.alpha,
                      seed=args.seed, resamples=args.resamples,
                      public_key=public_key)  # fmt: skip
    data = row.pop("export")
    if args.export and data is not None:
        atomic_write_text(Path(args.export), json.dumps(data, indent=2, sort_keys=True) + "\n")
        row["export"] = args.export
    if args.attest:
        row["export"] = data
        key = ed25519_private_from_file(args.attest, signer=False)
        document = attest(row, key, signed_at=args.signed_at)
        atomic_write_text(Path(args.out), json.dumps(document, indent=2, sort_keys=True) + "\n")
        row["export"] = args.export
        row["attestation"] = args.out
    return row


def table(row: dict[str, Any]) -> None:
    from opentine._cli_common import console

    stats = row["stats"]
    console.print(f"{stats['method']}  n={stats['n']}  alpha={stats['alpha']}  "
                  f"seed={stats['seed']}  resamples={stats['resamples']}",
                  highlight=False, markup=False)  # fmt: skip
    console.print(f"  {'metric':<10} {'A':>9} {'B':>9} {'delta':>10}  {'interval / p':<24} verdict",
                  highlight=False, markup=False)  # fmt: skip
    for name, m in stats["metrics"].items():
        spread = f"[{m['ci'][0]}, {m['ci'][1]}]" if m["ci"] else f"p={m['p_value']}"
        verdict = ("REGRESSION" if m["regression"] else "improvement" if m["improvement"]
                   else "no significant change")  # fmt: skip
        console.print(f"  {name:<10} {m['a'] or '-':>9} {m['b'] or '-':>9} {m['delta']:>10}  "
                      f"{spread:<24} {verdict}", highlight=False, markup=False)  # fmt: skip


__all__ = ["compare_ci", "table"]
