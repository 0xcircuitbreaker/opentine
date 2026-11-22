"""Reference self-improving loop: every variant gated by signed OpenTine records.

    python examples/self_improving_loop.py WORKDIR [--steps 8] [--model stub|anthropic]
                                           [--no-seeded-faults] [--cap-usd 10]
                                           [--verify] [--require-ts]

A small loop improves a toy solver one variant at a time. Each step records the
mutation run, its spend and sandbox policy, monitor verdicts, signed visible,
sealed-holdout and canary evals and an integrity check; two of three approvers
must sign; the policy key signs an admission decision; and only then can
``tine promote --require-admission promote`` move the ``prod`` label. A
promoted variant that regresses on the canary is reverted. By default the stub
model seeds a reward hack at step 2 (caught and never promoted) and a hidden
regression at step 4 (promoted, then reverted by the canary).

The default model is a deterministic stub: no network and no key. ``--model
anthropic`` asks a real model (bring your own key: ``ANTHROPIC_API_KEY`` and the
optional ``anthropic`` package; ``OPENTINE_LOOP_MODEL`` picks the model).
``--verify`` then checks every object and signed record the run wrote with the
Python verifier, a freshly built ``tine-verify.pyz`` and, when built, the TS
verifier (``--require-ts`` makes TS mandatory), via ``scripts/verify_everywhere.py``.
See docs/REFERENCE-LOOP.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reference_loop.loop import run_loop  # noqa: E402
from reference_loop.models import AnthropicModel, StubModel  # noqa: E402

RECORD_DIRS = ("approvals", "evals", "integrity", "policy", "promotion", "sandbox")


def verify(work: Path, *, require_ts: bool) -> int:
    """Every object of the run's repository and every signed record, by every verifier."""
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    sys.path.insert(0, str(scripts))
    from verify_everywhere import main as verify_everywhere

    targets = [(work / "repo").as_posix()]
    targets += [(work / name).as_posix() for name in RECORD_DIRS if (work / name).is_dir()]
    return verify_everywhere(targets + (["--require-ts"] if require_ts else []))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("workdir", nargs="?", help="Where the repository and report go")
    parser.add_argument("--steps", type=int, default=8, help="Iterations (default 8)")
    parser.add_argument("--model", choices=("stub", "anthropic"), default="stub")
    parser.add_argument("--no-seeded-faults", action="store_true",
                        help="Stub only: no seeded reward hack or regression")  # fmt: skip
    parser.add_argument("--cap-usd", type=float, default=10.0, help="Budget cap (USD)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify every produced object with python, pyz and TS")  # fmt: skip
    parser.add_argument("--require-ts", action="store_true", help="With --verify: TS is required")
    args = parser.parse_args(argv)
    work = Path(args.workdir or tempfile.mkdtemp(prefix="reference-loop-"))
    if args.model == "anthropic":
        model = AnthropicModel()
    elif args.no_seeded_faults:
        model = StubModel()
    else:
        model = StubModel(hack_at=2, regress_at=4)
    report = run_loop(work, steps=args.steps, model=model, cap_usd=args.cap_usd)
    for row in report["steps"]:
        if "stopped" in row:
            print(f"step {row['step']}: stopped ({row['stopped']})")
            continue
        verdict = "kept" if row["kept"] else ("reverted" if row["canary"] == "revert"
                                              else "refused")  # fmt: skip
        extra = f" [{row['seeded']}]" if row["seeded"] else ""
        print(f"step {row['step']}: {verdict}{extra} visible={row['scores']['visible']:.2f} "
              f"holdout={row['scores']['holdout']:.2f} {row['note']}")  # fmt: skip
    curated = report["final"]["curated"]
    print(
        f"champion knows {report['champion']['ops']}; curated "
        f"{len(curated.get('members', []))} runs, excluded {len(curated.get('excluded', []))}"
    )
    print(f"report: {(work / 'report.json').as_posix()}")
    print(json.dumps({"champion": report["champion"]["variant"]}))
    return verify(work, require_ts=args.require_ts) if args.verify else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
