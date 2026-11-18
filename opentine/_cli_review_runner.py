"""``tine review runner`` and ``tine review runner-identity`` (0.55).

``runner REVIEW --fleet TOML --event PUSH.json --out DIR`` is what the review
runner image runs on every push (:mod:`opentine._review_runner`): the event is
a mirror sync's or a forge webhook's push. It writes ``DIR/findings.json`` (the
signed findings, what ``tine-verify.pyz`` checks), ``DIR/vsa.json`` (the DSSE
admission VSA), ``DIR/evals/<name>/`` (signed verdicts) and ``DIR/report.json``.
``runner-identity`` prints the runner's service identity, never trusted by
default; ``--previous-pubkey`` names the keys it rotated from.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def add_runner_parsers(actions: Any) -> list[argparse.ArgumentParser]:
    from opentine._review_runner import MODES

    runner = actions.add_parser("runner", help="Review, evaluate and attest one push")
    runner.add_argument("review_id")
    runner.add_argument("--fleet", required=True, metavar="TOML", help="The reviewers' fleet.toml")
    runner.add_argument("--trust", action="store_true", help="Trust this manifest's exact bytes")
    runner.add_argument("--event", required=True, metavar="JSON",
                        help="The push: {source, ref, before?, after?, at, run?}")  # fmt: skip
    runner.add_argument("--config", metavar="TOML", help="Runner config (.tine/runner.toml)")
    runner.add_argument("--hosting", choices=MODES, default="self-hosted")
    runner.add_argument("--out", required=True, metavar="DIR", help="Where decisions are written")
    ident = actions.add_parser("runner-identity", help="Print the runner's service identity")
    ident.add_argument("--previous-pubkey", action="append", default=[], metavar="FILE",
                       help="A key this identity was rotated from (repeatable)")  # fmt: skip
    for parser in (runner, ident):
        parser.add_argument("--ed25519-key-file", required=True, metavar="PATH",
                            help="The runner's own Ed25519 key, never a user's")  # fmt: skip
    runner.add_argument("--key-id", help="Key id recorded in the signatures")
    return [runner, ident]


def _write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", "utf-8")


def act(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _review_runner as runner
    from opentine._signing_keys import ed25519_private_from_file

    key = ed25519_private_from_file(args.ed25519_key_file)
    if args.review_action == "runner-identity":
        old = [bytes.fromhex(Path(p).read_text("utf-8").strip()) for p in args.previous_pubkey]
        found = runner.identity(key, old)
        return {"identity": found}, f"review runner {found['fingerprint']} (not trusted by default)"
    from opentine.fleet import _manifest

    root = Path(repo.worktree)
    config = runner.load_config(Path(args.config) if args.config else root / runner.CONFIG)
    event = json.loads(Path(args.event).read_text("utf-8"))
    fleet = _manifest.load(Path(args.fleet), trust_now=args.trust)
    out = Path(args.out)
    report = runner.run_push(repo, args.review_id, fleet, key, event, config=config,
                             mode=args.hosting, out=out, key_id=args.key_id)  # fmt: skip
    from opentine import _review_run

    _write(out / "findings.json", _review_run.load(repo, args.review_id))
    _write(out / "vsa.json", report["vsa"])
    _write(out / "report.json", report)
    found = len(report["review"]["findings"])
    text = (f"review runner ({args.hosting}): {found} finding(s), VSA "
            f"{report['steps'][2]['evidence']['result']}, cost {report['cost']['total']}; "
            f"sandbox {report['sandbox_policy']}")  # fmt: skip
    return {"runner": report}, text


__all__ = ["act", "add_runner_parsers"]
