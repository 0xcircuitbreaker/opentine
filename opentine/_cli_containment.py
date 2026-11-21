"""``tine containment record|check|scan`` (0.69): sandbox policy and containment evidence.

``record RUN --policy FILE --key KEY`` signs and holds the run's sandbox policy
(:mod:`opentine._containment`); ``check RUN [--policy FILE|--digest D]`` compares
the recorded digest with the declared one and exits 1 on
``sandbox-policy-mismatch``; ``scan RUN [--key KEY]`` runs the advisory
detectors over the run's recorded steps and, with a key, signs and holds each
new finding (:mod:`opentine._containment_detect`). Budgets are ``tine budget``
(:mod:`opentine._cli_budget`).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error
from opentine._cli_keyless import COMMANDS as KEYLESS_COMMANDS
from opentine._cli_keyless import add_keyless_parser
from opentine._cli_organism import COMMANDS as ORGANISM_COMMANDS
from opentine._cli_organism import add_organism_parser
from opentine._cli_policy import COMMANDS as POLICY_COMMANDS
from opentine._cli_policy import add_policy_parser
from opentine._cli_transcripts import COMMANDS as TRANSCRIPTS_COMMANDS
from opentine._cli_transcripts import add_transcripts_parser

SCHEMA = "tine-cli-containment/1"


def add_containment_parser(subparsers: argparse._SubParsersAction) -> None:
    add_keyless_parser(subparsers)  # 0.74: tine keyless verify
    add_organism_parser(subparsers)  # 0.72: tine organism tag|untag|approve|status|gate
    add_transcripts_parser(
        subparsers
    )  # 0.74: tine transcripts index|search|similar|cluster|label|flags
    add_policy_parser(subparsers)  # 0.75 (release 0.74.0): tine policy check|list|show
    parser = subparsers.add_parser("containment", help="Sandbox policy and containment evidence")
    verbs = parser.add_subparsers(dest="containment_command", required=True)
    rec = verbs.add_parser("record", help="Sign and hold a run's sandbox policy")
    rec.add_argument("--policy", required=True, metavar="FILE", help="Sandbox policy JSON")
    check = verbs.add_parser("check", help="Compare the recorded policy digest to the declared")
    which = check.add_mutually_exclusive_group()
    which.add_argument("--policy", metavar="FILE", help="The declared sandbox policy JSON")
    which.add_argument("--digest", metavar="DIGEST", help="The pinned sha256: policy digest")
    scan = verbs.add_parser("scan", help="Advisory detectors over a run's recorded steps")
    scan.add_argument("--key", metavar="KEY", help="Sign and hold each new finding")
    for verb in (rec, check, scan):
        verb.add_argument("run", metavar="RUN", help="The run (id or ref)")
    for verb in (check, scan):
        verb.add_argument("--strict", action="store_true", help="Advisory findings block too")
    rec.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    for verb in (rec, check, scan):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _run_id(repo: Any, value: str) -> str:
    from opentine.repository.ops import resolve_target

    try:
        return resolve_target(repo, value)
    except KeyError:
        raise KeyError(f"cannot resolve {value}: no such ref or run") from None


def _json(path: str) -> Any:
    return json.loads(Path(path).read_bytes())


def _key(path: str) -> Any:
    from opentine._key_hygiene import ed25519_private

    return ed25519_private(path)


def _record(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _containment

    run = _run_id(repo, args.run)
    policy = _json(args.policy)
    oid = _containment.record(repo, run, policy, _key(args.key))
    digest = _containment.digest(policy)
    return {"run": run, "record": oid, "policy_digest": digest}, [f"{run}: {digest} ({oid})"]


def _check(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _containment

    declared = _containment.digest(_json(args.policy)) if args.policy else args.digest
    body = _containment.check(repo, _run_id(repo, args.run), declared)
    if args.strict and body["findings"]:
        body["ok"] = False
    lines = [f"{p['policy_digest']} {p['verification']}" for p in body["policies"]]
    lines += [f"{f['code']}: {f['message']}" for f in body["findings"]]
    return {**body, "strict": args.strict}, lines or ["no sandbox policy recorded"]


def _scan(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _containment, _containment_detect
    from opentine._containment_records import rfc3339

    run = _run_id(repo, args.run)
    found = _containment_detect.scan_run(repo.load_run(run), _containment.allowlist(repo, run))
    recorded: list[str] = []
    if args.key:
        import time

        key, at = _key(args.key), rfc3339(time.time())
        have = {r["digest"] for r in _containment_detect.recorded(repo, run)}
        for f in found:
            mark = _containment_detect.mark(_containment_detect.claim_for(f, run, at))
            if mark not in have:
                recorded.append(_containment_detect.record(repo, run, f, key, at))
                have.add(mark)
    body = {"run": run, "ok": not (args.strict and found), "strict": args.strict,
            "findings": found, "recorded": recorded}  # fmt: skip
    lines = [f"{f['code']} step {f['step']}: {f['detail']}" for f in found]
    return body, lines or ["no containment findings"]


def cmd_containment(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.containment_command
    handler = {"record": _record, "check": _check, "scan": _scan}[verb]
    try:
        repo = Repo.open(args.repo)
        body, lines = handler(args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"containment {verb}: ") from exc
    if args.json:
        emit({"command": f"containment {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb in ("check", "scan") and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {
    "containment": cmd_containment,
    **ORGANISM_COMMANDS,
    **TRANSCRIPTS_COMMANDS,
    **POLICY_COMMANDS,
    **KEYLESS_COMMANDS,
}
