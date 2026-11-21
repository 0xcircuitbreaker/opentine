"""``tine policy check|list|show`` (0.74): the policy engine.

``check POLICY --subject RUN`` assembles the input document from the signed
records of RUN (:mod:`opentine._policy_input`), evaluates every rule of POLICY
(a file, or a standard policy by name; :mod:`opentine._policy`) and, with
``--key``, signs and holds the decision as an ``opentine.policy-admission/1``
attestation (:mod:`opentine._policy_record`). Exit 0 on ``allow``, 1 on
``deny``; a missing or invalid policy is an error (exit 1, nothing allowed).
``--input FILE`` evaluates over a given input document instead (never signed).
``list`` names the standard policies; ``show RUN`` lists the held admissions.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-policy/1"


def add_policy_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("policy", help="Evaluate admission policies over signed records")
    verbs = parser.add_subparsers(dest="policy_command", required=True)
    check = verbs.add_parser("check", help="Evaluate a policy for a run; sign the decision")
    check.add_argument("policy", metavar="POLICY", help="Policy JSON file or standard name")
    check.add_argument("--subject", required=True, metavar="REF", help="The run (id or ref)")
    check.add_argument("--evals", action="append", default=[], metavar="DIR",
                       help="Eval verdict folder (repeatable)")  # fmt: skip
    check.add_argument("--holdout", action="append", default=[], metavar="DIR",
                       help="Sealed holdout folder (repeatable)")  # fmt: skip
    check.add_argument("--budget", metavar="SUBJECT", help="Budget subject to include")
    check.add_argument("--param", action="append", default=[], metavar="NAME=JSON",
                       help="Override a policy param (JSON value, else a string)")  # fmt: skip
    check.add_argument("--input", dest="input_file", metavar="FILE",
                       help="Evaluate over this input document (not signed)")  # fmt: skip
    check.add_argument("--key", metavar="KEY", help="Sign and hold the admission record")
    check.add_argument("--at", metavar="TIME", help="Record time (default now, UTC)")
    check.add_argument("--show-input", action="store_true", help="Include the input document")
    lst = verbs.add_parser("list", help="The standard policies shipped with OpenTine")
    show = verbs.add_parser("show", help="The held admission records of a run")
    show.add_argument("run", metavar="RUN", help="The run (id or ref)")
    for verb in (check, lst, show):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _params(policy: dict[str, Any], given: list[str]) -> dict[str, Any]:
    out = dict(policy.get("params", {}))
    for item in given:
        name, sep, raw = item.partition("=")
        if not sep or not name:
            raise ValueError(f"--param {item!r} is not NAME=VALUE")
        try:
            out[name] = json.loads(raw)
        except ValueError:
            out[name] = raw
    return out


def _run_id(repo: Any, value: str) -> str:
    from opentine.repository.ops import resolve_target

    return resolve_target(repo, value)


def _check(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _policy, _policy_record
    from opentine._audit_game import now

    doc, _raw = _policy.load(args.policy)
    digest = _policy.policy_digest(doc)
    repo = None
    if args.input_file:
        if args.key:
            raise ValueError("--input is never signed: drop --key")
        document = json.loads(Path(args.input_file).read_bytes().decode("utf-8"))
        subject = args.subject
    else:
        from opentine import _policy_input
        from opentine.repo import Repo

        repo = Repo.open(args.repo)
        subject = _run_id(repo, args.subject)
        document = _policy_input.build(repo, Path(args.repo), subject, eval_dirs=args.evals,
                                       holdouts=args.holdout, budget=args.budget,
                                       params=_params(doc, args.param))  # fmt: skip
    try:
        input_digest = _policy.input_digest(document)
    except Exception:  # noqa: BLE001 - not canonical JSON: decide() records policy.input
        input_digest = "sha256:" + "0" * 64
    result = _policy.decide(doc, document)
    oid = None
    if args.key and repo is not None:
        from opentine._key_hygiene import ed25519_private

        body = _policy_record.claim(doc, digest, subject, input_digest, result, args.at or now())
        oid = _policy_record.record(repo, subject, body, ed25519_private(args.key))
    out = {"policy": {"name": doc["name"], "digest": digest}, "subject": subject,
           "input_digest": input_digest, "decision": result["decision"],
           "rules": result["rules"], "recorded": oid}  # fmt: skip
    if args.show_input:
        out["input"] = document
    lines = [f"{result['decision']}: {doc['name']} ({digest}) for {subject}"]
    for r in result["rules"]:
        extra = f" [{r['code']}]" if r["code"] else ""
        lines.append(f"  {r['outcome']:5} {r['effect']:8} {r['id']}{extra}")
    if oid:
        lines.append(f"recorded {oid}")
    return out, lines


def _list(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _policy

    found = []
    for name in _policy.standard():
        doc, _raw = _policy.load(_policy.STANDARD_DIR / f"{name}.json")
        found.append({"name": name, "digest": _policy.policy_digest(doc),
                      "description": doc.get("description", "")})  # fmt: skip
    return {"policies": found}, [f"{p['name']}: {p['description']}" for p in found]


def _show(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine import _policy_record
    from opentine.repo import Repo

    repo = Repo.open(args.repo)
    run = _run_id(repo, args.run)
    rows = _policy_record.rows(repo, run)
    lines = [f"{r['oid']} {'signed' if r['signed'] else 'UNSIGNED'} "
             f"{(r['claim'] or {}).get('decision')} {(r['claim'] or {}).get('policy')}"
             for r in rows]  # fmt: skip
    return {"subject": run, "records": rows}, lines or [f"no admission records for {run}"]


_VERBS = {"check": _check, "list": _list, "show": _show}


def cmd_policy(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._policy import PolicyFileError

    verb = args.policy_command
    try:
        body, lines = _VERBS[verb](args)
    except (OSError, ValueError, KeyError, PolicyFileError) as exc:
        raise error(exc, prefix=f"policy {verb}: ") from exc
    if args.json:
        emit({"command": f"policy {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "check" and body["decision"] != "allow":
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"policy": cmd_policy}

__all__ = ["COMMANDS", "SCHEMA", "add_policy_parser", "cmd_policy"]
