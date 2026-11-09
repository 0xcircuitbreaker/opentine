"""``tine review create|add|gate|show|export|verify|import|push|run|findings`` (SPEC 4.20).

A Review is kept in ``.tine/reviews/<id>.json`` as its bundle
(:mod:`opentine.repository._review_store`). ``create`` writes version 0 and
``add`` the next version (subjects, findings, monitors, gates, reviewers or code
repositories added); both sign with a reviewer's Ed25519 key
(``--ed25519-key-file``). ``gate`` signs one decision on the head version.
``show`` verifies the Review and prints its gate status; ``export`` writes the
bundle that ``tine-verify.pyz --offline`` checks air-gapped; ``verify`` checks
such a file and exits 4 when it fails; ``import`` adopts one; ``push`` sends
what a remote's ``caps.reviews`` lacks (:mod:`opentine._cli_review_remote`).
``run`` and ``findings`` (0.48: reviewer fleets, signed findings) live in
:mod:`opentine._cli_review_run`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit
from opentine._cli_remote_target import add_remote_args
from opentine._review_rules import SEVERITIES

ACTIONS = ("create", "add", "gate", "show", "export", "verify", "import", "push", "run",
           "findings")  # fmt: skip


def _key_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ed25519-key-file", required=True, metavar="PATH",
                        help="A reviewer's Ed25519 key; it signs the new record")  # fmt: skip
    parser.add_argument("--key-id", help="Key id recorded in the signature")


def _change_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--code-repo", action="append", default=[], metavar="NAME[=PROJECT]",
                        help="A repository the Review spans (repeatable)")  # fmt: skip
    parser.add_argument("--reviewer", action="append", default=[], metavar="HEX",
                        help="A further reviewer's Ed25519 public key (repeatable)")  # fmt: skip
    parser.add_argument("--gate", action="append", default=[], metavar="NAME")


def add_review_parser(sub: Any) -> None:
    review = sub.add_parser("review", help="Reviews: findings, monitors and signed gates")
    actions = review.add_subparsers(dest="review_action", required=True)
    create = actions.add_parser("create", help="Write version 0 of a Review")
    create.add_argument("review_id", help="[a-z0-9][a-z0-9._-]{0,63}")
    create.add_argument("--title", required=True)
    _change_args(create)
    add = actions.add_parser("add", help="Sign the next version with what is added")
    add.add_argument("review_id")
    _change_args(add)
    add.add_argument("--run", action="append", default=[], metavar="OID")
    add.add_argument("--commit", action="append", default=[], metavar="SHA")
    add.add_argument(
        "--at", metavar="NAME", help="The code repo of --run/--commit (default: first)"
    )
    add.add_argument("--finding", action="append", default=[], metavar="SEVERITY:MESSAGE")
    add.add_argument("--resolve", action="append", default=[], metavar="FINDING_ID")
    add.add_argument("--monitor", choices=("risk", "intent-drift", "coverage"))
    add.add_argument("--scorer", default="manual")
    add.add_argument("--score")
    add.add_argument("--threshold")
    add.add_argument("--verdict", metavar="FILE", help="A tine-eval-verdict/1 to take it from")
    gate = actions.add_parser("gate", help="Sign a decision on a gate of the head version")
    gate.add_argument("review_id")
    gate.add_argument("gate")
    choice = gate.add_mutually_exclusive_group(required=True)
    choice.add_argument("--approve", action="store_true")
    choice.add_argument("--reject", action="store_true")
    gate.add_argument("--reason", default="")
    for parser in (create, add, gate):
        _key_args(parser)
    show = actions.add_parser("show", help="Verify a Review and print its gate status")
    show.add_argument("review_id")
    export = actions.add_parser("export", help="Write the Review's bundle (verifies offline)")
    export.add_argument("review_id")
    export.add_argument("-o", "--output", required=True, metavar="FILE")
    verify = actions.add_parser("verify", help="Check a review bundle file (exit 4 on failure)")
    verify.add_argument("file")
    imported = actions.add_parser("import", help="Adopt a verified review bundle")
    imported.add_argument("file")
    push = actions.add_parser("push", help="Send what a remote lacks (caps.reviews)")
    push.add_argument("review_id")
    add_remote_args(push)
    from opentine._cli_review_run import add_run_parsers

    fleet = add_run_parsers(actions)
    for parser in (show, export, verify):
        parser.add_argument("--reviewer-key", metavar="HEX", help="Pin the first reviewer")
    for parser in (create, add, gate, show, export, verify, imported, push, *fleet):
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def _code_repos(values: list[str]) -> list[dict[str, Any]]:
    out = []
    for value in values:
        name, _, project = value.partition("=")
        out.append({"name": name, "project": project or None})
    return out


def _monitor(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _eval_verdict

    if args.verdict:
        verdict = json.loads(Path(args.verdict).read_text("utf-8"))
        checked = _eval_verdict.verify(verdict)
        return {"name": args.monitor, "scorer": verdict["scorer"], "score": verdict["score"],
                "threshold": verdict["threshold"], "passed": checked["passed"],
                "verdict": checked["digest"]}  # fmt: skip
    if args.score is None or args.threshold is None:
        raise ValueError("--monitor needs --score and --threshold, or --verdict")
    score, threshold = (_eval_verdict.score_text(float(v)) for v in (args.score, args.threshold))
    passed = _eval_verdict.Decimal(score) >= _eval_verdict.Decimal(threshold)
    return {"name": args.monitor, "scorer": args.scorer, "score": score,
            "threshold": threshold, "passed": passed, "verdict": None}  # fmt: skip


def _merged(head: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    repos = {row["name"]: row for row in head["repos"]}
    repos.update({row["name"]: row for row in _code_repos(args.code_repo)})
    reviewers = [*head["reviewers"], *[k for k in args.reviewer if k not in head["reviewers"]]]
    at = args.at or sorted(repos)[0]
    subjects = list(head["subjects"])
    for kind, ids in (("run", args.run), ("commit", args.commit)):
        subjects += [{"repo": at, "type": kind, "id": i} for i in ids if i]
    findings = [{**row, "status": "resolved"} if row["id"] in args.resolve else row
                for row in head["findings"]]  # fmt: skip
    missing = set(args.resolve) - {row["id"] for row in head["findings"]}
    if missing:
        raise KeyError(f"no finding {sorted(missing)[0]} in this review")
    for spec in args.finding:
        severity, _, message = spec.partition(":")
        if severity not in SEVERITIES:
            raise ValueError(f"--finding is SEVERITY:MESSAGE, SEVERITY one of {SEVERITIES}")
        findings.append({"id": f"f{len(findings) + 1}", "severity": severity, "subject": None,
                         "message": message.strip(), "status": "open"})  # fmt: skip
    monitors = list(head["monitors"])
    if args.monitor:
        monitors = [row for row in monitors if row["name"] != args.monitor] + [_monitor(args)]
    return {"title": head["title"], "reviewers": reviewers, "repos": list(repos.values()),
            "subjects": subjects, "findings": findings, "monitors": monitors,
            "gates": [*head["gates"], *args.gate]}  # fmt: skip


def _write(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine import _review
    from opentine._signing_keys import ed25519_private_from_file
    from opentine.repository import _review_store as store

    key = ed25519_private_from_file(args.ed25519_key_file)
    me = key.public_key().public_bytes_raw().hex()
    current = store.load(repo, args.review_id)
    head = current["versions"][-1] if current else None
    if args.review_action == "gate":
        if head is None:
            raise KeyError(f"no review {args.review_id} here")
        decision = "approve" if args.approve else "reject"
        record = _review.sign_gate(_review.build_gate(head, args.gate, decision, args.reason), key,
                                   key_id=args.key_id)  # fmt: skip
        found = store.decide(repo, record)
        return {"decision": record, "digest": _review.digest(record), "gate": found}
    if args.review_action == "create":
        if head is not None:
            raise ValueError(f"review {args.review_id} exists: use `tine review add`")
        reviewers = [me, *[k for k in args.reviewer if k != me]]
        repos = _code_repos(args.code_repo or ["default"])
        record = _review.build(args.review_id, title=args.title, reviewers=reviewers,
                               repos=repos, gates=args.gate)  # fmt: skip
    else:
        if head is None:
            raise KeyError(f"no review {args.review_id} here: `tine review create` first")
        record = _review.build(args.review_id, previous=head, **_merged(head, args))
    signed = _review.sign(record, key, key_id=args.key_id)
    oid = store.append(repo, signed, expected=None if head is None else _review.digest(head))
    return {"version": signed, "digest": oid}


def _bundle(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine.repository import _review_store as store

    if args.review_action in ("verify", "import"):
        return json.loads(Path(args.file).read_text("utf-8"))
    found = store.load(repo, args.review_id)
    if found is None:
        raise KeyError(f"no review {args.review_id} here")
    return found


def _act(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine import _review
    from opentine.repository import Repo
    from opentine.repository import _review_store as store

    action = args.review_action
    repo = None if action == "verify" else Repo.open(args.repo)
    if action in ("create", "add", "gate"):
        body = _write(args, repo)
        return body, f"review {args.review_id}: {body['digest']}"
    if action in ("run", "findings"):
        from opentine._cli_review_run import act

        return act(args, repo)
    if action == "push":
        from opentine._cli_review_remote import push

        body = push(args, store.load(repo, args.review_id))
        return body, f"pushed {body['versions']} version(s), {body['decisions']} decision(s)"
    value = _bundle(args, repo)
    if action == "import":
        added = store.install(repo, value)
        return {"added": added}, f"imported {added['versions']} version(s)"
    result = _review.verify_bundle(value, reviewer_key=args.reviewer_key)
    gates = ", ".join(f"{g} {s}" for g, s in result["gates"].items()) or "no gates"
    text = f"review {result['review_id']} v{result['seq']}: {result['status']} ({gates})"
    if action == "export":
        Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", "utf-8")
        text += f"; wrote {Path(args.output).as_posix()}"
    body: dict[str, Any] = {"result": result}
    if action == "show":
        body["version"] = value["versions"][-1]
    return body, text


def cmd_review(args: argparse.Namespace) -> None:
    from opentine._signed_record import RecordError

    try:
        body, text = _act(args)
    except RecordError as exc:
        fail(f"{exc.code}: {exc}", VERIFICATION_FAILED, prefix="tine review: ")
    except (KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine review: ")
    if args.json:
        emit({"command": "review", "action": args.review_action, "ok": True, **body})
    else:
        print(text)


__all__ = ["ACTIONS", "add_review_parser", "cmd_review"]
