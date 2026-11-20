"""``tine custody record --artifact|chain|check|gate`` (0.71): checkpoint and weight custody.

``record EVENT LOCATION --artifact NAME --sign-key KEY [--file F | --digest D]``
signs, chains and holds one event (:mod:`opentine._weight_custody`); weights are
read only to digest them, never stored. ``chain NAME`` lists the events and their
chain state; ``check NAME [--file LOCATION=PATH]...`` reports gaps and exits 1
(:mod:`opentine._weight_custody_check`). ``gate`` reads one agent tool call
(Claude Code / Codex ``PreToolUse`` or ``{"protocol": "opentine-custody-gate/1",
"tool": {"name", "input"}}``) on stdin and denies a load of a ``model-organism``
artifact without approval; it fails closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import IO, Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-custody-weights/1"
PROTOCOL = "opentine-custody-gate/1"
MAX_PAYLOAD = 8 * 1024 * 1024


def add_weight_arguments(rec: argparse.ArgumentParser, verbs: Any) -> None:
    rec.add_argument("--artifact", metavar="NAME", help="0.71: a checkpoint/weight custody event")
    which = rec.add_mutually_exclusive_group()
    which.add_argument("--file", metavar="PATH", help="Digest these weight bytes (not stored)")
    which.add_argument("--digest", metavar="DIGEST", help="The sha256: digest of the weights")
    rec.add_argument("--max-bytes", type=int, default=None, help="Cap of the streaming digest")
    rec.add_argument("--run", dest="training_run", metavar="RUN", help="The training run")
    rec.add_argument("--data", action="append", default=[], metavar="DIGEST",
                     help="A data commitment (repeatable)")  # fmt: skip
    rec.add_argument("--lineage", metavar="NODE", help="The lineage node")
    rec.add_argument("--tag", action="append", default=[], help="created: model-organism")
    chain = verbs.add_parser("chain", help="0.71: the custody events of a weight artifact")
    check = verbs.add_parser("check", help="0.71: report gaps in a weight custody chain")
    check.add_argument("--file", action="append", default=[], dest="observed",
                       metavar="LOCATION=PATH", help="An observed copy to account for")  # fmt: skip
    check.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (chain, check):
        verb.add_argument("artifact", metavar="NAME", help="The artifact name")
        verb.add_argument("--repo", default=".")
        verb.add_argument("--json", action="store_true", help="Emit a JSON object instead")
    gate = verbs.add_parser("gate", help="0.71: hook gate for model-organism loads (stdin)")
    gate.add_argument("--repo", default=".")
    gate.add_argument(
        "--agent",
        choices=["claude-code", "codex", "generic"],
        help="Hook dialect (default: claude-code)",
    )


def _record(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _weight_custody as wc
    from opentine._key_hygiene import ed25519_private

    digest, size = args.digest, None
    if args.file:
        digest, size = wc.file_digest(Path(args.file), args.max_bytes or wc.MAX_BYTES)
    run = None
    if args.training_run:
        from opentine.repository.ops import resolve_target

        run = resolve_target(repo, args.training_run)
    out = wc.record(repo, args.artifact, args.action, ed25519_private(args.sign_key),
                    location=args.subject, digest=digest, size=size, run=run, data=args.data,
                    lineage=args.lineage, tags=args.tag)  # fmt: skip
    body = {"artifact": args.artifact, "event": args.action, "record": out["record"],
            "seq": out["seq"], "prev": out["prev"], "digest": digest, "size": size}  # fmt: skip
    return body, [f"{args.artifact} #{out['seq']} {args.action} {args.subject} ({out['record']})"]


def _chain(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _weight_custody_check as check

    rows = [{"record": r["oid"], "seq": r["hold_seq"], "event": (r["claim"] or {}).get("event"),
             "signer": r["signer"], "verification": r["verification"],
             "claim": r["claim"], "problems": r["problems"]}
            for r in check.chain(repo, args.artifact)]  # fmt: skip
    lines = [f"#{r['seq']} {r['event']} {r['record']} {r['verification']}"
             + "".join(f"\n  {p}" for p in r["problems"]) for r in rows]  # fmt: skip
    return {"artifact": args.artifact, "events": rows}, lines or ["no custody events"]


def _check(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _weight_custody as wc
    from opentine import _weight_custody_check as check

    observed = []
    for item in args.observed:
        loc, sep, path = item.rpartition("=")
        if not sep or not loc:
            raise ValueError(f"--file takes LOCATION=PATH, not {item!r}")
        observed.append((loc, wc.file_digest(Path(path))[0]))
    body = check.check(repo, args.artifact, observed, strict=args.strict)
    lines = [f"{f['code']}: {f['message']}" for f in body["findings"]]
    return body, lines or [f"{args.artifact}: custody chain has no gaps"]


def run_weights(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine.repo import Repo

    verb = args.custody_command
    handler = {"record": _record, "chain": _chain, "check": _check}[verb]
    try:
        repo = Repo.open(args.repo)
        body, lines = handler(args, repo)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix=f"custody {verb}: ") from exc
    if args.json:
        emit({"command": f"custody {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "check" and not body["ok"]:
        raise SystemExit(1)


def _tool_input(raw: bytes) -> Any:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("the payload is not a JSON object")
    if payload.get("protocol") == PROTOCOL:
        tool = payload.get("tool")
        if not isinstance(tool, dict):
            raise ValueError("the payload names no tool")
        return tool.get("input")
    if "tool_input" not in payload:
        raise ValueError("the payload has no tool_input")
    return payload["tool_input"]


def gate(args: argparse.Namespace, stream: IO[bytes] | None = None,
         out: IO[bytes] | None = None) -> int:  # fmt: skip
    """Decide one tool call; always one JSON object on stdout and exit status 0."""
    from opentine import _weight_custody_gate as gate_mod
    from opentine.repo import Repo

    try:
        raw = (stream or sys.stdin.buffer).read(MAX_PAYLOAD + 1)
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("the payload is larger than 8 MiB")
        decision = gate_mod.decide(Repo.open(args.repo), _tool_input(raw))
    except Exception as exc:  # noqa: BLE001 - fail closed: anything unreadable denies
        decision = {"decision": "block", "reason": f"custody gate: {exc}", "artifacts": []}
    if args.agent == "generic":
        doc: dict[str, Any] = {"protocol": PROTOCOL, **decision}
    elif decision["decision"] == "allow":
        doc = {}
    else:
        doc = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": decision["reason"]}}  # fmt: skip
    sink = out or sys.stdout.buffer
    sink.write(json.dumps(doc, sort_keys=True).encode("utf-8") + b"\n")
    sink.flush()
    return 0


__all__ = ["PROTOCOL", "SCHEMA", "add_weight_arguments", "gate", "run_weights"]
