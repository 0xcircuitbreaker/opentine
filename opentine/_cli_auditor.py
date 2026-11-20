"""``tine auditor import-petri|seal|findings|reveal|check`` (0.65): auditor runs, audit games.

``import-petri FILE --repo PATH`` records a Petri or Bloom transcript as a
``role=auditor`` run (:mod:`opentine._petri`); ``--blind SECRET`` seals the
target's identity, writing the secret the game owner keeps. ``seal``,
``findings`` and ``reveal`` sign and hold the three records of a blind audit
game (:mod:`opentine._audit_game`); ``check`` judges every game offline and
exits 1 on a ``fail:`` finding (``--strict``: on an advisory too).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import error

SCHEMA = "tine-cli-auditor/1"


def add_auditor_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("auditor", help="Auditor runs and blind audit games")
    verbs = parser.add_subparsers(dest="auditor_command", required=True)
    imp = verbs.add_parser("import-petri", help="Record a Petri/Bloom transcript as a run")
    imp.add_argument("source", metavar="FILE")
    imp.add_argument("--save", metavar="PATH", help="Also write a portable .tine artifact")
    imp.add_argument("--blind", metavar="SECRET", help="Seal the target; write the secret here")
    imp.add_argument("--objective", default="", help="Hidden objective sealed with --blind")
    imp.add_argument("--allow-in-repo", action="store_true",
                     help="Allow the --blind secret inside the repository")  # fmt: skip
    seal = verbs.add_parser("seal", help="Sign and hold a game's sealed commitment")
    found = verbs.add_parser("findings", help="Sign and hold the auditor's findings")
    found.add_argument("--findings", required=True, metavar="FILE", help="Findings document")
    found.add_argument("--verdict", required=True, choices=("concern", "no-concern"))
    reveal = verbs.add_parser("reveal", help="Sign and hold the reveal (after findings)")
    for verb in (seal, found, reveal):
        verb.add_argument("run", metavar="RUN", help="The auditor run")
        verb.add_argument("--game", required=True, metavar="GAME", help="Game name")
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    for verb in (seal, reveal):
        verb.add_argument("--secret", required=True, metavar="SECRET", help="Sealed secret")
    check = verbs.add_parser("check", help="Judge every blind audit game offline")
    check.add_argument("--game", metavar="GAME", help="Only this game")
    check.add_argument("--strict", action="store_true", help="Advisory findings block too")
    for verb in (imp, seal, found, reveal, check):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _import(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _audit_game, _petri

    doc = _petri.load(Path(args.source).read_bytes())
    who = _petri.roles(doc)
    sealed = None
    if args.blind:
        _check_placement(Path(args.blind), [Path(args.repo), Path(repo.path)], args.allow_in_repo)
        secret = _audit_game.secret(who[_petri.TARGET], args.objective)
        sealed = _audit_game.commitment(secret)
        text = json.dumps(secret, indent=2, sort_keys=True) + "\n"
        _write_private(Path(args.blind), text.encode("utf-8"))
    run = _petri.to_run(doc, sealed=sealed)
    if args.save:
        run.save(Path(args.save), lenient=True)
    run_id = repo.put_run(run).run_id
    body = {"run": run_id, "transcript": who["transcript"], "steps": len(run.steps),
            "auditor_model": who[_petri.AUDITOR], "judge_model": who[_petri.JUDGE],
            "target_model": None if sealed else who[_petri.TARGET], "sealed": sealed,
            "scores": who["scores"]}  # fmt: skip
    return body, [f"imported {who['transcript']} as {run_id} (role=auditor)"
                  + (f", target sealed {sealed}" if sealed else "")]  # fmt: skip


def _check_placement(path: Path, roots: list[Path], allow_in_repo: bool) -> None:
    """Refuse an opening the audited agent could read: inside the repository, or existing."""
    if os.path.lexists(path):
        raise ValueError(f"{path} exists; the blind secret is never overwritten")
    target = path.parent.resolve() / path.name
    for root in roots:
        home = root.resolve()
        inside = target.is_relative_to(home) or _folded(target).is_relative_to(_folded(home))
        if not allow_in_repo and inside:
            raise ValueError(f"{path} is inside the repository, where the auditor can read it; "
                             "keep the secret outside it, or pass --allow-in-repo")  # fmt: skip


def _folded(path: Path) -> PurePosixPath:
    """Case-folded form, so a variant on a case-insensitive filesystem still matches."""
    return PurePosixPath(path.as_posix().casefold())


def _write_private(path: Path, data: bytes) -> None:
    """Write the blind-audit opening owner-only (0600); it unseals the target."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)


def _secret(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_bytes())
    if not isinstance(data, dict):
        raise ValueError("a sealed secret is a JSON object")
    return data


def _sign(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _audit_game
    from opentine._key_hygiene import ed25519_private

    verb = args.auditor_command
    at = args.at or _audit_game.now()
    claim: dict[str, Any] = {"convention": _audit_game.CONVENTION, "game": args.game,
                             "step": verb, "at": at}  # fmt: skip
    rows = _audit_game.records(repo, args.game).get(args.game, [])
    seal = _audit_game.latest(rows, "seal")
    if verb == "seal":
        claim["commitment"] = _audit_game.commitment(_secret(args.secret))
    elif seal is None:
        raise ValueError(f"game {args.game} has no signed seal")
    else:
        claim["seal"] = seal["oid"]
    if verb == "findings":
        data = Path(args.findings).read_bytes()
        claim |= {"findings_digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                  "verdict": args.verdict}  # fmt: skip
    elif verb == "reveal":
        findings = _audit_game.latest(rows, "findings")
        sealed = _secret(args.secret)
        claim |= {k: sealed.get(k) for k in ("target", "objective", "nonce")}
        claim["findings"] = findings["oid"] if findings else None
    run = repo.load_run(args.run).id if not args.run.startswith("run:") else args.run
    oid = _audit_game.record(repo, run, claim, ed25519_private(args.key))
    return {"record": oid, "game": args.game, "step": verb}, [f"{verb} {args.game}: {oid}"]


def _check(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._audit_game_check import check

    body = check(repo, args.game, strict=args.strict)
    lines = [f"{g['state']:9} {g['game']}" + (f" verdict {g['verdict']}" if g["verdict"] else "")
             for g in body["games"]] or ["no audit games"]  # fmt: skip
    lines += [f"{f['code']} {f['game']}: {f['message']}" for f in body["findings"]]
    return body, lines


def cmd_auditor(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._petri import PetriError
    from opentine.repo import Repo

    verb = args.auditor_command
    handler = {"import-petri": _import, "check": _check}.get(verb, _sign)
    try:
        repo = Repo.open(args.repo)
        body, lines = handler(args, repo)
    except (OSError, ValueError, KeyError, PetriError) as exc:
        raise error(exc, prefix=f"auditor {verb}: ") from exc
    if args.json:
        emit({"command": f"auditor {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "check" and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"auditor": cmd_auditor}

__all__ = ["COMMANDS", "add_auditor_parser", "cmd_auditor"]
