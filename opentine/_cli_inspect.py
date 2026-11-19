"""``tine inspect import|export|metr|sign|verify`` (0.64): Inspect AI and METR interop.

``import LOG --repo PATH`` records each sample of an Inspect ``.eval`` or
``.json`` log as a run (:mod:`opentine._inspect_import`); with ``--key KEY
--evals DIR`` it also signs one eval folder per scorer
(:mod:`opentine._inspect_verdicts`). ``export --repo PATH`` writes the log back
(:mod:`opentine._inspect_export`) with the same sample ids and scores. ``metr
DIR --out FILE.jsonl`` reads a METR task-standard family into an eval dataset
without running it (:mod:`opentine._metr_task`). ``sign LOG --key KEY`` and
``verify LOG`` handle the detached log signature the Inspect hook writes
(:mod:`opentine._inspect_hook`). ``tine import inspect LOG``, ``tine import
metr DIR`` and ``tine export inspect`` are spellings of these (:func:`rewrite`).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import VERIFICATION_FAILED, error

SCHEMA = "tine-cli-inspect/1"
_SPELLINGS = {("import", "inspect"): "import", ("import", "metr"): "metr",
              ("export", "inspect"): "export"}  # fmt: skip


def rewrite(argv: list[str]) -> list[str]:
    """``tine import inspect LOG`` -> ``tine inspect import LOG`` (and metr, export)."""
    verb = _SPELLINGS.get(tuple(argv[:2]))
    if verb is None or (verb != "export" and len(argv) < 3) or Path(argv[1]).exists():
        return argv  # a file literally named inspect/metr keeps its old meaning
    return ["inspect", verb, *argv[2:]]


def add_inspect_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("inspect", help="Inspect AI logs and METR tasks in and out")
    verbs = parser.add_subparsers(dest="inspect_command", required=True)
    into = verbs.add_parser("import", help="Record an Inspect log's samples as runs")
    into.add_argument("log", metavar="LOG", help="An Inspect .eval or .json log")
    into.add_argument("--key", metavar="KEY", help="Sign each scorer's scores as eval verdicts")
    into.add_argument("--evals", metavar="DIR", help="Where --key writes eval folders")
    into.add_argument("--threshold", type=float, default=1.0, help="Verdict pass mark (default 1)")
    into.add_argument("--created-at", metavar="TIME", help="Verdict time (default: the log's)")
    out = verbs.add_parser("export", help="Write imported runs back as an Inspect log")
    out.add_argument("--prefix", metavar="PREFIX", help="Which imported eval (see --json import)")
    out.add_argument("--format", choices=("json", "eval"), default="json", dest="log_format")
    out.add_argument("--output", metavar="PATH", help="Write here, not stdout")
    out.add_argument("--force", action="store_true", help="Replace an existing --output")
    metr = verbs.add_parser("metr", help="Read a METR task family into an eval dataset")
    metr.add_argument("family", metavar="DIR", help="Task family directory")
    metr.add_argument("--out", required=True, metavar="FILE.jsonl", help="Dataset to write")
    sign = verbs.add_parser("sign", help="Write a detached signature beside an Inspect log")
    sign.add_argument("log", metavar="LOG")
    sign.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    sign.add_argument("--signed-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default now)")
    check = verbs.add_parser("verify", help="Check an Inspect log against its signature")
    check.add_argument("log", metavar="LOG")
    for verb in (into, out):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
    for verb in (into, out, metr, sign, check):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _key(path: str) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(path, signer=False)


def _created(log: dict[str, Any], given: str | None) -> str:
    from opentine._eval_run import now
    from opentine._eval_verdict import TIME_RE

    if given:
        return given
    text = str(log["eval"].get("created") or "")[:19]
    return text + "Z" if TIME_RE.fullmatch(text + "Z") else now()


def _import(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    from opentine._inspect_import import import_log
    from opentine._inspect_log import read_log
    from opentine.repo import Repo

    if bool(args.key) != bool(args.evals):
        raise ValueError("--key and --evals go together")
    log = read_log(args.log)
    body = import_log(Repo.open(args.repo), log)
    lines = [f"imported {len(body['samples'])} sample(s) of {body['task']} "
             f"under {body['ref_prefix']}"]  # fmt: skip
    body["verdicts"] = None
    if args.key:
        from opentine._inspect_verdicts import write_verdicts

        rows = [{"run": row["run"], "sample": sample}
                for row, sample in zip(body["samples"], log["samples"], strict=True)]  # fmt: skip
        body["verdicts"] = write_verdicts(rows, _key(args.key), Path(args.evals),
                                          threshold=args.threshold,
                                          created_at=_created(log, args.created_at))  # fmt: skip
        for name, row in body["verdicts"]["scorers"].items():
            lines.append(f"  {name}: {row['items']} verdict(s) in {row['folder']}")
        if body["verdicts"]["skipped"]:
            lines.append(f"  {len(body['verdicts']['skipped'])} score(s) not in 0..1: no verdict")
    return body, lines


def _export(args: argparse.Namespace) -> None:
    from opentine import _inspect_export as export
    from opentine._cli_flags import _require_output_slot
    from opentine.repo import Repo

    log = export.collect(Repo.open(args.repo), args.prefix)
    data = export.to_eval_bytes(log) if args.log_format == "eval" else export.to_json_bytes(log)
    if args.output:
        _require_output_slot(Path(args.output), args.force)
        with open(args.output, "wb") as handle:
            handle.write(data)
        if args.json:
            from opentine._cli_json import emit

            emit({"command": "inspect export", "schema": SCHEMA, "output": args.output,
                  "format": args.log_format, "samples": len(log["samples"])})  # fmt: skip
        return
    if args.log_format == "eval" and sys.stdout.isatty():
        raise ValueError("--format eval is a zip: pass --output PATH or redirect stdout")
    sys.stdout.flush()
    sys.stdout.buffer.write(data)  # byte-exact: no newline translation
    sys.stdout.buffer.flush()


def _body(args: argparse.Namespace) -> tuple[dict[str, Any], list[str], int]:
    verb = args.inspect_command
    if verb == "import":
        body, lines = _import(args)
        return body, lines, 0
    if verb == "metr":
        from opentine._eval_dataset import write_jsonl
        from opentine._metr_task import read_family

        family = read_family(args.family)
        write_jsonl(Path(args.out), family["items"])
        body = {"family": family["family"], "tasks": len(family["items"]),
                "dynamic": family["dynamic"], "out": Path(args.out).as_posix()}  # fmt: skip
        note = " (get_tasks is not a literal: no tasks read)" if family["dynamic"] else ""
        return body, [f"{family['family']}: {len(family['items'])} task(s){note}"], 0
    from opentine import _inspect_hook as hook

    if verb == "sign":
        path = hook.sign_log(args.log, _key(args.key), signed_at=args.signed_at)
        return {"signature": path.as_posix()}, [f"signed: {path}"], 0
    result = hook.verify_log(args.log)
    line = "ok" if result["ok"] else f"FAILED: {result['reason']}"
    return result, [line], 0 if result["ok"] else VERIFICATION_FAILED


def cmd_inspect(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit

    try:
        if args.inspect_command == "export":
            return _export(args)
        body, lines, code = _body(args)
    except (OSError, ValueError, KeyError) as exc:
        raise error(exc, prefix="inspect: ") from exc
    if args.json:
        emit({"command": f"inspect {args.inspect_command}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"inspect": cmd_inspect}

__all__ = ["COMMANDS", "add_inspect_parser", "cmd_inspect", "rewrite"]
