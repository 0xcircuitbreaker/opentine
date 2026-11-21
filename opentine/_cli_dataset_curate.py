"""``tine dataset curate|justify|versions|verify-version|materialize`` (0.75).

``curate --select EXPR --out NAME --key KEY`` signs a dataset version from the
repository's runs (:mod:`opentine._dataset_version`): withdrawn runs and runs
the taint filter names are left out; ``--include-tainted --justification ID``
lets in the tainted runs a pinned curator or policy key justified.
``justify NAME --run RUN... --reason TEXT --key KEY`` signs that justification.
A contributor's ``tine dataset withdraw`` (:mod:`opentine._cli_dataset_contrib`)
leaves the run out of later versions.
``versions [NAME]`` lists versions with their verification;
``verify-version (ID | --file PAYLOAD.json)`` checks one version offline
(no trust bundle; exits 1 when it fails); ``materialize ID --out D.jsonl``
writes a verified version as eval items (:mod:`opentine._dataset_materialize`).
See docs/DATASETS.md.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "tine-cli-dataset-curate/1"
VERBS = ("curate", "justify", "versions", "verify-version", "materialize")


def add_curate_verbs(verbs: Any) -> None:
    curate = verbs.add_parser("curate", help="Sign a dataset version selected from runs")
    curate.add_argument("--select", required=True, metavar="EXPR",
                        help="e.g. 'failures:EVAL', 'model:gpt-* and not passes:EVAL'")  # fmt: skip
    curate.add_argument("--out", required=True, metavar="NAME", help="The dataset name")
    curate.add_argument("--evals", action="append", default=[], metavar="DIR",
                        help="Also read DIR/verdicts.jsonl")  # fmt: skip
    curate.add_argument("--include-tainted", action="store_true",
                        help="Let in the tainted runs a justification names")  # fmt: skip
    curate.add_argument("--justification", metavar="ID", help="A dataset justification id")
    justify = verbs.add_parser("justify", help="Justify letting tainted runs into a dataset")
    justify.add_argument("name", metavar="NAME")
    justify.add_argument("--run", action="append", required=True, metavar="RUN")
    justify.add_argument("--reason", required=True, metavar="TEXT")
    for verb in (curate, justify):
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 key")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    listing = verbs.add_parser("versions", help="Dataset versions and their verification")
    listing.add_argument("name", nargs="?", metavar="NAME")
    check = verbs.add_parser("verify-version", help="Check one dataset version offline")
    check.add_argument("record", nargs="?", metavar="ID", help="The version attestation id")
    check.add_argument("--file", metavar="PAYLOAD.json", help="An exported attestation payload")
    mat = verbs.add_parser("materialize", help="Write a verified dataset version as eval items")
    mat.add_argument("record", metavar="ID", help="The version attestation id")
    mat.add_argument("--out", required=True, metavar="DATASET.jsonl")
    for verb in (curate, justify, listing, check, mat):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _resolve(repo: Any, value: str) -> str:
    from opentine.repository.ops import resolve_target

    try:
        return resolve_target(repo, value)
    except KeyError:
        raise KeyError(f"cannot resolve {value}: no such ref or run") from None


def _row(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _dataset_version as dv
    from opentine._key_hygiene import ed25519_private
    from opentine._promote import _now

    verb = args.dataset_command
    if verb == "versions":
        rows = dv.versions(repo, args.name)
        return {"ok": True, "versions": rows}, [
            f"{r['name']} v{r['version']} {r['members']} member(s) {r['verification']} "
            f"{r['record']}" for r in rows] or ["no dataset versions"]  # fmt: skip
    if verb == "verify-version":
        return _verify(args, repo)
    if verb == "materialize":
        from opentine._dataset_materialize import materialize

        row = materialize(repo, args.record, args.out)
        return row, [f"wrote {row['items']} item(s) of {row['name']} v{row['version']} to "
                     f"{row['out']} ({row['digest']})"]  # fmt: skip
    key, at = ed25519_private(args.key), args.at or _now()
    if verb == "justify":
        runs = [_resolve(repo, r) for r in args.run]
        oid = dv.justify(repo, args.name, runs, args.reason, key, at)
        return {"ok": True, "record": oid, "name": args.name, "runs": sorted(set(runs))}, [
            f"justified {len(set(runs))} run(s) for {args.name}: {oid}"]  # fmt: skip
    out = dv.curate(repo, args.out, args.select, key, at, eval_dirs=args.evals,
                    include_tainted=args.include_tainted,
                    justification_id=args.justification)  # fmt: skip
    claim, flt = out["claim"], out["claim"]["taint_filter"]
    body = {"ok": True, "record": out["record"], "name": claim["name"],
            "version": claim["version"], "previous": claim["previous"],
            "selection": claim["selection"], "members": [m["run"] for m in claim["members"]],
            "members_digest": claim["members_digest"],
            "dropped": claim["dedup"]["dropped"], "excluded": flt["excluded"],
            "included_tainted": flt["included_tainted"], "mode": flt["mode"],
            "withdrawn": claim["withdrawn"], "tombstones": out["tombstones"]}  # fmt: skip
    return body, [
        f"{claim['name']} v{claim['version']}: {len(body['members'])} member(s), "
        f"{len(body['dropped'])} duplicate(s), {len(body['excluded'])} tainted left out, "
        f"{len(body['withdrawn'])} withdrawn: {out['record']}"]  # fmt: skip


def _verify(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine._dataset_claims import offline

    if bool(args.record) == bool(args.file):
        raise ValueError("name one version: an attestation id or --file")
    if args.file:
        payload, record = json.loads(Path(args.file).read_bytes()), None
    else:
        record = args.record
        payload = repo.get(record).payload()
    found = offline(payload)
    lines = [f"{'OK' if found['ok'] else 'FAILED'} signature={found['signature']} "
             f"members={found['members']} excluded={found['excluded']}",
             *(f"  {p}" for p in found["problems"])]  # fmt: skip
    return {"record": record, **found}, lines


def cmd_curate(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._dataset_taint import TaintFilterError
    from opentine.repo import Repo
    from opentine.repository._holds import HoldError

    verb = args.dataset_command
    try:
        repo = None if verb == "verify-version" and args.file else Repo.open(args.repo)
        body, lines = _row(args, repo)
    except (OSError, ValueError, KeyError, PermissionError, HoldError,
            TaintFilterError) as exc:  # fmt: skip
        raise error(exc, prefix=f"dataset {verb}: ") from exc
    if args.json:
        emit({"command": f"dataset {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if body.get("ok") is False:
        raise SystemExit(1)


__all__ = ["SCHEMA", "VERBS", "add_curate_verbs", "cmd_curate"]
