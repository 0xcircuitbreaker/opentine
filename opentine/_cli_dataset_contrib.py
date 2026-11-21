"""``tine dataset contrib-redact|check|withdraw``: contributor tooling for open run datasets (0.75).

``contrib-redact RUN --deny-list FILE --licence SPDX --key K --out BUNDLE``
packages the redaction pass, the contributor's deny-list, a signed licence
annotation and a signed ``--redacted-public`` bundle, then unbundles that copy
and scans it for the deny-list: any hit removes the bundle and exits 1.
``check BUNDLE`` refuses (exit 1) a bundle without a valid licence annotation
by its contributor key, with an SPDX id outside the allow-list, or with a dirty
file-level licence scan. ``withdraw RUN --key K --reason CATEGORY`` signs and
holds an ``opentine-dataset/withdraw/1`` claim, and with ``--tombstones FILE``
adds its tombstone to that manifest. See docs/DATASET_CONTRIBUTORS.md.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

SCHEMA = "tine-cli-dataset-contrib/1"
VERBS = ("contrib-redact", "check", "withdraw")


def add_contrib_verbs(verbs: Any) -> None:
    from opentine._dataset_withdraw import REASONS

    red = verbs.add_parser("contrib-redact", help="Redact one run into a signed public bundle")
    red.add_argument("run", metavar="RUN", help="A run ref or run id")
    red.add_argument(
        "--deny-list",
        required=True,
        metavar="FILE",
        help="Local terms to remove; never written anywhere",
    )
    red.add_argument("--licence", required=True, metavar="SPDX", help="One SPDX licence id")
    red.add_argument(
        "--relicensing-grant",
        action="store_true",
        help="Opt in: curators may relicense the contribution",
    )
    red.add_argument("--key", required=True, metavar="KEY", help="The contributor Ed25519 key")
    red.add_argument("--out", required=True, metavar="BUNDLE")
    red.add_argument("--pack-format", choices=("TINEPACK3", "TINEPACK5"), default="TINEPACK3")
    check = verbs.add_parser("check", help="Refuse a contributed bundle without a valid licence")
    check.add_argument("bundle", metavar="BUNDLE")
    check.add_argument("--pubkey", metavar="PATH", help="Require this contributor Ed25519 key")
    check.add_argument("--tombstones", metavar="FILE", help="Refuse a tombstoned run")
    wd = verbs.add_parser("withdraw", help="Sign and hold the withdrawal of a contributed run")
    wd.add_argument("run", metavar="RUN", help="A run ref or run id")
    wd.add_argument("--key", required=True, metavar="KEY", help="The contributor Ed25519 key")
    wd.add_argument("--reason", required=True, choices=REASONS)
    wd.add_argument("--tombstones", metavar="FILE", help="Add the tombstone to this manifest")
    for verb in (red, check):
        verb.add_argument(
            "--allow",
            action="append",
            metavar="SPDX",
            help="Allowed licence id (repeatable; default: a permissive set)",
        )
    for verb in (red, wd):
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository root")
    for verb in (red, check, wd):
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _resolve(repo: Any, name: str) -> tuple[str, str]:
    """``(ref, run id)`` for a ref name or a run id."""
    from opentine.repository._refs import normalize_ref

    if name.startswith("run:"):
        if not repo.has(name):
            raise KeyError(f"no run {name} in the repository")
        return "heads/contrib", name
    ref = normalize_ref(name if "/" in name else f"heads/{name}")
    run = repo.read_ref(ref)
    if not run or not run.startswith("run:"):
        raise KeyError(f"no such run ref: {name}")
    return ref, run


def _redact(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _contrib_bundle, _contrib_denylist, _dataset_licence
    from opentine._cli_integrity import _key
    from opentine._promote import _now
    from opentine.repo import Repo

    deny = _contrib_denylist.load(args.deny_list)
    allow = _dataset_licence.allow_list(args.allow)
    repo = Repo.open(Path(args.repo))
    ref, run = _resolve(repo, args.run)
    data, summary = _contrib_bundle.build(
        repo,
        ref,
        run,
        _key(args),
        deny,
        spdx=args.licence,
        grant=args.relicensing_grant,
        at=args.at or _now(),
        allow=allow,
        pack_format=args.pack_format,
    )
    scan = _contrib_bundle.leak_scan(data, deny)
    out = Path(args.out)
    if scan["hits"]:
        out.unlink(missing_ok=True)
        return {"ok": False, "out": None, "sha256": None, **summary, "leak_scan": scan}
    out.write_bytes(data)
    import hashlib

    return {
        "ok": True,
        "out": out.as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        **summary,
        "leak_scan": scan,
    }


def _check(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _bundle, _contrib_bundle, _dataset_licence
    from opentine._dataset_withdraw import read_tombstones
    from opentine._signing_keys import ed25519_public_from_file

    allow = _dataset_licence.allow_list(args.allow)
    pubkey = ed25519_public_from_file(args.pubkey).public_bytes_raw() if args.pubkey else None
    tombs = read_tombstones(args.tombstones) if args.tombstones else None
    data = _bundle.read_file(args.bundle)
    row = _contrib_bundle.check(data, allow=allow, pubkey=pubkey, tombstones=tombs)
    return {"bundle": Path(args.bundle).as_posix(), **row}


def _withdraw(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _dataset_withdraw as wd
    from opentine._cli_integrity import _key
    from opentine._promote import _now
    from opentine.repo import Repo

    repo = Repo.open(Path(args.repo))
    _, run = _resolve(repo, args.run)
    record = wd.withdraw(repo, run, _key(args), args.reason, args.at or _now())
    row = next(r for r in wd.withdrawals(repo) if r["record"] == record)
    stone = wd.tombstone(row)
    count = None
    if args.tombstones:
        count = len(wd.write_tombstones(args.tombstones, [stone]))
    return {
        "ok": True,
        "record": record,
        "run": run,
        "reason": args.reason,
        "contributor": row["contributor"],
        "state": row["state"],
        "tombstone": stone,
        "tombstones": count,
    }


def _say(verb: str, row: dict[str, Any]) -> list[str]:
    if verb == "contrib-redact":
        scan = row["leak_scan"]
        if not row["ok"]:
            return [f"REFUSED: {scan['hits']} deny-list hits in the unbundled copy; no bundle"]
        return [
            f"WROTE {row['out']} public run {row['public_run']} ({row['redacted']} of "
            f"{row['objects']} objects redacted; leak scan clean)"
        ]
    if verb == "check":
        return ["OK" if row["ok"] else "REFUSED", *(f"  {p}" for p in row["problems"])]
    return [f"WITHDRAWN {row['run']} ({row['reason']}) record {row['record']}"]


def cmd_contrib(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._contrib_denylist import DenyListError
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    verb = args.dataset_command
    handler = {"contrib-redact": _redact, "check": _check, "withdraw": _withdraw}[verb]
    try:
        row = handler(args)
    except (
        DenyListError,
        PassphraseUnavailable,
        SignatureError,
        KeyError,
        OSError,
        ValueError,
    ) as exc:
        raise error(exc, prefix=f"dataset {verb}: ") from exc
    if args.json:
        emit({"command": f"dataset {verb}", "schema": SCHEMA, **row})
    else:
        for line in _say(verb, row):
            console.print(_terminal(line), markup=False)
    if row.get("ok") is False:
        raise SystemExit(1)


__all__ = ["SCHEMA", "VERBS", "add_contrib_verbs", "cmd_contrib"]
