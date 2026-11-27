"""``tine dataset seal|unseal|exposure`` (0.60).

Canaries live in :mod:`opentine._cli_canary` (``canary-add|canary-list|canary-check``)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

VERBS = ("seal", "unseal", "exposure")


def add_holdout_parsers(verbs: Any) -> list[Any]:
    seal = verbs.add_parser("seal", help="Seal a JSONL dataset: Merkle commitment + TINEAES")
    seal.add_argument("dataset", metavar="DATASET.jsonl")
    seal.add_argument("--out", required=True, metavar="DIR", help="Sealed holdout folder")
    seal.add_argument("--name", required=True, help="Holdout name ([a-z0-9._-])")
    seal.add_argument("--max-unseals", type=int, required=True, help="Exposure budget: unseals")
    seal.add_argument("--max-items", type=int, required=True, help="Exposure budget: items")
    seal.add_argument("--max-queries", type=int, metavar="N",
                      help="Query budget: evals per lineage node (0.86)")  # fmt: skip
    seal.add_argument("--rotate-from", metavar="DIR", help="The generation this one replaces")
    unseal = verbs.add_parser("unseal", help="Record a signed access, then release items")
    unseal.add_argument("folder", metavar="DIR")
    unseal.add_argument("--out", required=True, metavar="FILE.jsonl", help="Released items")
    unseal.add_argument("--run", required=True, help="The run the access is for")
    unseal.add_argument("--why", required=True, help="Why (recorded, signed)")
    unseal.add_argument("--purpose", choices=("eval", "other"), default="eval")
    unseal.add_argument("--items", metavar="I,J", help="Item indices (default: all)")
    unseal.add_argument("--exceed-budget", action="store_true",
                        help="Record an unseal over budget (promote then refuses)")  # fmt: skip
    exposure = verbs.add_parser("exposure", help="A holdout's exposure and commitment chain")
    exposure.add_argument("folder", metavar="DIR")
    exposure.add_argument("--chain", nargs="*", default=[], metavar="OLDER",
                          help="Older generations, oldest first, to check the chain")  # fmt: skip
    for verb in (seal, unseal):
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
        verb.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    for verb in (seal, unseal):
        verb.add_argument("--seal-key", required=True, metavar="FILE",
                          help="32-byte seal key, outside DIR (seal creates it)")  # fmt: skip
    for verb in (seal, unseal, exposure):
        verb.add_argument("--repo", default=".", help="Repository holding the key roles")
    return [seal, unseal, exposure]


def _now(at: str | None) -> str:
    from opentine._promote import _now

    return at or _now()


def _key(path: str) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(path, signer=False)


def _inside(path: Path, folder: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(folder).resolve())
    except ValueError:
        return False
    return True


def _seal(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _holdout as holdout
    from opentine._eval_dataset import read_jsonl
    from opentine._signing_pins import key_fingerprint

    if _inside(Path(args.seal_key), Path(args.out)):
        raise holdout.HoldoutError("holdout.seal-key", "keep the seal key outside DIR")
    if args.max_unseals < 1 or args.max_items < 1 or (args.max_queries or 1) < 1:
        raise holdout.HoldoutError("holdout.budget", "budgets are at least 1")
    key = _key(args.key)
    holdout.require_role(Path(args.repo), key_fingerprint(key.public_key().public_bytes_raw()),
                         "dataset")  # fmt: skip
    previous = holdout.load(Path(args.rotate_from)) if args.rotate_from else None
    master = holdout.seal_key(Path(args.seal_key), create=True)
    claim = holdout.seal(read_jsonl(Path(args.dataset)), Path(args.out), name=args.name,
                         key=key, master=master, at=_now(args.at), previous=previous,
                         budget={"max_unseals": args.max_unseals, "max_items": args.max_items,
                                 **({"max_queries": args.max_queries}
                                    if args.max_queries is not None else {})})  # fmt: skip
    return {"out": Path(args.out).as_posix(), **{k: claim[k] for k in (
        "holdout", "root", "items", "generation", "previous", "budget")}}  # fmt: skip


def _unseal(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._holdout import seal_key
    from opentine._holdout_access import unseal

    indices = [int(x) for x in args.items.split(",")] if args.items else None
    return unseal(Path(args.folder), seal_key(Path(args.seal_key), create=False), _key(args.key),
                  repo=Path(args.repo), run=args.run, why=args.why, purpose=args.purpose,
                  indices=indices, at=_now(args.at), out=Path(args.out),
                  exceed_budget=args.exceed_budget)  # fmt: skip


def _exposure(args: argparse.Namespace) -> dict[str, Any]:
    from opentine._holdout import chain
    from opentine._holdout_access import exposure

    links = chain([Path(p) for p in [*args.chain, args.folder]])
    row = {k: v for k, v in exposure(Path(args.folder), Path(args.repo)).items()
           if not k.startswith("_")}  # fmt: skip
    from opentine._holdout_query import counts

    queries = counts(Path(args.folder), Path(args.repo))  # 0.86: advisory, ok unchanged
    return {
        **row,
        "chain": links,
        "queries": queries,
        "ok": not row["over_budget"] and row["chain_ok"],
    }


def cmd_holdout(args: argparse.Namespace) -> None:
    from opentine._cli_common import console
    from opentine._cli_errors import ERROR, fail
    from opentine._cli_json import emit
    from opentine._eval_dataset import DatasetError
    from opentine._holdout import HoldoutError
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    verb = args.dataset_command
    handler = {"seal": _seal, "unseal": _unseal, "exposure": _exposure}[verb]
    try:
        row = handler(args)
    except HoldoutError as exc:
        row = {"ok": False, "refusals": [{"code": exc.code, "detail": exc.detail}]}
    except (DatasetError, PassphraseUnavailable, SignatureError, OSError, ValueError) as exc:
        fail(exc, ERROR, prefix=f"dataset {verb}: ", cause=exc)
    row = {"ok": True, **row} if "ok" not in row else row
    if args.json:
        emit({"command": f"dataset {verb}", "schema": "tine-cli-holdout/1", **row})
    else:
        printable = {k: v for k, v in row.items() if k != "records"}
        console.print(json.dumps(printable, indent=2, sort_keys=True), highlight=False,
                      markup=False)  # fmt: skip
    if not row["ok"]:
        raise SystemExit(1)


__all__ = ["VERBS", "add_holdout_parsers", "cmd_holdout"]
