"""``tine agent scaffold | scaffold-diff | scaffold-pin`` (0.88): scaffold manifests.

* ``scaffold`` prints the scaffold manifest of a harness under ``--root``
  (:mod:`opentine._scaffold_manifest`); with ``--record RUN --key KEY --repo
  PATH`` it also signs it onto the stored run as a held attestation
  (:mod:`opentine._scaffold_record`).
* ``scaffold-diff BEFORE AFTER`` compares two manifests (a manifest file, or a
  ``tine agent scaffold --json`` output) path by path.
* ``scaffold-pin --harness H --glob G... --key KEY`` signs the list of scaffold
  globs that replaces the defaults (:mod:`opentine._scaffold_files`).

Manifest files are untrusted JSON (read through :mod:`opentine._json_shallow`).
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import fail

SCHEMA = "tine-cli-scaffold/1"
MAX_MANIFEST = 64 << 20


def _emit(args: argparse.Namespace, payload: dict[str, Any], lines: list[str]) -> None:
    if args.json:
        from opentine._cli_json import emit

        emit({"command": f"agent {args.agent_command}", "schema": SCHEMA, **payload})
        return
    for line in lines:
        console.print(line, markup=False, highlight=False)


def _key(path: str) -> Any:
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(path, signer=False)


def _at(args: argparse.Namespace) -> str:
    from opentine._utc import rfc3339_utc

    return args.at or rfc3339_utc(time.time())


def _scaffold(args: argparse.Namespace) -> None:
    from opentine._scaffold_manifest import build

    manifest = build(args.harness, args.root)
    record = None
    if args.record:
        if not (args.key and args.repo):
            fail("--record needs --key and --repo", 2, prefix="agent scaffold")
        from opentine._scaffold_record import record as file_record
        from opentine.repo import Repo

        record = file_record(Repo.open(args.repo), args.record, manifest, _key(args.key))
    lines = [f"scaffold {_terminal(args.harness)} ({manifest['source']}): "
             f"{len(manifest['files'])} file(s), tree {manifest['tree_sha256'][:16]}"]  # fmt: skip
    lines += [f"  {row['kind']:<8} {_terminal(row['path'])}" for row in manifest["files"]]
    if record:
        lines.append(f"recorded {record} on {_terminal(args.record)}")
    _emit(args, {"manifest": manifest, "record": record}, lines)


def _load(path: str) -> dict[str, Any]:
    from opentine import _json_shallow
    from opentine._scaffold_manifest import SCHEMA as MANIFEST

    with open(path, "rb") as handle:
        raw = handle.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ValueError(f"{path} is larger than {MAX_MANIFEST} bytes")
    doc = _json_shallow.loads(raw)
    doc = doc.get("manifest", doc) if isinstance(doc, dict) else doc
    files = doc.get("files") if isinstance(doc, dict) else None
    if (
        doc.get("schema") != MANIFEST
        or not isinstance(files, list)
        or not all(isinstance(r, dict) and isinstance(r.get("path"), str) for r in files)
    ):
        raise ValueError(f"{path} is not an {MANIFEST} manifest")
    from opentine._scaffold_manifest import tree_digest

    if tree_digest(files) != doc.get("tree_sha256"):
        raise ValueError(f"{path}: tree_sha256 does not match its files")
    return doc


def _diff(args: argparse.Namespace) -> None:
    from opentine._scaffold_manifest import diff

    before, after = _load(args.before), _load(args.after)
    found = diff(before, after)
    payload = {"before_tree": before["tree_sha256"], "after_tree": after["tree_sha256"],
               **found}  # fmt: skip
    lines = ["same scaffold" if found["same"] else
             f"{len(found['added'])} added, {len(found['removed'])} removed, "
             f"{len(found['changed'])} changed"]  # fmt: skip
    lines += [f"+ {_terminal(p)}" for p in found["added"]]
    lines += [f"- {_terminal(p)}" for p in found["removed"]]
    lines += [f"~ {_terminal(r['path'])}" for r in found["changed"]]
    _emit(args, payload, lines)


def _pin(args: argparse.Namespace) -> None:
    from opentine._scaffold_files import pin

    row = pin(Path(args.root), {args.harness: list(args.glob or [])}, _key(args.key), _at(args))
    _emit(args, row, [f"pinned {len(row['harnesses'][args.harness])} glob(s) for "
                      f"{_terminal(args.harness)} at {_terminal(row['pin'])}"])  # fmt: skip


HANDLERS = {"scaffold": _scaffold, "scaffold-diff": _diff, "scaffold-pin": _pin}


def run(args: argparse.Namespace) -> None:
    from opentine._scaffold_files import ScaffoldError

    try:
        HANDLERS[args.agent_command](args)
    except ScaffoldError as exc:
        fail(str(exc), 1, prefix=f"agent {args.agent_command}")
    except (OSError, ValueError, KeyError) as exc:
        fail(str(exc), 2, prefix=f"agent {args.agent_command}")


def add_parsers(verbs: Any) -> None:
    scaffold = verbs.add_parser("scaffold", help="Digest every scaffold file of a harness")
    scaffold.add_argument("--harness", default="claude-code")
    scaffold.add_argument("--root", default=".", help="Directory the scaffold is under")
    scaffold.add_argument("--record", metavar="RUN", help="Sign the manifest onto this run")
    scaffold.add_argument("--key", metavar="KEY", help="Ed25519 key that signs the record")
    diff = verbs.add_parser("scaffold-diff", help="Compare two scaffold manifests")
    diff.add_argument("before", metavar="BEFORE")
    diff.add_argument("after", metavar="AFTER")
    pin = verbs.add_parser("scaffold-pin", help="Sign the scaffold globs of a harness")
    pin.add_argument("--harness", required=True)
    pin.add_argument("--glob", action="append", metavar="GLOB", help="A scaffold glob")
    pin.add_argument("--key", metavar="KEY", required=True, help="A policy-role key")
    pin.add_argument("--root", default=".", help="Repository root the list is filed under")
    pin.add_argument("--at", metavar="RFC3339", help="Signing time")


__all__ = ["HANDLERS", "SCHEMA", "add_parsers", "run"]
