"""``tine lineage diff OLD NEW`` (0.88): the signed structural diff of two variants.

``--from``/``--to`` name the variants by id; each must be a signed record in the
lineage folder, and ``bound`` reports whether its recorded artifacts include the
tree's digest. ``--key`` signs the diff (:mod:`opentine._sdiff`) into
``--out`` (default ``LINEAGE_FOLDER/diffs/HEX.json``). ``--check FILE`` verifies
a signed diff and, given OLD and NEW, recomputes it (exit 1 when it does not
hold). ``--tree`` prints the tree digest of each path, the value to record as
``--code-tree``/``--skill`` so a later diff is bound to the variant.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error

SCHEMA = "tine-cli-lineage-diff/1"


def add_diff_parser(actions: argparse._SubParsersAction) -> None:
    diff = actions.add_parser("diff", help="Signed structural diff between two variants")
    diff.add_argument("old", nargs="?", help="The older variant's tree (directory or file)")
    diff.add_argument("new", nargs="?", help="The newer variant's tree (directory or file)")
    diff.add_argument("--repo", default=".", metavar="PATH", help="v3 repository")
    diff.add_argument("--dir", metavar="DIR", help="Lineage folder (REPO/.tine/lineage)")
    diff.add_argument("--from", dest="from_variant", metavar="VARIANT", help="Older variant id")
    diff.add_argument("--to", dest="to_variant", metavar="VARIANT", help="Newer variant id")
    diff.add_argument("--key", metavar="KEY", help="Ed25519 private key that signs the diff")
    diff.add_argument("--out", metavar="FILE", help="Signed diff file (LINEAGE/diffs/HEX.json)")
    diff.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    diff.add_argument("--check", metavar="FILE", help="Verify a signed diff file")
    diff.add_argument("--tree", action="store_true", help="Print each path's tree digest")
    diff.add_argument("--json", action="store_true", help="Machine-readable output")


def _folder(args: argparse.Namespace) -> Path:
    from opentine._lineage import FOLDER

    return Path(args.dir) if args.dir else Path(args.repo) / FOLDER


def _artifacts(args: argparse.Namespace, variant: str | None) -> dict | None:
    from opentine._lineage import DIGEST_RE, loads, signed
    from opentine._sdiff import DiffRefused

    if variant is None:
        return None
    if not DIGEST_RE.fullmatch(variant):
        raise DiffRefused("lineage-diff.variant-unknown", f"{variant!r} is not a sha256: id")
    try:
        doc = loads((_folder(args) / "variants" / f"{variant[7:]}.json").read_bytes())
    except (OSError, ValueError, RecursionError):
        doc = None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not (isinstance(claim, dict) and claim.get("variant") == variant and signed(doc)):
        raise DiffRefused(
            "lineage-diff.variant-unknown",
            f"{variant} is not a signed record in {_folder(args).as_posix()}",
        )
    return dict(claim.get("artifacts") or {})


def _row(args: argparse.Namespace) -> dict:
    from opentine import _sdiff

    paths = [p for p in (args.old, args.new) if p is not None]
    if args.tree:
        if not paths:
            raise error("lineage diff --tree needs a path", USAGE, prefix="lineage: ")
        trees = [{"path": Path(p).as_posix(), "tree": _sdiff.tree_digest(_sdiff.listing(Path(p)))}
                 for p in paths]  # fmt: skip
        return {"mode": "tree", "ok": True, "trees": trees}
    if args.check:
        if len(paths) == 1:
            raise error("lineage diff --check takes both OLD and NEW, or neither", USAGE,
                        prefix="lineage: ")  # fmt: skip
        trees = [Path(p) for p in paths] or [None, None]
        return {"mode": "check", **_sdiff.check(Path(args.check), *trees)}
    if len(paths) != 2:
        raise error("lineage diff needs OLD and NEW", USAGE, prefix="lineage: ")
    claim = _sdiff.compute(Path(args.old), Path(args.new), from_variant=args.from_variant,
                           to_variant=args.to_variant,
                           from_artifacts=_artifacts(args, args.from_variant),
                           to_artifacts=_artifacts(args, args.to_variant))  # fmt: skip
    signed_path = None
    if args.key:
        from opentine._promote import _now
        from opentine._signing_keys import ed25519_private_from_file

        key = ed25519_private_from_file(args.key, signer=False)
        raw = _sdiff.dumps(_sdiff.sign(claim, key, at=args.at or _now()))
        out = Path(args.out) if args.out else (
            _folder(args) / "diffs" / f"{hashlib.sha256(raw).hexdigest()}.json")  # fmt: skip
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)
        signed_path = out.as_posix()
    elif args.out:
        raise error("lineage diff --out needs --key: only a signed diff is filed", USAGE,
                    prefix="lineage: ")  # fmt: skip
    return {"mode": "diff", "ok": True, "signed": signed_path, "claim": claim}


def _text(row: dict) -> str:
    if row["mode"] == "tree":
        return "\n".join(f"{t['tree']} {t['path']}" for t in row["trees"])
    if row["mode"] == "check":
        lines = [f"{'OK' if row['ok'] else 'REFUSED'} signed by {row['signer']}"]
        return "\n".join(lines + [f"  {f['code']}: {f['detail']}" for f in row["findings"]])
    claim = row["claim"]
    totals = claim["totals"]
    lines = [f"{totals['changed']} of {totals['files']} files changed, {totals['structural']} "
             f"structurally, {totals['flagged']} flagged"]  # fmt: skip
    for item in claim["files"]:
        mark = "" if item["structural"] else " (no structural change)"
        flags = f" flags: {', '.join(item['flags'])}" if item["flags"] else ""
        lines.append(f"{item['status']} {item['kind']} {item['path']}{mark}{flags}")
        for change in item["changes"][:50]:
            lines.append(f"  {change['op']} {change.get('item', change.get('before', ''))}")
    if row["signed"]:
        lines.append(f"SIGNED {row['signed']}")
    return "\n".join(lines)


def cmd_diff(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._key_store import PassphraseUnavailable
    from opentine._sdiff import DiffRefused
    from opentine._signing_keys import SignatureError

    try:
        row = _row(args)
    except (DiffRefused, PassphraseUnavailable, SignatureError, OSError, ValueError) as exc:
        raise error(exc, prefix="lineage: ") from exc
    if args.json:
        emit({"command": "lineage diff", "schema": SCHEMA, **row})
    else:
        for line in _text(row).split("\n"):
            console.print(_terminal(line), markup=False)
    if not row["ok"]:
        raise SystemExit(1)


__all__ = ["SCHEMA", "add_diff_parser", "cmd_diff"]
