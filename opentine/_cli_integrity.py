"""``tine integrity check|pin|sign|scan`` (0.59; scan 0.60): protected surfaces.

``check RUN`` judges the run's tool calls and every pinned digest against the
signed ``.tine/protected.toml`` (:mod:`opentine._integrity_run`) and exits 1 on
any ``fail:`` finding; ``--record`` adds the advisory reward-hack detectors
over a run record. ``advisory:`` findings never block unless ``--strict``
(owner decision D12). With ``--key`` a run that tripped a ``fail:`` is marked
by a signed ``opentine.integrity.taint`` attestation. ``pin`` writes the
current digests of every protected file into the list (which must then be
re-signed); ``sign`` pins the list's bytes with a ``policy``-role key.
``scan`` (0.60) finds registered canaries (:mod:`opentine._canary_scan`).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._cli_errors import USAGE, error

SCHEMA = "tine-cli-integrity/1"


def add_integrity_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("integrity", help="Protected surfaces: graders, tests, holdouts")
    verbs = parser.add_subparsers(dest="integrity_command", required=True)
    check = verbs.add_parser("check", help="Check a run against the protected surfaces")
    pin = verbs.add_parser("pin", help="Write current digests of protected files into the list")
    sign = verbs.add_parser("sign", help="Sign the protected list with a policy-role key")
    scan = verbs.add_parser("scan", help="Find registered canaries in runs, prompts, memory, packs")
    scan.add_argument(
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="Also search this file (an exported pack or bundle) as raw bytes",
    )
    for p in (check, pin, sign, scan):
        p.add_argument("--repo", default=".", metavar="PATH", help="Repository root")
        p.add_argument("--json", action="store_true", help="Machine-readable output")
    check.add_argument("run", help="The run (run:sha256:HEX)")
    check.add_argument("--strict", action="store_true", help="Advisory findings block too")
    check.add_argument("--record", metavar="PATH", help="Run record: also run the detectors")
    for p in (check, sign):
        p.add_argument("--key", metavar="KEY", help="Ed25519 key (check: signs the taint)")
        p.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")


def _key(args: argparse.Namespace):
    from opentine._signing_keys import ed25519_private_from_file

    return ed25519_private_from_file(args.key, signer=False)


def _pin(root: Path) -> dict:
    from opentine._integrity import parse
    from opentine._integrity_defaults import merged
    from opentine._integrity_observe import pins
    from opentine._integrity_run import LIST

    path = root / LIST
    protected = merged(parse(path.read_bytes()), root)  # 0.85: default surfaces folded in
    found = pins(protected, root)
    for surface in protected["surfaces"]:  # literal .tine files (pins() skips .tine)
        for glob in surface["globs"]:
            if glob.startswith(".tine/") and "*" not in glob and (root / glob).is_file():
                found[surface["name"]][glob] = _sha(root / glob)
    lines = ["version = 1"]
    for surface in protected["surfaces"]:
        globs = ", ".join(json.dumps(g) for g in surface["globs"])
        lines += ["", "[[surface]]", f'name = "{surface["name"]}"',
                  f'kind = "{surface["kind"]}"', f"globs = [{globs}]",
                  "[surface.pins]"]  # fmt: skip
        lines += [f'{json.dumps(p)} = "{d}"' for p, d in sorted(found[surface["name"]].items())]
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return {"ok": True, "pins": sum(len(v) for v in found.values()),
            "list": path.as_posix(), "signed": False}  # fmt: skip


def _sha(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _detected(path: str) -> list[dict[str, str]]:
    """The advisory detectors over a run record, as ``advisory:`` findings (D12)."""
    from opentine._integrity_advisory_evidence import advise

    record = json.loads(Path(path).read_bytes())
    if not isinstance(record, dict):
        raise ValueError(f"{path}: a run record is a JSON object")
    found = advise(record)["findings"]
    return [{"level": "advisory", "code": f["code"], "surface": "detector",
             "path": f["path"], "detail": f["detail"]} for f in found]  # fmt: skip


def _row(args: argparse.Namespace) -> dict:
    from opentine import _integrity_run as run
    from opentine._promote import _now

    root = Path(args.repo)
    command = args.integrity_command
    if command == "pin":
        return _pin(root)
    if command == "scan":
        from opentine._canary_scan import scan

        return scan(root, args.file)
    if command == "sign":
        if not args.key:
            raise error("integrity sign needs --key", USAGE, prefix="integrity: ")
        return {"ok": True, **run.sign_list(root, _key(args), args.at or _now())}
    row = run.check_run(root, args.run, strict=args.strict)
    if args.record:
        from opentine._integrity import blocking

        row["findings"] += _detected(args.record)
        hard = blocking(row["findings"], strict=args.strict)
        row["ok"], row["blocking"] = not hard, len(hard)
    if args.key and any(f["level"] == "fail" for f in row["findings"]):
        row["taint"] = run.taint(root, _key(args), row, args.at or _now())
    return row


def cmd_integrity(args: argparse.Namespace) -> None:
    from opentine._cli_json import emit
    from opentine._integrity import ProtectedError
    from opentine._key_store import PassphraseUnavailable
    from opentine._signing_keys import SignatureError

    try:
        row = _row(args)
    except (PassphraseUnavailable, SignatureError, ProtectedError, OSError, ValueError) as exc:
        raise error(exc, prefix="integrity: ") from exc
    command = args.integrity_command
    if args.json:
        emit({"command": f"integrity {command}", "schema": SCHEMA, **row})
    elif command == "check":
        verdict = "OK" if row["ok"] else "TAINTED"
        console.print(_terminal(f"{verdict} {row['run']} ({len(row['touched'])} files touched)"),
                      markup=False)  # fmt: skip
        for f in row["findings"]:
            console.print(_terminal(f"  {f['code']} {f['path']}: {f['detail']}"), markup=False)
        if row["taint"]:
            console.print(_terminal(f"  taint: {row['taint']['path']}"), markup=False)
    elif command == "pin":
        console.print(_terminal(f"PINNED {row['pins']} files in {row['list']}; re-sign it"),
                      markup=False)  # fmt: skip
    elif command == "scan":
        verdict = "CLEAN" if row["ok"] else "CANARY FOUND"
        console.print(_terminal(f"{verdict} {row['counts']}"), markup=False)
        for m in row["matches"]:
            console.print(_terminal(f"  {m['surface']} {m['where']}: {m['canary_sha256']}"),
                          markup=False)  # fmt: skip
    else:
        console.print(_terminal(f"SIGNED {row['protected_sha256']} by {row['signer']}"),
                      markup=False)  # fmt: skip
    if row.get("ok") is False:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"integrity": cmd_integrity}

__all__ = ["COMMANDS", "SCHEMA", "add_integrity_parser", "cmd_integrity"]
