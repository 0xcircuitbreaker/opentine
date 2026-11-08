"""``tine schema list|show|validate``: the published JSON Schemas (0.45).

``list`` names every schema; ``show NAME`` prints one exactly as
``docs/schemas/NAME.schema.json`` holds it; ``validate FILE [--schema NAME]``
checks a JSON document (``-`` reads stdin), choosing the schema from the
document's ``schema``/``scheme``/``format`` tag or its ``command`` when none is
named. ``validate`` exits 4 (verify failed) on an invalid document.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opentine import _schemas
from opentine._cli_errors import VERIFICATION_FAILED, fail
from opentine._cli_json import emit

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


def add_schema_parser(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("schema", help="List, show and validate the published JSON Schemas")
    verbs = parser.add_subparsers(dest="schema_command", metavar="VERB", required=True)
    listing = verbs.add_parser("list", help="Name every published schema")
    show = verbs.add_parser("show", help="Print one schema")
    show.add_argument("name", metavar="NAME", help="e.g. tine-verify-report-2 or a tag")
    check = verbs.add_parser("validate", help="Check a JSON document against its schema")
    check.add_argument("file", metavar="FILE", help="JSON document, or - for stdin")
    check.add_argument("--schema", metavar="NAME", help="Schema to use (default: detect)")
    for verb in (listing, show, check):
        verb.add_argument("--json", action="store_true", help="Emit a JSON object instead")


def _read(path: str) -> object:
    try:
        raw = (
            sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
            if path == "-"
            else (Path(path).read_bytes())
        )
        if len(raw) > MAX_DOCUMENT_BYTES:
            fail(f"{path} is larger than {MAX_DOCUMENT_BYTES} bytes")
        return json.loads(raw.decode("utf-8"))
    except OSError as exc:
        fail(f"cannot read {path}: {exc.strerror or exc}")
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"{path} is not JSON: {exc}")
    raise AssertionError("unreachable")  # pragma: no cover


def cmd_schema(args: argparse.Namespace) -> None:
    verb = args.schema_command
    try:
        if verb == "list":
            rows = [{"name": n, "id": _schemas.SCHEMAS[n]["$id"], "title": _schemas.summary(n)}
                    for n in _schemas.names()]  # fmt: skip
            if args.json:
                emit({"command": "schema-list", "count": len(rows), "schemas": rows})
            else:
                print("\n".join(f"{r['name']:<30} {r['title']}" for r in rows))
        elif verb == "show":
            sys.stdout.write(_schemas.render(_schemas.get(args.name)))
        else:
            name, errors = _schemas.validate(_read(args.file), args.schema)
            if args.json:
                emit({"command": "schema-validate", "file": args.file, "schema_name": name,
                      "ok": not errors, "errors": errors})  # fmt: skip
            else:
                for error in errors:
                    print(f"{args.file}: {error or '/'}", file=sys.stderr)
                print(f"{args.file}: {'valid' if not errors else 'INVALID'} ({name})")
            if errors:
                raise SystemExit(VERIFICATION_FAILED)
    except _schemas.SchemaError as exc:
        fail(str(exc.args[0]))


COMMANDS = {"schema": cmd_schema}

__all__ = ["COMMANDS", "add_schema_parser", "cmd_schema"]
