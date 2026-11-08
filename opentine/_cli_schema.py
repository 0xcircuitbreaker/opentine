"""``tine schema list|show|validate``: the published JSON Schemas (0.45).

``list`` names every schema; ``show NAME`` prints one exactly as
``docs/schemas/NAME.schema.json`` holds it; ``validate FILE [--schema NAME]``
checks a JSON document (``-`` reads stdin), choosing the schema from the
document's ``schema``/``scheme``/``format`` tag or its ``command`` when none is
named. ``validate`` exits 4 (verify failed) on an invalid document; an unknown schema
or a missing file exits 3 (not found); a document nested deeper than
:data:`MAX_DEPTH` is refused as a usage error (exit 2) before any recursion.
``show --json`` wraps the schema in the CLI envelope (``definition``) because a
bare schema names no ``command``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opentine import _schemas
from opentine._cli_errors import NOT_FOUND, USAGE, VERIFICATION_FAILED, fail
from opentine._cli_json import emit

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
#: Deepest nesting ``validate`` accepts (the canonical JSON bound, SPEC 1.1).
MAX_DEPTH = 512


def _too_deep(document: object) -> bool:
    """Whether *document* nests past :data:`MAX_DEPTH`, measured without recursion."""
    stack = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, (dict, list)):
            if depth > MAX_DEPTH:
                return True
            items = value.values() if isinstance(value, dict) else value
            stack.extend((item, depth + 1) for item in items)
    return False


def _deep(path: str) -> None:
    fail(f"{path} nests deeper than {MAX_DEPTH} levels; not validated", USAGE)


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
        document = json.loads(raw.decode("utf-8"))
    except RecursionError:
        _deep(path)
    except FileNotFoundError:
        fail(f"cannot read {path}: no such file", NOT_FOUND)
    except OSError as exc:
        fail(f"cannot read {path}: {exc.strerror or exc}")
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"{path} is not JSON: {exc}")
    if _too_deep(document):
        _deep(path)
    return document


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
            schema = _schemas.get(args.name)
            if args.json:  # the envelope: the schema itself names no `command`
                emit({"command": "schema-show", "name": _schemas.stem(args.name),
                      "definition": schema})  # fmt: skip
            else:
                sys.stdout.write(_schemas.render(schema))
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
        fail(str(exc.args[0]), NOT_FOUND)


COMMANDS = {"schema": cmd_schema}

__all__ = ["COMMANDS", "add_schema_parser", "cmd_schema"]
