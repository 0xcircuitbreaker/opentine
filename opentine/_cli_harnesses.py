"""``tine harnesses``: every agent CLI ``tine run --harness`` drives, and how well.

A plug-and-play check: which CLIs are installed here, the command each runs, and
what a recorded run of it will hold -- the model, token usage (what makes it
priceable), the CLI's own cost figure, and tool calls with results.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from rich.markup import escape
from rich.table import Table

from opentine._cli_common import HARNESS_FACTORIES, console
from opentine.harnesses._harness_catalog import FIDELITY

#: Fidelity of the harnesses with dedicated parsers (not catalogue rows).
_DEDICATED = {
    "claude-code": ("yes", "yes", "yes", "yes"),
    "codex": ("flag", "yes", "no", "yes"),
    "generic": ("your events", "your events", "your events", "your events"),
}


def harness_rows() -> list[dict[str, object]]:
    rows = []
    for name in sorted(HARNESS_FACTORIES):
        factory = HARNESS_FACTORIES[name]
        command = tuple(getattr(factory, "default_command", ()) or ())
        declared = getattr(factory, "fidelity", None)
        fidelity = (
            dict(declared)
            if declared
            else dict(zip(FIDELITY, _DEDICATED.get(name, ("no",) * 4), strict=True))
        )
        rows.append(
            {
                "name": name,
                "command": list(command),
                "installed": bool(command) and shutil.which(command[0]) is not None,
                **{column: fidelity.get(column, "no") for column in FIDELITY},
            }
        )
    return rows


def check_adapters(only: str | None) -> int:
    """``tine harnesses --check [NAME]``: every importer adapter's conformance."""
    from opentine.harnesses._adapter_spec import builtin_specs, check, external_specs

    external, skipped = external_specs()
    specs = {**builtin_specs(), **external}
    if only and only not in specs and only not in skipped:
        console.print(f"[red]no adapter {escape(only)}[/]")
        return 1
    failed = 0
    for name in sorted({*specs, *skipped}):
        if only and name != only:
            continue
        origin = "built-in" if specs.get(name) and specs[name].description == "built-in" else "ext"
        issues = check(specs[name]) if name in specs else [skipped[name]]
        failed += bool(issues) and "not allowlisted" not in skipped.get(name, "")
        state = "ok" if not issues else "; ".join(issues)
        console.print(f"  {name:<24} {origin:<9} {state}", markup=False)
    return 1 if failed else 0


def cmd_harnesses(args: argparse.Namespace) -> None:
    if getattr(args, "check", None):
        raise SystemExit(check_adapters(None if args.check == "*" else args.check))
    rows = harness_rows()
    if getattr(args, "installed", False):
        rows = [row for row in rows if row["installed"]]
    if getattr(args, "json", False):
        sys.stdout.write(
            json.dumps({"command": "harnesses", "harnesses": rows}, ensure_ascii=True) + "\n"
        )
        return
    table = Table(title="Agent CLI harnesses (tine run --harness NAME --prompt ...)")
    for column in ("harness", "command", "installed", *FIDELITY):
        table.add_column(column)
    for row in rows:
        command = " ".join(row["command"]) or "--harness-command CMD"  # type: ignore[arg-type]
        table.add_row(
            escape(str(row["name"])),
            escape(command),
            "yes" if row["installed"] else "-",
            *(escape(str(row[column])) for column in FIDELITY),
        )
    console.print(table)
    console.print(
        "usage = token counts per model call, so `tine price` can re-price the run; "
        "flag = the model is known only when the command passes --model."
    )


def add_harnesses_parser(sub: argparse._SubParsersAction) -> None:
    harnesses = sub.add_parser("harnesses", help="List agent CLIs `tine run --harness` can record")
    harnesses.add_argument("--installed", action="store_true", help="Only CLIs found on PATH")
    harnesses.add_argument(
        "--check", nargs="?", const="*", metavar="ADAPTER",
        help="Check importer adapters (built-in and allowlisted entry points)",
    )  # fmt: skip
    harnesses.add_argument(
        "--json", action="store_true", help="Emit a machine-readable JSON object"
    )


def _add_harness_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--harness", choices=sorted(HARNESS_FACTORIES))
    parser.add_argument("--prompt")
    parser.add_argument("--cwd")
    parser.add_argument("--harness-command")
    parser.add_argument("--harness-arg", action="append", default=[])
    parser.add_argument("--harness-login-env", action="store_true")
    parser.add_argument("--harness-env", action="append", default=[])
    parser.add_argument("--harness-timeout", type=float, default=3_600.0, metavar="SECONDS")
    parser.add_argument("--harness-max-output", type=int, default=4_000_000, metavar="CHARS")
    parser.add_argument("--harness-max-events", type=int, default=10_000, metavar="N")
    parser.add_argument("--harness-max-line-bytes", type=int, default=1_000_000, metavar="BYTES")


__all__ = ["_add_harness_args", "add_harnesses_parser", "cmd_harnesses", "harness_rows"]
