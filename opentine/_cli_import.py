"""``tine import``: materialize a foreign agent trace as an OpenTine run.

A thin shell over :mod:`opentine.trace.importers`: it reads ``SOURCE`` (a file,
or ``-`` for stdin), hands it to the importer ``--format`` names, and records
the events with :meth:`Recorder.import_events`. An imported run is ordinary.

Formats
-------
``otel-json``      an OTLP/JSON export (``resourceSpans``…, one or one per line),
                   a ``{"spans": [...]}`` wrapper, or one span object.
``otel-spans``     a JSON array of OTel GenAI spans, or one span per line.
``jsonl``          OpenTine ``TraceEvent`` records, one JSON object per line.
``langchain`` ``llamaindex`` ``autogen`` ``crewai`` ``openai-agents``
                   serialized framework log records, as a JSON array or JSONL.
``otel-logs``      OTLP/JSON logs (Claude Code, Codex and Gemini CLI events).
``claude-code-transcript`` ``codex-session`` ``gemini-session`` ``qwen-session``
``atif`` ``opencode-session`` an agent's session log (opencode.db[::id]);
                   ``--from-default-location`` lists them; ``latest`` or an id prefix.
``auto``           (the default) recognize the source by its shape.

Persistence — at least one target is required
---------------------------------------------
``--save PATH``    write the imported run as a portable v2 ``.tine`` artifact
                   (refusing an existing destination unless ``--force``).
``--repo PATH``    record it into an existing v3 repository, advancing
                   ``--ref`` (default ``heads/main``).

Both may be given. With ``--save`` alone the run is built in a throwaway
repository that is deleted afterwards, so importing never leaves a repository
behind that the user did not ask for. Environment and code capture is off: the
provenance of an imported trace belongs to the machine that produced it, not to
the one running ``tine import``.

Pricing
-------
``--price``        run the post-hoc pricing pass (:mod:`opentine._pricing_pass`)
                   over the parsed events before any of them is written, so the
                   model steps land carrying the catalog's cost and billing
                   record. A step no rate card covers is recorded ``unknown``,
                   not ``$0.00``, and a cost the source itself reported is kept.
                   Without the flag import behaviour is unchanged.

With ``--json`` the human lines are replaced by one object naming the run and
both targets (schema: :mod:`opentine._cli_json_surface`). Reading and routing
``SOURCE`` lives in :mod:`opentine._cli_import_read`.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_flags import _require_output_slot, refuse_unhonoured
from opentine._cli_import_fleet import add_extra_args, check_fleet, import_fleet
from opentine._cli_import_read import STDIN as STDIN  # re-exported: one spelling of "-"
from opentine._cli_import_read import detect_and_read
from opentine._cli_import_read import read_events as read_events  # re-exported entry point
from opentine._cli_import_sessions import print_sessions, resolve
from opentine._cli_json_surface import emit_import
from opentine._import_billing import distrust_source_billing, mark_unpriced
from opentine._import_write import record
from opentine._pricing_pass import price_events
from opentine.core import Run
from opentine.repo import Repo
from opentine.trace._import_detect import TRANSCRIPT_FORMATS
from opentine.trace._transcript_common import capture_marker
from opentine.trace.schema import TraceEvent

FRAMEWORK_FORMATS = ("langchain", "llamaindex", "autogen", "crewai", "openai-agents")
IMPORT_FORMATS = (
    "auto",
    "otel-json",
    "otel-logs",
    "otel-spans",
    "jsonl",
    *TRANSCRIPT_FORMATS,
    *FRAMEWORK_FORMATS,
)
DEFAULT_REF = "heads/main"


def add_import_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("import", help="Import a foreign agent trace as a run")
    parser.add_argument(
        "source",
        nargs="?",
        help="Trace file to read, - for stdin, or with --from-default-location "
        "'latest' or a session-id prefix",
    )
    parser.add_argument("--format", choices=IMPORT_FORMATS, default="auto")
    parser.add_argument(
        "--from-default-location",
        action="store_true",
        help="Find SOURCE among the agent CLIs' own session logs; without SOURCE, list them",
    )
    parser.add_argument(
        "--save", metavar="PATH", help="Write the imported run as a portable .tine artifact"
    )
    parser.add_argument(
        "--repo", metavar="PATH", help="Record the imported run into this v3 repository"
    )
    parser.add_argument(
        "--ref",
        metavar="REF",
        default=None,
        help=f"Ref the --repo import advances (default {DEFAULT_REF})",
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace an existing --save destination"
    )
    add_extra_args(parser)  # --fleet, --adapter
    parser.add_argument(
        "--price",
        action="store_true",
        help="Price the imported model steps from the catalog before the run is written",
    )
    return parser


def _refuse_unusable_flags(args: argparse.Namespace) -> None:
    """Refuse a flag this invocation cannot honour instead of dropping it."""
    check_fleet(args)
    if not args.save and not args.repo:
        console.print(
            "[red]Nothing to write: pass --save PATH for a portable .tine artifact, "
            "--repo PATH to record into a v3 repository, or both.[/]"
        )
        raise SystemExit(1)
    if not args.repo and args.ref is not None:
        # Spelled out rather than routed through refuse_unhonoured: --ref carries a
        # different parser default on every other subcommand that declares it, and
        # FLAG_DEFAULTS holds one default per dest for the whole CLI.
        console.print(
            "[red]--ref has no effect without --repo. A --save artifact is a file, not a ref.[/]"
        )
        raise SystemExit(1)
    if not args.save:
        refuse_unhonoured(
            args,
            ("force",),
            mode="without --save",
            hint="--force replaces an existing artifact; a repository import advances a ref.",
        )


def _persist(repo: Repo, events: list[TraceEvent], ref, output, capture, source_format) -> Run:
    """Record the events and read the run back, before any scratch repo is gone."""
    run = repo.load_run(record(repo, events, ref, capture, source_format))
    if output is not None:
        run.save(output)
    return run


def _refused(exc: Exception) -> SystemExit:
    """Report an unreadable source or a refusing repository as a message.

    KernelError subclasses ValueError, so every repository, importer, and JSON
    failure reads as a refusal rather than an interpreter traceback.
    """
    console.print(f"[red]Import failed:[/] {_terminal(exc)}")
    return SystemExit(1)


def cmd_import(args: argparse.Namespace) -> None:
    if args.from_default_location and args.source is None:
        print_sessions(args.format)
        return
    if args.source is None:
        console.print(
            "[red]Pass a SOURCE to import, or --from-default-location to list sessions.[/]"
        )
        raise SystemExit(1)
    if args.from_default_location and not Path(args.source).exists():
        try:
            args.source = str(resolve(args.source, args.format).path)
        except ValueError as exc:
            raise _refused(exc) from exc
    _refuse_unusable_flags(args)
    output = Path(args.save) if args.save else None
    if output is not None:
        _require_output_slot(output, args.force)
    ref = args.ref or DEFAULT_REF
    repo_path = None
    capture = None
    try:
        source_format, events = detect_and_read(args.source, args.format, args.adapter)
    except (OSError, RecursionError, ValueError) as exc:
        raise _refused(exc) from exc
    if not events:
        # Distinct from a read failure: the source was read fine and held nothing
        # this importer recognizes, which almost always means the wrong --format.
        console.print(
            f"[red]No trace events found in {_terminal(args.source)} "
            f"as --format {_terminal(source_format)}.[/]"
        )
        raise SystemExit(1)
    if source_format in TRANSCRIPT_FORMATS or args.adapter:
        capture = capture_marker(source_format)
    events = distrust_source_billing(events)  # an import never claims a free call
    if getattr(args, "price", False):
        # Before the first blob is written, on records no store has seen: the
        # price lands as part of the initial recording of these steps, never as
        # a rewrite of a stored, content-addressed event.
        try:
            events = price_events(events)
        except (OSError, ValueError) as exc:
            raise _refused(exc) from exc
    events = mark_unpriced(events)
    try:
        if args.repo:
            repo = Repo.open(args.repo)
            repo_path = repo.path
            if getattr(args, "fleet", False):
                return import_fleet(args, repo, events, ref, capture, source_format)
            run = _persist(repo, events, ref, output, capture, source_format)
        else:
            with tempfile.TemporaryDirectory(prefix="tine-import-") as scratch:
                run = _persist(
                    Repo.init(Path(scratch) / "import"), events, ref, output, capture, source_format
                )
    except (OSError, RecursionError, ValueError) as exc:
        raise _refused(exc) from exc
    if getattr(args, "json", False):
        emit_import(
            run,
            source=args.source,
            source_format=source_format,
            events_imported=len(events),
            saved_to=output,
            repo=repo_path,
            # --ref is refused without --repo, so a --save-only import advanced none.
            ref=ref if repo_path is not None else None,
        )
        return
    console.print(
        f"[{BRAND}]# Imported[/] {len(events)} event(s) from "
        f"{_terminal(args.source)} [{BRAND}]as[/] {_terminal(run.id)}"
    )
    if output is not None:
        console.print(f"[{BRAND}]Saved:[/] {_terminal(output)}")
    if repo_path is not None:
        console.print(f"[{BRAND}]Repo:[/] {_terminal(repo_path)} ref={_terminal(ref)}")
