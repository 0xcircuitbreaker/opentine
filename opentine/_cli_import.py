"""``tine import``: materialize a foreign agent trace as an OpenTine run.

The importers in :mod:`opentine.trace.importers` were reachable only from
Python. This command is a thin shell over them: it reads ``SOURCE`` (a file, or
``-`` for stdin), hands the bytes to the importer named by ``--format``, and
records the resulting :class:`~opentine.trace.schema.TraceEvent` list with
:meth:`Recorder.import_events`. No importer is reimplemented here, and no
artifact or repository format changes: an imported run is an ordinary run.

Formats
-------
``otel-json``      one complete OTLP/JSON export document (``resourceSpans``…),
                   or a ``{"spans": [...]}`` wrapper, or one span object.
``otel-spans``     a JSON array of OTel GenAI span objects, or one span per
                   line (JSONL).
``jsonl``          OpenTine ``TraceEvent`` records, one JSON object per line.
``langchain`` ``llamaindex`` ``autogen`` ``crewai`` ``openai-agents``
                   serialized framework log records, as a JSON array or JSONL.

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
both targets; its schema is documented in :mod:`opentine._cli_json_surface`.

Reading and routing ``SOURCE`` lives in :mod:`opentine._cli_import_read`, whose
``read_events`` is re-exported here as the entry point it has always been.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_flags import _require_output_slot, refuse_unhonoured
from opentine._cli_import_read import STDIN as STDIN  # re-exported: one spelling of "-"
from opentine._cli_import_read import read_events as read_events  # re-exported entry point
from opentine._cli_json_surface import emit_import
from opentine._pricing_pass import price_events
from opentine.core import Run
from opentine.repo import Repo
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

FRAMEWORK_FORMATS = ("langchain", "llamaindex", "autogen", "crewai", "openai-agents")
IMPORT_FORMATS = ("otel-json", "otel-spans", "jsonl", *FRAMEWORK_FORMATS)
DEFAULT_REF = "heads/main"


def add_import_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("import", help="Import a foreign agent trace as a run")
    parser.add_argument("source", help="Trace file to read, or - for stdin")
    parser.add_argument("--format", choices=IMPORT_FORMATS, required=True)
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
    parser.add_argument(
        "--price",
        action="store_true",
        help="Price the imported model steps from the catalog before the run is written",
    )
    return parser


def _refuse_unusable_flags(args: argparse.Namespace) -> None:
    """Refuse a flag this invocation cannot honour instead of dropping it."""
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


def _record(repo: Repo, events: list[TraceEvent], ref: str) -> str:
    recorder = Recorder.start(repo, ref=ref, capture=False)
    recorder.import_events(events)
    return recorder.finalize()


def _persist(repo: Repo, events: list[TraceEvent], ref: str, output: Path | None) -> Run:
    """Record the events and read the run back, before any scratch repo is gone."""
    run = repo.load_run(_record(repo, events, ref))
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
    _refuse_unusable_flags(args)
    output = Path(args.save) if args.save else None
    if output is not None:
        _require_output_slot(output, args.force)
    ref = args.ref or DEFAULT_REF
    repo_path = None
    try:
        events = read_events(args.source, args.format)
    except (OSError, RecursionError, ValueError) as exc:
        raise _refused(exc) from exc
    if not events:
        # Distinct from a read failure: the source was read fine and held nothing
        # this importer recognizes, which almost always means the wrong --format.
        console.print(
            f"[red]No trace events found in {_terminal(args.source)} "
            f"as --format {_terminal(args.format)}.[/]"
        )
        raise SystemExit(1)
    if getattr(args, "price", False):
        # Before the first blob is written, on records no store has seen: the
        # price lands as part of the initial recording of these steps, never as
        # a rewrite of a stored, content-addressed event.
        try:
            events = price_events(events)
        except (OSError, ValueError) as exc:
            raise _refused(exc) from exc
    try:
        if args.repo:
            repo = Repo.open(args.repo)
            repo_path = repo.path
            run = _persist(repo, events, ref, output)
        else:
            with tempfile.TemporaryDirectory(prefix="tine-import-") as scratch:
                run = _persist(Repo.init(Path(scratch) / "import"), events, ref, output)
    except (OSError, RecursionError, ValueError) as exc:
        raise _refused(exc) from exc
    if getattr(args, "json", False):
        emit_import(
            run,
            source=args.source,
            source_format=args.format,
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
