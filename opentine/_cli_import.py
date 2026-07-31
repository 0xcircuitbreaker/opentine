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
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_flags import refuse_unhonoured
from opentine._cli_flow import _require_output_slot
from opentine.repo import Repo
from opentine.trace.importers import (
    MAX_TRACE_IMPORT_BYTES,
    framework_events,
    jsonl_events,
    otel_genai_events,
)
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

FRAMEWORK_FORMATS = ("langchain", "llamaindex", "autogen", "crewai", "openai-agents")
IMPORT_FORMATS = ("otel-json", "otel-spans", "jsonl", *FRAMEWORK_FORMATS)
DEFAULT_REF = "heads/main"
STDIN = "-"


def add_import_parser(subparsers: argparse._SubParsersAction) -> None:
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


def _read_text(source: str) -> str:
    """Read the whole source, refusing more than one importer payload's worth."""
    if source == STDIN:
        # .buffer for a real pipe; a text stream (a redirect, or a host that
        # substituted stdin) is read as text instead of raising AttributeError.
        data = getattr(sys.stdin, "buffer", sys.stdin).read(MAX_TRACE_IMPORT_BYTES + 1)
    else:
        path = Path(source)
        if path.stat().st_size > MAX_TRACE_IMPORT_BYTES:
            raise ValueError("trace import exceeds aggregate payload limit")
        data = path.read_bytes()
    if len(data) > MAX_TRACE_IMPORT_BYTES:
        raise ValueError("trace import exceeds aggregate payload limit")
    return data.decode("utf-8", "replace") if isinstance(data, bytes) else data


def _records(text: str) -> list:
    """Decode a JSON array, a single JSON object, or one JSON object per line.

    Whole-document parsing is tried first, so a pretty-printed array spanning
    many lines is not mistaken for JSONL; JSONL only reaches the per-line path
    because the concatenation is not itself valid JSON.
    """
    try:
        decoded = json.loads(text)
    except ValueError:
        pass
    else:
        return decoded if isinstance(decoded, list) else [decoded]
    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        # The decoder counts lines within the fragment it was handed, so on its
        # own it reports "line 1" for every bad record in the file.
        except ValueError as exc:
            raise ValueError(f"line {number} is not valid JSON: {exc}") from exc
    return records


def read_events(source: str, source_format: str) -> list[TraceEvent]:
    """Route *source* to the importer named by *source_format*."""
    if source_format == "jsonl":
        # The JSONL importer does its own bounded, streaming read of a path.
        return jsonl_events(sys.stdin if source == STDIN else source)
    text = _read_text(source)
    if source_format == "otel-json":
        return otel_genai_events(json.loads(text))
    if source_format == "otel-spans":
        return otel_genai_events(_records(text))
    return framework_events(_records(text), source_format)


def _record(repo: Repo, events: list[TraceEvent], ref: str) -> str:
    recorder = Recorder.start(repo, ref=ref, capture=False)
    recorder.import_events(events)
    return recorder.finalize()


def _persist(repo: Repo, events: list[TraceEvent], ref: str, output: Path | None) -> str:
    run_id = _record(repo, events, ref)
    if output is not None:
        repo.load_run(run_id).save(output)
    return run_id


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
    try:
        if args.repo:
            repo = Repo.open(args.repo)
            repo_path = repo.path
            run_id = _persist(repo, events, ref, output)
        else:
            with tempfile.TemporaryDirectory(prefix="tine-import-") as scratch:
                run_id = _persist(Repo.init(Path(scratch) / "import"), events, ref, output)
    except (OSError, RecursionError, ValueError) as exc:
        raise _refused(exc) from exc
    console.print(
        f"[{BRAND}]# Imported[/] {len(events)} event(s) from "
        f"{_terminal(args.source)} [{BRAND}]as[/] {_terminal(run_id)}"
    )
    if output is not None:
        console.print(f"[{BRAND}]Saved:[/] {_terminal(output)}")
    if repo_path is not None:
        console.print(f"[{BRAND}]Repo:[/] {_terminal(repo_path)} ref={_terminal(ref)}")
