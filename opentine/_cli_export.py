"""``tine export``: ship a recorded run into the OpenTelemetry ecosystem.

``tine import`` reads a foreign agent trace into OpenTine; this is the other
direction, and the same converter runs it. The document is built by
:func:`opentine.trace.exporters.to_otel_genai_document`, the exact inverse of
the ``otel-json`` importer, so a run exported here and imported back is the run
that was exported — a round trip this command's tests assert rather than assume.

Export is read-only over provenance. It loads a run through ``Run.load``, the
public loader every release since 0.3.0 exposes, writes nothing back to the
artifact, and introduces no artifact or repository format version. The lossy
edges of the mapping itself are documented once, in
:mod:`opentine.trace.exporters`, and are not restated here.

Destinations
------------
``--format otel-json``  (the default) writes the OTLP/JSON document — one
                        ``resourceSpans`` envelope — to stdout, or to
                        ``--output PATH``, which refuses an existing file
                        without ``--force``. Stdout, the written file, and the
                        OTLP body below are all spelled by the CLI's one JSON
                        serializer (``_cli_json.serialize``), so the document a
                        collector receives is the document a file gets, and both
                        stay pipeable and diffable.
``--format otlp``       POSTs that same document to an OTLP/HTTP collector.

``--endpoint URL`` names the collector and implies ``--format otlp``; with
``--format otlp`` and no ``--endpoint`` the endpoint comes from
``OTEL_EXPORTER_OTLP_ENDPOINT``, the variable every OTel SDK already reads.
``/v1/traces`` is appended to it unless it already ends there, which is the
OTLP/HTTP base-endpoint convention. The receipt names the URL, the span count,
and the HTTP status, and is printed only for a collector that accepted the
spans: a connection failure or a non-2xx reply is a refusal that exits 1, never
a silently dropped export.

A cleartext push is refused unless the endpoint is a loopback IP (127.0.0.1/::1)
or ``--allow-insecure`` says otherwise — a run carries prompts and completions, so
it is exactly as sensitive as the repository objects the v3 transport verbs
guard with the same rule, through the same check and the same flag name.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import httpx

from opentine._canon import atomic_write_text
from opentine._cli_common import BRAND, _find_run, _terminal, console
from opentine._cli_flags import _require_output_slot, refuse_unhonoured
from opentine._cli_json import emit, serialize
from opentine._cli_text import without_userinfo as _without_userinfo
from opentine.core import Run
from opentine.redaction import redact_value
from opentine.repository._http import require_secure_remote
from opentine.trace._otlp_push import TRACES_PATH, post, traces_url
from opentine.trace.exporters import to_otel_genai_document

__all__ = ["EXPORT_FORMATS", "TRACES_PATH", "add_export_parser", "cmd_export"]

EXPORT_FORMATS = ("otel-json", "otlp")
ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"
DEFAULT_SERVICE_NAME = "opentine"


def add_export_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("export", help="Export a run as OpenTelemetry GenAI spans")
    parser.add_argument("run_id", help="Run to export: a .tine file, or an id under .tine_runs")
    parser.add_argument("--format", choices=EXPORT_FORMATS, default="otel-json")
    parser.add_argument(
        "--output", metavar="PATH", help="Write the OTLP/JSON document here instead of stdout"
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace an existing --output destination"
    )
    parser.add_argument(
        "--endpoint",
        metavar="URL",
        help=f"OTLP/HTTP collector to POST to; implies --format otlp (default ${ENDPOINT_ENV})",
    )
    parser.add_argument(
        "--service-name",
        metavar="NAME",
        default=DEFAULT_SERVICE_NAME,
        help="resource service.name carried by the exported spans",
    )
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="Permit a cleartext http:// endpoint (a loopback IP like 127.0.0.1 needs no opt-in)",
    )
    return parser


def _endpoint(args: argparse.Namespace) -> str | None:
    """The collector to push to, or ``None`` for a document on stdout/``--output``.

    ``--endpoint`` implies ``--format otlp``: argparse cannot tell an explicit
    ``--format otel-json`` from the default, so the flag that names a
    destination is the one that decides, and the help text says so.
    """
    endpoint = (args.endpoint or "").strip()
    if not endpoint and args.format == "otlp":
        endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
        if not endpoint:
            console.print(
                "[red]--format otlp needs a collector: pass --endpoint URL "
                f"or set {ENDPOINT_ENV}.[/]"
            )
            raise SystemExit(1)
    return endpoint or None


def _refuse_unusable_flags(args: argparse.Namespace, endpoint: str | None) -> None:
    """Refuse a flag this destination cannot honour instead of dropping it."""
    if endpoint is not None:
        refuse_unhonoured(
            args,
            ("output", "force"),
            mode="with an OTLP push",
            hint="The document goes to the collector; export without --endpoint to write a file.",
        )
        return
    refuse_unhonoured(
        args,
        ("allow_insecure",),
        mode="without an OTLP push",
        hint="It relaxes the transport check on --endpoint; a written document has no transport.",
    )
    if not args.output:
        refuse_unhonoured(
            args,
            ("force",),
            mode="without --output",
            hint="--force replaces an existing document; stdout has nothing to replace.",
        )


def _spans(document: dict[str, Any]) -> list[Any]:
    """The spans the exporter put in its single resource/scope envelope."""
    resource = document["resourceSpans"][0]
    return resource["scopeSpans"][0]["spans"]


def _write(document: dict[str, Any], output: Path | None) -> None:
    if output is None:
        # The CLI's one JSON writer: no Rich wrapping or markup on machine output.
        emit(document)
        return
    # Atomic replace, like every other artifact writer: a symlink at the
    # destination is replaced, never written through.
    atomic_write_text(output, serialize(document) + "\n")
    console.print(
        f"[{BRAND}]# Exported[/] {len(_spans(document))} span(s) [{BRAND}]to[/] {_terminal(output)}"
    )


def _shown(url: str) -> str:
    return _terminal(_without_userinfo(url))  # never print a URL's credentials


def _push(document: dict[str, Any], endpoint: str, allow_insecure: bool) -> None:
    url = traces_url(endpoint)
    try:
        require_secure_remote(url, allow_insecure)
    except ValueError as exc:
        console.print(
            f"[red]Refusing to push run content in cleartext to {_shown(url)}: "
            "a run carries prompts and completions. Use https, or --allow-insecure.[/]"
        )
        raise SystemExit(1) from exc
    try:
        status, detail = post(url, serialize(document, indent=None).encode("utf-8"))
    except (httpx.HTTPError, httpx.InvalidURL) as exc:  # InvalidURL is no HTTPError
        console.print(f"[red]OTLP export failed:[/] {_shown(url)} is unreachable: {_terminal(exc)}")
        raise SystemExit(1) from exc
    if not 200 <= status < 300:
        suffix = f": {_terminal(detail)}" if detail else ""
        console.print(f"[red]OTLP export rejected:[/] {_shown(url)} returned HTTP {status}{suffix}")
        raise SystemExit(1)
    console.print(
        f"[{BRAND}]# Exported[/] {len(_spans(document))} span(s) [{BRAND}]to[/] "
        f"{_shown(url)} [{BRAND}]HTTP[/] {status}"
    )


def cmd_export(args: argparse.Namespace) -> None:
    endpoint = _endpoint(args)
    _refuse_unusable_flags(args, endpoint)
    output = Path(args.output) if args.output else None
    if output is not None:
        _require_output_slot(output, args.force)
    path = _find_run(args.run_id)
    if not path:
        console.print(f"[red]Run not found: {_terminal(args.run_id)}[/]")
        raise SystemExit(1)
    try:
        run = Run.load(path)
        # Scrubbed again on the way out: a .tine written before 0.9.1 still holds
        # the prose secrets (tokens, PEM keys, URL passwords) its writer kept.
        document = redact_value(to_otel_genai_document(run, service_name=args.service_name))
        # The write and the push are inside the same guard as the conversion:
        # ``serialize`` refuses a document it cannot render faithfully (nesting
        # past the format bound, or a cycle) rather than writing a truncation
        # marker, and that refusal has to exit 1 with a message like any other.
        if endpoint is None:
            _write(document, output)
        else:
            _push(document, endpoint, args.allow_insecure)
    # KernelError subclasses ValueError, so a refusing artifact reads as a
    # refusal here rather than as an interpreter traceback.
    except (OSError, RecursionError, TypeError, ValueError) as exc:
        console.print(f"[red]Export failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
