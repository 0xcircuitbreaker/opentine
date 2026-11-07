"""``tine explain RUN [--narrative] [--no-store] [--repo PATH] [--json]``.

In a v3 repository (``--repo``, or one in the working directory) the summary
is stored as an annotation on the run, under ``metadata["opentine.explain"]``,
through the same annotation chain ``tag`` and ``bisect`` write. Storing the
same summary twice writes nothing new (the annotation writer deduplicates). A
legacy ``.tine`` run is explained but not stored: its file may be signed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine import _explain
from opentine._cli_errors import fail
from opentine._cli_json import emit


def add_explain_parser(sub: Any) -> None:
    explain = sub.add_parser(
        "explain", help="A deterministic offline summary of a run, stored as an annotation"
    )
    explain.add_argument("run_id", metavar="RUN", help="Run object id, ref, or legacy run/path")
    explain.add_argument(
        "--narrative",
        action="store_true",
        help=f"Add a labelled narrative from the local model in ${_explain.NARRATIVE_ENV}",
    )
    explain.add_argument("--no-store", action="store_true", help="Do not write the annotation")
    explain.add_argument("--repo", metavar="PATH", help="v3 repository (default: one in the cwd)")
    explain.add_argument("--json", action="store_true", help="Emit a machine-readable JSON object")


def _v3_target(args: argparse.Namespace) -> tuple[Any, str] | None:
    repo_path = args.repo or ("." if (Path(".tine") / "config.json").is_file() else None)
    if repo_path is None:
        return None
    from opentine.repository import Repo

    repo = Repo.open(repo_path)
    name = args.run_id
    if name.startswith("run:"):
        return repo, name
    for ref in (name, f"heads/{name}", f"tags/{name}"):
        try:
            oid = repo.read_ref(ref)
        except (ValueError, OSError):
            oid = None
        if oid:
            return repo, oid
    fail(f"no run named {name[:80]!r} in this repository", 2)
    raise AssertionError  # unreachable


def _store(repo: Any, oid: str, summary: dict, story: dict | None) -> str | None:
    from opentine.repository._annotations import load_run_annotation, write_run_annotation

    metadata, tags = load_run_annotation(repo, oid)
    metadata = {**metadata, _explain.ANNOTATION_KEY: summary}
    if story is not None:
        metadata[_explain.NARRATIVE_KEY] = story
    return write_run_annotation(repo, oid, metadata, tags)


def cmd_explain(args: argparse.Namespace) -> None:
    spec = None
    if args.narrative:
        try:
            spec = _explain.narrative_model_spec()
        except _explain.NarrativeUnavailable as exc:
            fail(str(exc), 2)
    target = _v3_target(args)
    if target is not None:
        repo, oid = target
        run = repo.load_run(oid)
    else:
        from opentine._cli_execute import _loaded_run

        repo, oid = None, ""
        _, run = _loaded_run(args.run_id)
    summary = _explain.summarize(run)
    story = None
    if spec is not None:
        try:
            story = _explain.narrative(summary, spec)
        except Exception as exc:  # noqa: BLE001 - a local server down is a clean refusal
            fail(f"--narrative: the local model {spec!r} failed: {type(exc).__name__}", 1)
    annotation = None
    if repo is not None and not args.no_store:
        annotation = _store(repo, oid, summary, story)
    if args.json:
        payload: dict[str, Any] = {"command": "explain", "run": oid or run.id}
        payload.update(digest=_explain.digest(summary), summary=summary)
        payload.update(stored=annotation is not None, annotation=annotation)
        payload["narrative"] = story
        emit(payload)
        return
    print(_explain.render_text(summary), end="")
    if story is not None:
        print(f"\nNarrative [{story['label']}; {story['model']}]:\n{story['text']}")


COMMANDS = {"explain": cmd_explain}

__all__ = ["COMMANDS", "add_explain_parser", "cmd_explain"]
