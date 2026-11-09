"""Entire: map runs onto an Entire-hosted repository through its git refs (0.48).

Entire keeps its sessions in the code repository itself, as checkpoint refs
(``refs/entire/checkpoints/<id[-2:]>/<id>``, the layout
:mod:`opentine._entire_export` writes and :mod:`opentine.trace._entire_refs`
reads), and serves whatever is pushed there. So the Entire integration posts
nothing over HTTP: it writes, in the code checkout,

* one checkpoint per run the commit's attribution names (or each ``--run``),
  redacted exactly as ``tine export --format entire`` redacts it, and
* the ``opentine.forge-check`` record as a git note on the commit under
  :data:`NOTES_REF`,

and prints the ``git push`` that publishes them. No token is involved; the
push uses the repository's own remote credentials, which need only push access
to ``refs/entire/*`` and ``refs/notes/*``.
"""

from __future__ import annotations

from typing import Any

from opentine._forge_check import encode

NOTES_REF = "refs/notes/opentine-forge"


def plan(args: Any, record: dict[str, Any], runs: list[str]) -> list[dict[str, Any]]:
    steps = [{"target": "checkpoint", "method": "git", "path": f"run {run}"} for run in runs]
    steps.append({"target": "note", "method": "git", "path": f"{NOTES_REF} {record['commit']}"})
    return steps


def _checkpoint(code: str, run_id: str) -> dict[str, Any]:
    from pathlib import Path

    from opentine._cli_common import _find_run
    from opentine._entire_export import write_checkpoint
    from opentine._graph_serde import run_from_dict, run_to_dict
    from opentine.core import Run

    path = _find_run(run_id)
    if not path:
        raise KeyError(f"run not found: {run_id[:40]}")
    raw = Run.load(path)
    run = run_from_dict(run_to_dict(raw, redact=True), type(raw))
    return write_checkpoint(Path(code), run)


def publish(code: str, record: dict[str, Any], runs: list[str]) -> list[dict[str, Any]]:
    from opentine._git_link import IDENTITY_ENV, git

    rows: list[dict[str, Any]] = []
    refs: list[str] = []
    for run_id in runs:
        written = _checkpoint(code, run_id)
        ref = written.get("ref")
        if isinstance(ref, str):
            refs.append(ref)
        rows.append({"target": "checkpoint", "state": "written", "id": ref})
    git(
        code,
        "notes",
        f"--ref={NOTES_REF}",
        "add",
        "-f",
        "-F",
        "-",
        record["commit"],
        stdin=encode(record),
        keep_env=IDENTITY_ENV,
    )
    rows.append({"target": "note", "state": "written", "id": NOTES_REF})
    return rows


def push_command(rows: list[dict[str, Any]]) -> str:
    refs = [row["id"] for row in rows if isinstance(row.get("id"), str)]
    return "git push origin " + " ".join(f"{ref}:{ref}" for ref in refs)


__all__ = ["NOTES_REF", "plan", "publish", "push_command"]
