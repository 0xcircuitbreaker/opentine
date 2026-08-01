"""Stable machine-readable JSON for ``tine import`` and ``tine tag``.

The contract is the one documented in :mod:`opentine._cli_json`, extended by
reference rather than restated: one JSON object on stdout and nothing else,
keys sorted, every value through ``json_safe``, a ``command`` field naming the
schema, and fields added but never renamed or removed within a major version.
Like :mod:`opentine._cli_json_flow` this module writes through that module's
single ``emit``, so there is still exactly one JSON writer in the CLI.

It exists as a third module only because the schema prose is the schema: the
two docstrings there are at the 250-line module gate, and a payload builder
whose contract cannot be written down next to it is a builder that drifts.

The same failure rule applies. A source that will not read, a ``--format`` that
recognizes nothing in it, a repository that refuses the write, or a run ``tag``
cannot find prints a human message and exits non-zero — no object is written,
because no import and no lookup completed. Every object below describes work
that finished.

``tine import SOURCE --format FMT --json``
    ``command``          ``"import"``
    ``format``           str — the ``--format`` importer that read the source
    ``source``           str — the source as given, ``"-"`` for stdin
    ``run``              object — ``id`` (full run id), ``short_id``,
                         ``step_count`` (steps in the materialized run)
    ``saved_to``         str or null — the ``--save`` artifact, null without it
    ``repo``             str or null — the repository that recorded the run, as
                         it resolved the ``--repo`` path; null without it
    ``ref``              str or null — the ref the repository import advanced;
                         null without ``--repo``, because ``--ref`` names
                         nothing a ``--save`` artifact has
    ``events_imported``  int — trace events the importer produced, which is what
                         the human rendering counts and **may exceed**
                         ``run.step_count``: an importer may fold several events
                         into one step

``tine tag RUN --json``
    Covers ``--list`` *and* the implicit list default: ``tag RUN`` with neither
    ``--add`` nor ``--remove`` lists. The mutating path is not a listing and
    refuses ``--json`` rather than dropping it.

    ``command``   ``"tag"``
    ``run_id``    str — full run id
    ``short_id``  str
    ``path``      str — the file or repository the run was read from
    ``tags``      array of str — as the artifact stores them, normalized and
                  sorted; empty when the run carries none
    ``count``     int — number of entries in ``tags``
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine._cli_json import emit
from opentine.core import Run, short_id


def emit_import(
    run: Run,
    *,
    source: str,
    source_format: str,
    events_imported: int,
    saved_to: Path | str | None,
    repo: Path | str | None,
    ref: str | None,
) -> None:
    """Write the one object describing a completed import."""
    payload: dict[str, Any] = {
        "command": "import",
        "format": source_format,
        "source": source,
        "run": {
            "id": run.id,
            "short_id": short_id(run.id),
            "step_count": len(run.steps),
        },
        "saved_to": None if saved_to is None else str(saved_to),
        "repo": None if repo is None else str(repo),
        "ref": ref,
        "events_imported": int(events_imported),
    }
    emit(payload)


def emit_tags(run: Run, path: Path | str) -> None:
    """Write the one object describing the tags a run carries."""
    tags = list(run.tags)
    emit(
        {
            "command": "tag",
            "run_id": run.id,
            "short_id": short_id(run.id),
            "path": str(path),
            "tags": tags,
            "count": len(tags),
        }
    )
