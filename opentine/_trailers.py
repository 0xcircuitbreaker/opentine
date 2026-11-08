"""The 0.45 commit trailer grammar: ``Tine-Run`` and ``Tine-Project``.

::

    Tine-Run: <run-oid>[ <project_id>]     (repeatable)
    Tine-Project: <project_id>             (at most once)

A ``Tine-Run`` line names one run, optionally with the project it belongs to.
``Tine-Project`` sets the project for every ``Tine-Run`` line that names none.
:func:`parse` returns the *link set*: ``(run, project)`` pairs in message order,
de-duplicated, ``project`` empty when neither line gives one. The web parser
reads the same lines and must return the same set (vectors:
``tests/data/trailer_vectors.json``).

Strict parsing rejects a message with two ``Tine-Project`` lines, a malformed
run id or project id, or extra words after a value. ``tine git log`` and the
hook keep reading leniently through :func:`opentine._git_link.run_ids`, which
skips what it cannot parse, so an old or hand-written message never fails a
commit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from opentine._git_link import MAX_RUNS_PER_COMMIT, RUN_ID

RUN_KEY = "Tine-Run"
PROJECT_KEY = "Tine-Project"
#: A project id: lower-case slug, the shape the web uses for project URLs.
PROJECT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
OID = re.compile(r"^run:sha256:[0-9a-f]{64}$")
_LINE = re.compile(r"^(Tine-Run|Tine-Project):(.*)$", re.MULTILINE | re.IGNORECASE)


class TrailerError(ValueError):
    """A ``Tine-Run`` / ``Tine-Project`` trailer breaks the grammar."""


@dataclass(frozen=True)
class Link:
    run: str
    project: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"run": self.run, "project": self.project}


def _project(value: str) -> str:
    if not PROJECT_ID.fullmatch(value):
        raise TrailerError(f"malformed project id: {value[:80]!r}")
    return value


def _run(value: str) -> str:
    # A legacy run id may contain colons, so an object-id prefix must be a whole oid.
    oid_like = value.lower().startswith("run:")
    if not RUN_ID.fullmatch(value) or oid_like and not OID.fullmatch(value):
        raise TrailerError(f"malformed run id: {value[:80]!r}")
    return value


def parse(message: str) -> list[Link]:
    """The link set *message* names; raise :class:`TrailerError` on bad grammar."""
    runs: list[tuple[str, str]] = []
    project = ""
    seen_project = False
    for key, rest in _LINE.findall(message):
        words = rest.split()
        if key.lower() == PROJECT_KEY.lower():  # git trailer keys ignore case
            if seen_project:
                raise TrailerError(f"{PROJECT_KEY} may appear at most once")
            if len(words) != 1:
                raise TrailerError(f"{PROJECT_KEY} takes exactly one project id")
            project, seen_project = _project(words[0]), True
            continue
        if not 1 <= len(words) <= 2:
            raise TrailerError(f"{RUN_KEY} takes a run id and an optional project id")
        runs.append((_run(words[0]), _project(words[1]) if len(words) == 2 else ""))
    links = [Link(run, own or project) for run, own in runs]
    return list(dict.fromkeys(links))[:MAX_RUNS_PER_COMMIT]


def format_links(links: list[Link], project: str = "") -> list[str]:
    """Trailer lines for *links*; one ``Tine-Project`` line when *project* is given."""
    lines = []
    for link in links:
        own = "" if link.project in ("", project) else f" {_project(link.project)}"
        lines.append(f"{RUN_KEY}: {_run(link.run)}{own}")
    if project:
        lines.append(f"{PROJECT_KEY}: {_project(project)}")
    return lines


__all__ = ["Link", "PROJECT_ID", "TrailerError", "format_links", "parse"]
