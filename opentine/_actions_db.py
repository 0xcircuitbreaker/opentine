"""The action index: a rebuildable SQLite sidecar of every run's actions.

It is a cache, never an authority. A run file or run object is the source of
truth; the index is rebuilt for any source whose stamp changed and wholesale
when the extractor (``ACTIONS_SCHEMA``) or opentine itself changes, so an
incremental sync always equals a fresh build. A database that cannot be read
is discarded and rebuilt. Only redacted action records are stored (see
:mod:`opentine._actions`).
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from opentine import _actions_trust as trust
from opentine._actions import ACTIONS_SCHEMA, Action, extract_actions
from opentine._actions_schema import COLUMNS, SCHEMA
from opentine._version import __version__
from opentine.graph import Run

_STAMP = f"{ACTIONS_SCHEMA}:{__version__}"
_COLUMNS, _SCHEMA = COLUMNS, SCHEMA


@dataclass(frozen=True)
class Source:
    """One run to index: a stable *key*, a *stamp* that changes with it, a loader."""

    key: str
    stamp: str
    load: Callable[[], Run]


@dataclass
class SyncReport:
    indexed: int = 0
    removed: int = 0
    unreadable: int = 0
    truncated_runs: int = 0
    sources: int = 0


def _packed(values: list[str]) -> str:
    """``,a,b,`` so ``LIKE '%,a,%'`` matches one whole list element."""
    return "," + ",".join(value.replace(",", " ") for value in values) + ","


class ActionIndex:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.db = self._connect()

    def _connect(self) -> sqlite3.Connection:
        if str(self.path) == ":memory:":
            db = sqlite3.connect(":memory:")
            db.executescript(_SCHEMA)
            db.execute("INSERT INTO meta VALUES ('stamp', ?)", (_STAMP,))
            return db
        trust.check_location(self.path)
        stamp = trust.keyed_stamp(_STAMP, str(self.path.absolute()))
        try:
            db = trust.connect(self.path)
            row = db.execute("SELECT value FROM meta WHERE key = 'stamp'").fetchone()
        except sqlite3.DatabaseError:
            row = None
            with contextlib.suppress(NameError):
                db.close()
        if row is not None and row[0] == stamp:
            db.executescript(_SCHEMA)
            return db
        # Not an index this machine wrote (absent, damaged, foreign or shipped
        # with a clone): replace the file, never alter it in place.
        with contextlib.suppress(NameError, sqlite3.Error):
            db.close()
        trust.discard(self.path)
        db = trust.connect(self.path)
        db.executescript(_SCHEMA)
        with db:
            db.execute("INSERT OR REPLACE INTO meta VALUES ('stamp', ?)", (stamp,))
        return db

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> ActionIndex:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def sync(self, sources: Iterable[Source]) -> SyncReport:
        wanted = {source.key: source for source in sources}
        known = dict(self.db.execute("SELECT source, stamp FROM sources"))
        report = SyncReport(sources=len(wanted))
        with self.db:
            for key, stamp in known.items():
                if key not in wanted or wanted[key].stamp != stamp:
                    self._drop(key)
                    report.removed += key not in wanted
            for key, source in sorted(wanted.items()):
                if known.get(key) == source.stamp:
                    continue
                self._index(source, report)
        for (count,) in self.db.execute("SELECT count(*) FROM sources WHERE truncated = 1"):
            report.truncated_runs = count
        return report

    def _drop(self, key: str) -> None:
        ids = "SELECT id FROM actions WHERE source = ?"
        self.db.execute(f"DELETE FROM paths WHERE action_id IN ({ids})", (key,))  # noqa: S608
        self.db.execute(f"DELETE FROM hosts WHERE action_id IN ({ids})", (key,))  # noqa: S608
        self.db.execute("DELETE FROM actions WHERE source = ?", (key,))
        self.db.execute("DELETE FROM sources WHERE source = ?", (key,))

    def _index(self, source: Source, report: SyncReport) -> None:
        try:
            run = source.load()
            actions, truncated = extract_actions(run)
        except Exception:
            self.db.execute(
                "INSERT INTO sources (source, stamp, unreadable) VALUES (?, ?, 1)",
                (source.key, source.stamp),
            )
            report.unreadable += 1
            return
        self.db.execute(
            "INSERT INTO sources (source, stamp, run_id, truncated) VALUES (?, ?, ?, ?)",
            (source.key, source.stamp, run.id, int(truncated)),
        )
        for action in actions:
            self._insert(source.key, action)
        report.indexed += 1

    def _insert(self, key: str, action: Action) -> None:
        row = action.to_dict()
        row["verbs"], row["programs"] = _packed(action.verbs), _packed(action.programs)
        values = [row[column] for column in _COLUMNS]
        cursor = self.db.execute(
            f"INSERT INTO actions (source, {', '.join(_COLUMNS)}) "  # noqa: S608
            f"VALUES (?, {', '.join('?' for _ in _COLUMNS)})",
            (key, *[int(value) if isinstance(value, bool) else value for value in values]),
        )
        action_id = cursor.lastrowid
        self.db.executemany(
            "INSERT INTO paths VALUES (?, ?, ?)",
            [(action_id, path, int(path in action.written)) for path in action.paths],
        )
        self.db.executemany(
            "INSERT INTO hosts VALUES (?, ?)", [(action_id, host) for host in action.hosts]
        )

    def rows(
        self, where: str = "", params: tuple = (), *, limit: int | None = None
    ) -> Iterator[Action]:
        """Stored actions, oldest source first, each with its paths and hosts."""
        sql = f"SELECT id, {', '.join(_COLUMNS)} FROM actions {where} ORDER BY source, seq"
        if limit is not None:
            sql, params = f"{sql} LIMIT ?", (*params, int(limit))
        for record in self.db.execute(sql, params).fetchall():
            action_id, values = record[0], dict(zip(_COLUMNS, record[1:], strict=True))
            values["verbs"] = [v for v in values["verbs"].split(",") if v]
            values["programs"] = [v for v in values["programs"].split(",") if v]
            for flag in ("error", "redacted", "clipped"):
                values[flag] = bool(values[flag])
            stored = self.db.execute(
                "SELECT path, written FROM paths WHERE action_id = ? ORDER BY rowid", (action_id,)
            ).fetchall()
            values["paths"] = [path for path, _ in stored]
            values["written"] = [path for path, written in stored if written]
            values["hosts"] = [
                host
                for (host,) in self.db.execute(
                    "SELECT host FROM hosts WHERE action_id = ? ORDER BY rowid", (action_id,)
                )
            ]
            yield Action(**values)

    def edges(self) -> list[tuple[str, str, str]]:
        """Distinct ``(run_id, agent_ref, parent_ref)`` claims, for lineage walks."""
        sql = "SELECT DISTINCT run_id, agent_ref, parent_ref FROM actions"
        return [tuple(row) for row in self.db.execute(sql)]

    def run_ids(self) -> list[str]:
        return [row[0] for row in self.db.execute("SELECT run_id FROM sources WHERE run_id != ''")]

    def source_file(self, run_id: str, runs_dir: Path) -> Path | None:
        """The runs-directory file indexed for *run_id* (legacy sources only)."""
        row = self.db.execute("SELECT source FROM sources WHERE run_id = ?", (run_id,)).fetchone()
        if row is None or "/" in row[0] or "\\" in row[0] or not row[0].endswith(".tine"):
            return None
        return runs_dir / row[0]

    def count(self, where: str = "", params: tuple = ()) -> int:
        return self.db.execute(f"SELECT count(*) FROM actions {where}", params).fetchone()[0]

    def coverage(self) -> dict[str, int]:
        counts = self.db.execute(
            "SELECT count(*), sum(unreadable), sum(truncated) FROM sources"
        ).fetchone()
        return {
            "runs": counts[0] or 0,
            "unreadable_runs": counts[1] or 0,
            "truncated_runs": counts[2] or 0,
        }


__all__ = ["ActionIndex", "Source", "SyncReport"]
