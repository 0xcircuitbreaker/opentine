"""Running one read-only SQL statement against the query index (0.65).

Three layers keep ``tine query`` from changing anything: the file is opened
read-only (``mode=ro``), ``PRAGMA query_only`` is on, and an authorizer allows
only reading -- ``SELECT``, column reads, functions other than
``load_extension``, and recursive CTEs. Writes, ``ATTACH``/``DETACH``, every
``PRAGMA``, schema changes, transactions and ``load_extension`` are refused
with ``query.refused``. One statement per call (sqlite3 refuses more).

The work a statement may do is bounded by a count of virtual-machine steps
(``max_steps`` thousands), not by a clock: the same statement on the same
index stops at the same place on every machine (``query.too-many-steps``).
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
            getattr(sqlite3, "SQLITE_RECURSIVE", 33)}  # fmt: skip
_REFUSED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}
STEP_UNIT = 1000
#: The largest string or blob a statement may build (bounds memory, not time).
MAX_LENGTH = 1_000_000


class QueryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _authorizer(action: int, arg1: Any, arg2: Any, _db: Any, _trigger: Any) -> int:
    if action not in _ALLOWED:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and str(arg2 or arg1 or "").lower() in _REFUSED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def connect_ro(path: Path) -> sqlite3.Connection:
    uri = f"{Path(path).resolve().as_uri()}?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.execute("PRAGMA query_only = ON")
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LENGTH)
    db.set_authorizer(_authorizer)
    return db


def run(path: Path, sql: str, *, limit: int = 1000, max_steps: int = 1_000_000,
        params: tuple = ()) -> dict[str, Any]:  # fmt: skip
    """``{"columns", "rows", "truncated"}``: at most *limit* rows as dicts."""
    if not sql.strip():
        raise QueryError("query.empty", "give one SELECT statement")
    budget = {"left": max_steps}

    def tick() -> int:
        budget["left"] -= 1
        return 1 if budget["left"] < 0 else 0

    with closing(connect_ro(path)) as db:
        db.set_progress_handler(tick, STEP_UNIT)
        try:
            cursor = db.execute(sql, params)
            columns = [d[0] for d in cursor.description or ()]
            fetched = cursor.fetchmany(limit + 1)
        except sqlite3.DatabaseError as exc:
            text = str(exc)
            if budget["left"] < 0 or "interrupted" in text:
                raise QueryError("query.too-many-steps",
                                 f"the statement ran past {max_steps} thousand steps "
                                 "(raise --max-steps)") from exc  # fmt: skip
            if "too big" in text or "too large" in text:
                raise QueryError("query.too-large",
                                 f"a value is over {MAX_LENGTH} bytes") from exc  # fmt: skip
            if "not authorized" in text or "readonly" in text or "query_only" in text:
                raise QueryError("query.refused", f"only reading is allowed ({text})") from exc
            raise QueryError("query.sql", text) from exc
        except sqlite3.Warning as exc:  # e.g. more than one statement
            raise QueryError("query.sql", str(exc)) from exc
        except sqlite3.ProgrammingError as exc:
            raise QueryError("query.sql", str(exc)) from exc
    if not columns:
        raise QueryError("query.refused", "only a statement that returns rows is allowed")
    if len(set(columns)) != len(columns):
        raise QueryError("query.duplicate-column",
                         "name each result column once (use AS)")  # fmt: skip
    rows = [dict(zip(columns, values, strict=True)) for values in fetched[:limit]]
    return {"columns": columns, "rows": rows, "truncated": len(fetched) > limit}


__all__ = ["MAX_LENGTH", "QueryError", "STEP_UNIT", "connect_ro", "run"]
