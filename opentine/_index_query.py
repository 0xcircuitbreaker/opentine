"""Query DSL for the rebuildable v2 file index."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime

from opentine._graph_types import _normalize_tag
from opentine._index_types import IndexEntry

PREDICATES = ("tag", "model", "status", "cost", "after", "before")


class QueryError(ValueError):
    pass


@dataclass
class Query:
    text: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    model: str | None = None
    status: str | None = None
    cost_min: float | None = None
    cost_max: float | None = None
    after: float | None = None
    before: float | None = None


def _parse_date(value: str) -> float:
    for date_format in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(value, date_format).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    raise QueryError(f"invalid date {value!r}; use YYYY-MM-DD")


def _apply_cost(query: Query, value: str) -> None:
    candidate = value.strip()
    try:
        if ".." in candidate:
            minimum, _, maximum = candidate.partition("..")
            if minimum:
                query.cost_min = float(minimum)
            if maximum:
                query.cost_max = float(maximum)
        elif candidate.startswith(">="):
            query.cost_min = float(candidate[2:])
        elif candidate.startswith(">"):
            query.cost_min = float(candidate[1:])
        elif candidate.startswith("<="):
            query.cost_max = float(candidate[2:])
        elif candidate.startswith("<"):
            query.cost_max = float(candidate[1:])
        else:
            query.cost_min = float(candidate)
    except ValueError as exc:
        raise QueryError(f"invalid cost filter {value!r}") from exc


def parse_query(query: str) -> Query:
    try:
        tokens = shlex.split(query)
    except ValueError as exc:
        raise QueryError(f"malformed query: {exc}") from exc
    parsed = Query()
    for token in tokens:
        prefix, separator, value = token.partition(":")
        key = prefix.lower()
        if not (separator and value and key in PREDICATES):
            parsed.text.append(token.lower())
        elif key == "tag":
            normalized = _normalize_tag(value)
            if normalized:
                parsed.tags.append(normalized)
        elif key == "model":
            parsed.model = value.lower()
        elif key == "status":
            parsed.status = value.lower()
        elif key == "cost":
            _apply_cost(parsed, value)
        elif key == "after":
            parsed.after = _parse_date(value)
        elif key == "before":
            parsed.before = _parse_date(value)
    return parsed


def match_entry(entry: IndexEntry, query: Query) -> bool:
    return not (
        entry.unreadable
        or (query.tags and not all(tag in entry.tags for tag in query.tags))
        or (query.model and query.model not in entry.model.lower())
        or (query.status and entry.status.lower() != query.status)
        or (query.cost_min is not None and entry.cost < query.cost_min)
        or (query.cost_max is not None and entry.cost > query.cost_max)
        or (query.after is not None and entry.created_at < query.after)
        or (query.before is not None and entry.created_at > query.before)
        or (query.text and not all(term in entry.text for term in query.text))
    )
