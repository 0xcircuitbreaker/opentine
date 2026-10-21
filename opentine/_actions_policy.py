"""Action policies: deny/warn rules checked against the action index.

A policy file (TOML, or JSON) is a list of rules::

    [[rule]]
    id = "no-recursive-delete-of-root"
    level = "deny"            # deny (default) or warn
    program = "rm"
    cmd = "-rf /"
    message = "agents must not delete from the filesystem root"

    [[rule]]
    id = "only-known-hosts"
    level = "warn"
    verb = "net"
    host = "*.internal.example"

Every matcher is an action-query filter (see :mod:`opentine._actions_query`);
all of a rule's matchers must hold for an action to violate it. ``tine audit
--policy FILE`` exits 1 when a ``deny`` rule matches (or any rule, with
``--strict``), so a CI step can gate on what agents did.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentine._actions import Action
from opentine._actions_db import ActionIndex
from opentine._actions_query import ActionQuery, ActionQueryError, find, parse_time

MAX_POLICY_BYTES = 1024 * 1024
MAX_RULES = 1_000
_MATCHERS = "tool program path host mcp verb agent model provider session run since until".split()
_FLAGS = ("errors", "writes")
_KEYS = frozenset({"id", "level", "message", "cmd", *_MATCHERS, *_FLAGS})


@dataclass(frozen=True)
class Rule:
    id: str
    level: str
    message: str
    query: ActionQuery


@dataclass(frozen=True)
class Violation:
    rule: Rule
    action: Action


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ActionQueryError(f"{where} must be a non-empty string of at most 4096 characters")
    return value


def _rule(raw: Any, index: int) -> Rule:
    where = f"rule {index + 1}"
    if not isinstance(raw, dict):
        raise ActionQueryError(f"{where} must be a table")
    unknown = sorted(set(raw) - _KEYS)
    if unknown:
        raise ActionQueryError(f"{where} has unknown keys: {', '.join(unknown)}")
    level = raw.get("level", "deny")
    if level not in ("deny", "warn"):
        raise ActionQueryError(f"{where}: level must be deny or warn")
    query = ActionQuery()
    for key in _MATCHERS:
        if key in raw:
            value = _text(raw[key], f"{where}.{key}")
            setattr(query, key, parse_time(value) if key in ("since", "until") else value)
    cmd = raw.get("cmd", [])
    terms = [cmd] if isinstance(cmd, str) else cmd
    if not isinstance(terms, list):
        raise ActionQueryError(f"{where}.cmd must be a string or a list of strings")
    query.cmd = [_text(term, f"{where}.cmd") for term in terms]
    for flag in _FLAGS:
        if flag in raw:
            if type(raw[flag]) is not bool:
                raise ActionQueryError(f"{where}.{flag} must be true or false")
            setattr(query, flag, raw[flag])
    if query == ActionQuery():
        raise ActionQueryError(f"{where} has no matcher and would match every action")
    rule_id = _text(raw.get("id", f"rule-{index + 1}"), f"{where}.id")
    message = raw.get("message", "")
    if not isinstance(message, str):
        raise ActionQueryError(f"{where}.message must be a string")
    return Rule(rule_id, level, message[:4096], query)


def load_policy(path: str | Path) -> list[Rule]:
    file = Path(path)
    try:
        with file.open("rb") as handle:
            data = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise ActionQueryError(f"cannot read policy file: {exc.strerror or exc}") from exc
    if len(data) > MAX_POLICY_BYTES:
        raise ActionQueryError("policy file exceeds 1 MiB")
    try:
        text = data.decode("utf-8")
        parsed = json.loads(text) if file.suffix == ".json" else tomllib.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ActionQueryError(f"policy file is not valid {file.suffix or 'TOML'}") from exc
    rules = parsed.get("rule", parsed.get("rules")) if isinstance(parsed, dict) else parsed
    if not isinstance(rules, list) or not rules:
        raise ActionQueryError("policy file must hold a non-empty list of rules")
    if len(rules) > MAX_RULES:
        raise ActionQueryError(f"policy file holds more than {MAX_RULES} rules")
    return [_rule(raw, index) for index, raw in enumerate(rules)]


def evaluate(index: ActionIndex, rules: list[Rule], *, limit: int = 1_000) -> list[Violation]:
    """Every action that violates a rule, up to *limit* per rule."""
    found: list[Violation] = []
    for rule in rules:
        found.extend(Violation(rule, action) for action in find(index, rule.query, limit=limit))
    return found


__all__ = ["Rule", "Violation", "evaluate", "load_policy"]
