"""Policy files and decisions (0.74): ``opentine.policy/1``.

A policy file is JSON::

    {"schema": "opentine.policy/1", "name": "promote", "description": "...",
     "params": {"approvals": 2},
     "rules": [{"id": "holdout-signed", "effect": "require",
                "expr": "evals.exists(e, e.holdout && e.scorer)"}]}

``effect`` is ``require`` (the decision is ``allow`` only when every
``require`` rule is ``true``) or ``advisory`` (recorded, never blocks: D12).
Any error in a ``require`` rule, including a parse error, a bad input document
or a non-boolean result, denies; an error is recorded with its code. The
policy digest is ``sha256:`` over ``opentine.policy/1`` + NUL + the canonical
JSON of the whole file, so params are covered. Expressions are the language of
:mod:`opentine._policy_lang`, evaluated by :mod:`opentine._policy_eval` with
the input document's top-level keys bound as variables.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from opentine._json_shallow import loads as shallow_loads
from opentine._policy_eval import check_input, evaluate
from opentine._policy_lang import PolicyError, number_ok, parse

SCHEMA = "opentine.policy/1"
EFFECTS = ("require", "advisory")
MAX_RULES = 64
MAX_POLICY_BYTES = 256 * 1024
RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
STANDARD_DIR = Path(__file__).parent / "data" / "policies"


class PolicyFileError(ValueError):
    """The policy file is missing or not an ``opentine.policy/1`` document."""


def check_policy(doc: Any) -> list[str]:
    """Problems with *doc* as a policy (none: valid). Expressions are not parsed here."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return [f"not an {SCHEMA} document"]
    extra = set(doc) - {"schema", "name", "description", "params", "rules"}
    if extra:
        return [f"unknown fields {sorted(extra)}"]
    if not isinstance(doc.get("name"), str) or not doc["name"]:
        return ["name is a non-empty string"]
    if not isinstance(doc.get("description", ""), str):
        return ["description is a string"]
    if not isinstance(doc.get("params", {}), dict):
        return ["params is an object"]
    rules = doc.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        return [f"rules is a list of 1-{MAX_RULES} rules"]
    seen: set[str] = set()
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or not {"id", "expr", "effect"} <= set(rule)
            or set(rule) - {"id", "expr", "effect", "description"}
        ):
            return ["a rule has id, expr, effect and an optional description"]
        if not isinstance(rule["id"], str) or not RULE_ID.fullmatch(rule["id"]):
            return [f"rule id {rule['id']!r} is 1-64 of A-Z a-z 0-9 _ . : -"]
        if rule["id"] in seen:
            return [f"rule id {rule['id']} is repeated"]
        if rule["effect"] not in EFFECTS or not isinstance(rule["expr"], str):
            return [f"rule {rule['id']}: effect is require or advisory, expr a string"]
        seen.add(rule["id"])
    return []


def load(path: str | Path) -> tuple[dict[str, Any], bytes]:
    """The policy at *path* (or a standard policy by name) and its bytes."""
    # A bare standard name always means the shipped policy: a file of that name in the
    # working directory cannot shadow it (use ./NAME for such a file).
    if isinstance(path, str) and re.fullmatch(r"[a-z0-9-]{1,64}", path):
        if (STANDARD_DIR / f"{path}.json").is_file() or not Path(path).exists():
            path = STANDARD_DIR / f"{path}.json"
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyFileError(f"cannot read policy {path}: {exc.strerror}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyFileError(f"policy {path} is larger than {MAX_POLICY_BYTES} bytes")
    try:
        doc = strict_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PolicyFileError(f"policy {path} is not JSON: {exc}") from exc
    problems = check_policy(doc)
    if problems:
        raise PolicyFileError(f"policy {path}: {problems[0]}")
    return doc, raw


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _number(text: str) -> Any:
    value = float(text) if any(c in text for c in ".eE") else int(text)
    if not number_ok(value):
        raise ValueError(f"number {text[:32]} is not finite or not JSON-safe")
    return value


def strict_json(text: str) -> Any:
    """JSON with no duplicate keys, no NaN/Infinity and only JSON-safe numbers."""
    return shallow_loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                         parse_int=_number, parse_float=_number)  # fmt: skip


def standard() -> list[str]:
    return sorted(p.stem for p in STANDARD_DIR.glob("*.json"))


def policy_digest(doc: dict[str, Any]) -> str:
    from opentine.kernel import canonical_json

    return "sha256:" + hashlib.sha256(SCHEMA.encode() + b"\0" + canonical_json(doc)).hexdigest()


def input_digest(document: dict[str, Any]) -> str:
    from opentine.kernel import canonical_json

    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


def rule_result(expr: str, env: dict[str, Any]) -> dict[str, Any]:
    """``{"outcome": "true"|"false"|"error", "code"}`` of one expression."""
    try:
        value = evaluate(parse(expr), env)
    except PolicyError as exc:
        return {"outcome": "error", "code": exc.code, "message": str(exc)}
    except RecursionError:
        return {"outcome": "error", "code": "policy.steps", "message": "too deep"}
    if not isinstance(value, bool):
        return {"outcome": "error", "code": "policy.not-bool",
                "message": "a rule evaluates to a bool"}  # fmt: skip
    return {"outcome": "true" if value else "false", "code": None, "message": None}


def decide(doc: dict[str, Any], document: Any) -> dict[str, Any]:
    """Evaluate every rule of *doc* over *document*: ``{"decision", "rules"}``."""
    try:
        check_input(document)
        if not isinstance(document, dict):
            raise PolicyError("policy.input", "the input document is an object")
        bad = None
    except PolicyError as exc:
        bad = {"outcome": "error", "code": exc.code, "message": str(exc)}
    rules = []
    for rule in doc["rules"]:
        result = bad or rule_result(rule["expr"], document)
        rules.append({"id": rule["id"], "effect": rule["effect"], **result})
    allow = all(r["outcome"] == "true" for r in rules if r["effect"] == "require")
    return {"decision": "allow" if allow else "deny", "rules": rules}


__all__ = ["EFFECTS", "SCHEMA", "PolicyFileError", "check_policy", "decide", "input_digest",
           "load", "policy_digest", "rule_result", "standard", "strict_json"]  # fmt: skip
