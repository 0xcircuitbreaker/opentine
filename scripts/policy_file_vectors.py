"""Policy-file vectors (0.75) for tests/data/policy_vectors.json: raw file text and whether
``opentine._policy`` accepts it, refuses it as JSON (``strict_json``) or refuses it as a
policy (``check_policy``). The TS loader (ts/verifier/src/policyfile.ts) must agree."""

from __future__ import annotations

R = '"rules": [{"id": "a", "effect": "require", "expr": "true"}]'
HEAD = '"schema": "opentine.policy/1", "name": "p"'


def ok(id_: str, body: str) -> dict:
    return {"id": id_, "text": body, "expect": "ok"}


def bad(id_: str, body: str, stage: str) -> dict:
    return {"id": id_, "text": body, "expect": stage}


FILES = [
    ok("minimal", "{" + HEAD + ", " + R + "}"),
    ok(
        "params-and-description",
        "{" + HEAD + ', "description": "d", "params": {"k": [1, 2.5, -3]}, ' + R + "}",
    ),
    ok("max-safe-int", "{" + HEAD + ', "params": {"k": 9007199254740991}, ' + R + "}"),
    ok("min-safe-int", "{" + HEAD + ', "params": {"k": -9007199254740991}, ' + R + "}"),
    ok("fraction-beyond-safe-is-fine", "{" + HEAD + ', "params": {"k": 0.5}, ' + R + "}"),
    ok("proto-key", "{" + HEAD + ', "params": {"__proto__": 1}, ' + R + "}"),
    bad("duplicate-top-key", "{" + HEAD + ', "name": "q", ' + R + "}", "json"),
    bad("duplicate-nested-key", "{" + HEAD + ', "params": {"a": 1, "a": 2}, ' + R + "}", "json"),
    bad(
        "duplicate-rule-key",
        "{" + HEAD + ', "rules": [{"id": "a", "id": "b", "effect": "require", "expr": "true"}]}',
        "json",
    ),
    bad("nan", "{" + HEAD + ', "params": {"k": NaN}, ' + R + "}", "json"),
    bad("infinity", "{" + HEAD + ', "params": {"k": Infinity}, ' + R + "}", "json"),
    bad("negative-infinity", "{" + HEAD + ', "params": {"k": -Infinity}, ' + R + "}", "json"),
    bad("float-overflow", "{" + HEAD + ', "params": {"k": 1e400}, ' + R + "}", "json"),
    ok(
        "nested-param-at-limit",
        "{" + HEAD + ', "params": {"k": ' + "[" * 198 + "]" * 198 + "}, " + R + "}",
    ),
    bad(
        "nested-param-past-limit",
        "{" + HEAD + ', "params": {"k": ' + "[" * 199 + "]" * 199 + "}, " + R + "}",
        "json",
    ),
    bad("deep-nesting-bomb", "[" * 5000 + "]" * 5000, "json"),
    ok(
        "brackets-in-strings-do-not-count",
        "{" + HEAD + ', "params": {"k": "' + "[" * 500 + '"}, ' + R + "}",
    ),
    bad("unsafe-int", "{" + HEAD + ', "params": {"k": 9007199254740992}, ' + R + "}", "json"),
    bad(
        "unsafe-negative-int",
        "{" + HEAD + ', "params": {"k": -9007199254740992}, ' + R + "}",
        "json",
    ),
    bad("unsafe-integral-float", "{" + HEAD + ', "params": {"k": 1e16}, ' + R + "}", "json"),
    bad(
        "unsafe-integral-float-dot",
        "{" + HEAD + ', "params": {"k": 9007199254740992.0}, ' + R + "}",
        "json",
    ),
    bad("trailing-garbage", "{" + HEAD + ", " + R + "} x", "json"),
    bad("not-json", "schema: opentine.policy/1", "json"),
    bad("wrong-schema", '{"schema": "opentine.policy/2", "name": "p", ' + R + "}", "policy"),
    bad("unknown-field", "{" + HEAD + ', "extra": 1, ' + R + "}", "policy"),
    bad("empty-name", '{"schema": "opentine.policy/1", "name": "", ' + R + "}", "policy"),
    bad("null-params", "{" + HEAD + ', "params": null, ' + R + "}", "policy"),
    bad("no-rules", "{" + HEAD + ', "rules": []}', "policy"),
    bad(
        "bad-effect",
        "{" + HEAD + ', "rules": [{"id": "a", "effect": "block", "expr": "true"}]}',
        "policy",
    ),
    bad(
        "repeated-rule-id",
        "{" + HEAD + ', "rules": [{"id": "a", "effect": "require", "expr": "true"}, '
        '{"id": "a", "effect": "advisory", "expr": "true"}]}',
        "policy",
    ),
    bad(
        "bad-rule-id",
        "{" + HEAD + ', "rules": [{"id": "a b", "effect": "require", "expr": "true"}]}',
        "policy",
    ),
    bad("not-an-object", "[1]", "policy"),
]


def stage(text: str) -> str:
    """What the Python reference says of *text*: ok, json or policy."""
    from opentine._policy import check_policy, strict_json

    try:
        doc = strict_json(text)
    except (ValueError, RecursionError):
        return "json"
    return "policy" if check_policy(doc) else "ok"
