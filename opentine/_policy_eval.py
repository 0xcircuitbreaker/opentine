"""Evaluate a parsed policy expression over a JSON input document (0.74).

Values are JSON values: ``null``, booleans, numbers (one numeric type: ``1 ==
1.0``), strings, lists and string-keyed maps. Semantics, identical in
``ts/verifier/src/policy.ts``:

* ``==``/``!=``: values of different types are unequal (never an error);
  lists and maps compare element by element.
* ``< <= > >=``: numbers with numbers, strings with strings (by Unicode code
  point, never by UTF-16 unit), booleans with booleans (``false < true``);
  anything else is ``policy.type``. Strings are not normalised: NFC and NFD
  spellings differ.
* ``x in list`` is equality membership; ``k in map`` asks for a key (a
  non-string ``k`` is ``false``).
* ``a.f`` and ``m["k"]`` on a missing key are ``policy.no-such-key``; ``l[i]``
  takes an integral number in range (``policy.index`` otherwise).
* ``&&``/``||`` evaluate both sides, left first, and are commutative over
  errors as in CEL: ``false && error`` and ``error && false`` are ``false``,
  ``true || error`` is ``true``; otherwise the first error wins. A non-boolean
  operand is ``policy.type``. ``all``/``exists`` evaluate every element, then:
  ``all`` is ``false`` if any is false, else the first error, else ``true``;
  ``exists`` is ``true`` if any is true, else the first error, else ``false``.
  A map iterates its keys in code-point order.
* ``size`` counts code points of a string, items of a list, keys of a map.
* Every node evaluated is a step; more than :data:`MAX_STEPS` is
  ``policy.steps`` and cannot be absorbed by ``&&``/``||``.

The input document is checked first (``policy.input``): JSON types only,
finite numbers, integral numbers within +-(2**53 - 1), no lone surrogates,
depth at most :data:`MAX_INPUT_DEPTH`.
"""

from __future__ import annotations

from typing import Any

from opentine._policy_lang import PolicyError, number_ok

MAX_STEPS = 10_000
MAX_INPUT_DEPTH = 64


class _Fatal(Exception):
    def __init__(self, error: PolicyError) -> None:
        super().__init__(str(error))
        self.error = error


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def check_input(value: Any, depth: int = 0) -> None:
    if depth > MAX_INPUT_DEPTH:
        raise PolicyError("policy.input", "input nested too deeply")
    if value is None or isinstance(value, bool):
        return
    if _num(value):
        if not number_ok(value):
            raise PolicyError("policy.input", "input number is not finite or not JSON-safe")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise PolicyError("policy.input", "input string has a lone surrogate")
        return
    if isinstance(value, list):
        for item in value:
            check_input(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyError("policy.input", "input map keys are strings")
            check_input(key, depth + 1)
            check_input(item, depth + 1)
        return
    raise PolicyError("policy.input", "input holds a value that is not JSON")


def kind(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if _num(v):
        return "number"
    if isinstance(v, str):
        return "string"
    return "list" if isinstance(v, list) else "map"


def equal(a: Any, b: Any) -> bool:
    ka, kb = kind(a), kind(b)
    if ka != kb:
        return False
    if ka == "list":
        return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b, strict=True))
    if ka == "map":
        return set(a) == set(b) and all(equal(a[k], b[k]) for k in a)
    return a == b


def _order(op: str, a: Any, b: Any) -> bool:
    ka = kind(a)
    if ka != kind(b) or ka not in ("number", "string", "bool"):
        raise PolicyError("policy.type", f"cannot order {ka} and {kind(b)}")
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


class Evaluator:
    def __init__(self, env: dict[str, Any]) -> None:
        self.env = env
        self.steps = 0

    def run(self, tree: tuple) -> Any:
        try:
            return self.ev(tree, {})
        except _Fatal as fatal:
            raise fatal.error from None

    def _try(self, tree: tuple, scope: dict[str, Any]) -> tuple[Any, PolicyError | None]:
        try:
            value = self.ev(tree, scope)
        except PolicyError as exc:
            return None, exc
        if not isinstance(value, bool):
            return None, PolicyError("policy.type", f"expected a bool, got {kind(value)}")
        return value, None

    def _logic(self, results: list[tuple[Any, PolicyError | None]], short: bool) -> bool:
        if any(err is None and val is short for val, err in results):
            return short
        for _val, err in results:
            if err is not None:
                raise err
        return not short

    def ev(self, t: tuple, scope: dict[str, Any]) -> Any:  # noqa: C901 - one dispatch
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise _Fatal(PolicyError("policy.steps", f"more than {MAX_STEPS} steps"))
        op = t[0]
        if op == "lit":
            return t[1]
        if op == "var":
            if t[1] in scope:
                return scope[t[1]]
            if t[1] in self.env:
                return self.env[t[1]]
            raise PolicyError("policy.no-such-var", f"undeclared reference {t[1]}")
        if op == "list":
            return [self.ev(item, scope) for item in t[1]]
        if op in ("and", "or"):
            results = [self._try(t[1], scope), self._try(t[2], scope)]
            return self._logic(results, op == "or")
        if op == "not":
            v = self.ev(t[1], scope)
            if not isinstance(v, bool):
                raise PolicyError("policy.type", "! takes a bool")
            return not v
        if op == "neg":
            v = self.ev(t[1], scope)
            if not _num(v):
                raise PolicyError("policy.type", "- takes a number")
            return -v
        if op == "cmp":
            a, b = self.ev(t[2], scope), self.ev(t[3], scope)
            if t[1] in ("==", "!="):
                return equal(a, b) == (t[1] == "==")
            return _order(t[1], a, b)
        if op == "in":
            a, b = self.ev(t[1], scope), self.ev(t[2], scope)
            if isinstance(b, list):
                return any(equal(a, x) for x in b)
            if isinstance(b, dict):
                return isinstance(a, str) and a in b
            raise PolicyError("policy.type", f"'in' takes a list or map, got {kind(b)}")
        if op == "sel":
            v = self.ev(t[1], scope)
            if not isinstance(v, dict):
                raise PolicyError("policy.type", f"cannot select .{t[2]} on {kind(v)}")
            if t[2] not in v:
                raise PolicyError("policy.no-such-key", f"no such key: {t[2]}")
            return v[t[2]]
        if op == "has":
            v = self.ev(t[1], scope)
            if not isinstance(v, dict):
                raise PolicyError("policy.type", f"has() on {kind(v)}")
            return t[2] in v
        if op == "idx":
            return self._index(self.ev(t[1], scope), self.ev(t[2], scope))
        if op == "size":
            v = self.ev(t[1], scope)
            if isinstance(v, (str, list, dict)):
                return len(v)
            raise PolicyError("policy.type", f"size() of {kind(v)}")
        return self._macro(t, scope)

    def _index(self, v: Any, key: Any) -> Any:
        if isinstance(v, list):
            if not _num(key) or float(key) != int(key):
                raise PolicyError("policy.type", "a list index is an integral number")
            if not 0 <= int(key) < len(v):
                raise PolicyError("policy.index", "list index out of range")
            return v[int(key)]
        if isinstance(v, dict):
            if not isinstance(key, str):
                raise PolicyError("policy.type", "a map key is a string")
            if key not in v:
                raise PolicyError("policy.no-such-key", f"no such key: {key}")
            return v[key]
        raise PolicyError("policy.type", f"cannot index {kind(v)}")

    def _macro(self, t: tuple, scope: dict[str, Any]) -> bool:
        op, target, name, body = t
        items = self.ev(target, scope)
        if isinstance(items, dict):
            items = sorted(items)
        if not isinstance(items, list):
            raise PolicyError("policy.type", f"{op}() over {kind(items)}")
        results = [self._try(body, {**scope, name: item}) for item in items]
        return self._logic(results, op == "exists")


def evaluate(tree: tuple, env: dict[str, Any]) -> Any:
    """The value of *tree* with *env* bound (checked by :func:`check_input` first)."""
    return Evaluator(env).run(tree)


__all__ = ["MAX_INPUT_DEPTH", "MAX_STEPS", "Evaluator", "check_input", "equal", "evaluate",
           "kind"]  # fmt: skip
