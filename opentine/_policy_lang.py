"""The policy language (0.74): a strict, bounded subset of CEL, parsed to a tuple tree.

Accepted: ``null``, ``true``, ``false``, numbers (``12``, ``1.5``, ``2e3``),
strings (``"..."`` or ``'...'`` with ``\\\\ \\" \\' \\n \\r \\t \\uXXXX
\\UXXXXXXXX`` escapes), list literals, variables, field access ``a.b``,
indexing ``a[0]`` / ``a["k"]``, ``!``, unary ``-``, ``== != < <= > >=``,
``in``, ``&&``, ``||``, parentheses, ``has(a.b)``, ``size(x)`` /
``x.size()`` and the macros ``x.all(v, p)`` / ``x.exists(v, p)``. Nothing
else: no arithmetic, no user functions, no other macros, no comprehensions.
Comparisons do not chain (``a < b < c`` is refused). Every bound is fixed:
source length, nesting depth and node count here, steps in the evaluator.

The TypeScript verifier (``ts/verifier/src/policy.ts``) implements the same
grammar; shared vectors (``tests/data/policy_vectors.json``) run in both.
"""

from __future__ import annotations

from typing import Any

from opentine._policy_lex import (
    KEYWORDS,
    MAX_SAFE,
    MAX_SOURCE,
    RESERVED,
    PolicyError,
    number_ok,
    tokens,
)

MAX_DEPTH = 32
MAX_NODES = 1024
MAX_HEIGHT = 64  # tree height, so a long a.b.c... chain is bounded too


class _Parser:
    def __init__(self, src: str) -> None:
        self.toks = tokens(src)
        self.pos = 0
        self.depth = 0
        self.nodes = 0

    def node(self, *parts: Any) -> tuple:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise PolicyError("policy.parse", f"more than {MAX_NODES} nodes")
        return parts

    def peek(self) -> tuple[str, Any]:
        return self.toks[self.pos]

    def take(self, op: str | None = None) -> tuple[str, Any]:
        tok = self.toks[self.pos]
        if op is not None and tok != ("op", op):
            raise PolicyError("policy.parse", f"expected {op!r}")
        self.pos += 1
        return tok

    def at(self, op: str) -> bool:
        return self.peek() == ("op", op)

    def expr(self) -> tuple:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise PolicyError("policy.parse", f"nesting deeper than {MAX_DEPTH}")
        left = self.conj()
        while self.at("||"):
            self.take()
            left = self.node("or", left, self.conj())
        self.depth -= 1
        return left

    def conj(self) -> tuple:
        left = self.rel()
        while self.at("&&"):
            self.take()
            left = self.node("and", left, self.rel())
        return left

    def rel(self) -> tuple:
        left = self.unary()
        tok = self.peek()
        if tok in (("op", o) for o in ("==", "!=", "<", "<=", ">", ">=")):
            self.take()
            left = self.node("cmp", tok[1], left, self.unary())
        elif tok == ("ident", "in"):
            self.take()
            left = self.node("in", left, self.unary())
        else:
            return left
        nxt = self.peek()
        if nxt in (("op", o) for o in ("==", "!=", "<", "<=", ">", ">=")) or nxt == ("ident", "in"):
            raise PolicyError("policy.parse", "comparisons do not chain")
        return left

    def unary(self) -> tuple:
        if self.at("!") or self.at("-"):
            op = self.take()[1]
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise PolicyError("policy.parse", f"nesting deeper than {MAX_DEPTH}")
            inner = self.unary()
            self.depth -= 1
            return self.node("not" if op == "!" else "neg", inner)
        return self.member()

    def args(self) -> list[tuple]:
        self.take("(")
        out: list[tuple] = []
        if not self.at(")"):
            out.append(self.expr())
            while self.at(","):
                self.take()
                out.append(self.expr())
        self.take(")")
        return out

    def member(self) -> tuple:
        target = self.primary()
        while True:
            if self.at("."):
                self.take()
                kind, name = self.take()
                if kind != "ident" or name in KEYWORDS or name in RESERVED:
                    raise PolicyError("policy.parse", "expected a field name after '.'")
                if not self.at("("):
                    target = self.node("sel", target, name)
                    continue
                if name == "size":
                    if self.args():
                        raise PolicyError("policy.parse", "x.size() takes no arguments")
                    target = self.node("size", target)
                elif name in ("all", "exists"):
                    target = self._macro(name, target)
                else:
                    raise PolicyError("policy.parse", f"unknown function {name}")
            elif self.at("["):
                self.take()
                key = self.expr()
                self.take("]")
                target = self.node("idx", target, key)
            else:
                return target

    def _macro(self, name: str, target: tuple) -> tuple:
        args = self.args()
        if len(args) != 2 or args[0][0] != "var":
            raise PolicyError("policy.parse", f"{name}(var, predicate) takes a variable name")
        return self.node(name, target, args[0][1], args[1])

    def primary(self) -> tuple:
        kind, value = self.take()
        if kind in ("num", "str"):
            return self.node("lit", value)
        if kind == "op" and value == "(":
            inner = self.expr()
            self.take(")")
            return inner
        if kind == "op" and value == "[":
            items: list[tuple] = []
            if not self.at("]"):
                items.append(self.expr())
                while self.at(","):
                    self.take()
                    items.append(self.expr())
            self.take("]")
            return self.node("list", tuple(items))
        if kind == "ident" and value in KEYWORDS:
            return self.node("lit", KEYWORDS[value])
        if kind == "ident" and value not in RESERVED:
            if not self.at("("):
                return self.node("var", value)
            if value not in ("has", "size"):
                raise PolicyError("policy.parse", f"unknown function {value}")
            args = self.args()
            if len(args) != 1:
                raise PolicyError("policy.parse", f"{value}() takes one argument")
            if value == "has":
                if args[0][0] != "sel":
                    raise PolicyError("policy.parse", "has() takes a field selection a.b")
                return self.node("has", args[0][1], args[0][2])
            return self.node("size", args[0])
        raise PolicyError("policy.parse", "expected an expression")


def parse(src: str) -> tuple:
    """The expression tree of *src*, or :class:`PolicyError` ``policy.parse``."""
    parser = _Parser(src)
    tree = parser.expr()
    if parser.peek()[0] != "end":
        raise PolicyError("policy.parse", "unexpected input after the expression")
    if height(tree) > MAX_HEIGHT:
        raise PolicyError("policy.parse", f"expression tree taller than {MAX_HEIGHT}")
    return tree


def height(tree: Any) -> int:
    """Nodes on the longest root-to-leaf path (literal values are leaves, not nodes).

    Iterative, so a tree of any height is measured, never a ``RecursionError``
    (TS gets ``policy.parse`` for a long ``a.b.b...`` chain; so must Python).
    """
    best = 0
    stack = [(tree, 0)]
    while stack:
        node, above = stack.pop()
        if not isinstance(node, tuple):
            best = max(best, above)
        elif node and isinstance(node[0], str):  # an expression node
            best = max(best, above + 1)
            if node[0] != "lit":
                stack.extend((t, above + 1) for t in node[1:])
        else:  # a plain tuple of subtrees (arguments)
            stack.extend((t, above) for t in node)
    return best


__all__ = ["MAX_DEPTH", "MAX_HEIGHT", "MAX_NODES", "MAX_SAFE", "MAX_SOURCE", "PolicyError",
           "height", "number_ok", "parse", "tokens"]  # fmt: skip
