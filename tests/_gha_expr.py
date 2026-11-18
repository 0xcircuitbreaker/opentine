"""A small evaluator for the GitHub Actions expressions used in ``runs-on``.

Supports string literals, ``true``/``false``, dotted context lookups, ``!``,
``==``/``!=`` (case-insensitive for strings, as Actions compares them), ``&&``,
``||`` (both returning an operand, as Actions does) and parentheses. Anything
else, such as a function call, raises ``ValueError``, so a policy test built on
it fails closed instead of guessing.
"""

from __future__ import annotations

import re

TOKEN = re.compile(r"\s*(?:('(?:[^']|'')*')|(&&|\|\||==|!=|!|\(|\))|([A-Za-z_][\w.-]*))")


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos, text = [], 0, text.strip()
    while pos < len(text):
        match = TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise ValueError(f"unsupported expression syntax at {text[pos:]!r}")
        literal, op, name = match.groups()
        if literal is not None:
            tokens.append(("str", literal[1:-1].replace("''", "'")))
        elif op is not None:
            tokens.append(("op", op))
        else:
            tokens.append(("name", name))
        pos = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens, context):
        self.tokens, self.i, self.context = tokens, 0, context

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self, value=None):
        token = self.peek()
        if value is not None and token != ("op", value):
            raise ValueError(f"expected {value!r}, got {token!r}")
        self.i += 1
        return token

    def parse(self):
        value = self.or_()
        if self.i != len(self.tokens):
            raise ValueError(f"trailing tokens: {self.tokens[self.i :]!r}")
        return value

    def or_(self):
        left = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            right = self.and_()
            left = left if truthy(left) else right
        return left

    def and_(self):
        left = self.cmp()
        while self.peek() == ("op", "&&"):
            self.take()
            right = self.cmp()
            left = right if truthy(left) else left
        return left

    def cmp(self):
        left = self.unary()
        while self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            same = _norm(left) == _norm(self.unary())
            left = same if op == "==" else not same
        return left

    def unary(self):
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.unary())
        if self.peek() == ("op", "("):
            self.take()
            value = self.or_()
            self.take(")")
            return value
        kind, value = self.take()
        if kind == "str":
            return value
        if kind == "name" and value in ("true", "false"):
            return value == "true"
        if kind == "name" and self.peek() != ("op", "("):
            if value not in self.context:
                raise ValueError(f"unknown context value {value!r}")
            return self.context[value]
        raise ValueError(f"unsupported token {value!r}")


def _norm(value):
    return value.lower() if isinstance(value, str) else value


def truthy(value) -> bool:
    return bool(value)


def evaluate(text: str, context: dict) -> object:
    """Evaluate one ``${{ }}`` body against a flat ``{"github.ref": ...}`` context."""
    return _Parser(tokenize(text), context).parse()


def resolve(value: str, context: dict) -> object:
    """A ``runs-on`` value: a literal label, or a whole ``${{ ... }}`` expression."""
    match = re.fullmatch(r"\s*\$\{\{(.*)\}\}\s*", value, re.S)
    return evaluate(match.group(1), context) if match else value
