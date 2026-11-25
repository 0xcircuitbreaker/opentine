"""Strict JSON for the derived ``legacy_step_id``: read bodies as OpenTine reads them.

Decoder side and input-controlled: bounded, linear checks first. A body must be
the v3 canonical JSON (SPEC 0.2) of what it parses to, or derivation is refused
(``derive``). The hash is over the v2 canonical form (SPEC 0.3).
"""

from __future__ import annotations

import codecs
import hashlib
import json
import math
import re
from decimal import Decimal

from opentine._hec._core import HecError

MAX_JSON_DEPTH = 512  # = opentine.kernel.MAX_JSON_DEPTH
EVENT_TOKENS = 200_000  # kernel.validate_json_shape default (events)
_TOK_MIN, _TOK_MAX = 200_000, 16_000_000  # _artifact_io.compact_token_budget (blobs)
INT_MAX = 9_007_199_254_740_991
_JSON_TOK = re.compile(rb'[\[{\]},:"\\\x00]')
_ESC = json.encoder.encode_basestring_ascii
_SLICE = 1 << 14  # chars per escaped string piece (at most 12 bytes each)
#: Worst-case parsed-tree bytes per structural token (a list/dict/str object and its slot).
TOKEN_COST = 64
#: Parsed-tree bytes one derivation may build (~1M tokens), the same for every encoder and
#: decoder whatever its budget, so a writer never self-derives what a reader refuses.
PARSE_MAX = 64 * 1024 * 1024


def shape_ok(body: bytes, max_tokens: int) -> bool:
    """``kernel.validate_json_shape`` in one linear pass."""
    return tokens(body, max_tokens) >= 0


def tokens(body: bytes, max_tokens: int) -> int:
    """The structural token count of *body*, or -1 past the depth or token cap."""
    depth = count = 0
    in_str = False
    skip = -1
    for m in _JSON_TOK.finditer(body):
        p = m.start()
        c = body[p]
        if c == 0:
            return False
        if p == skip:
            continue
        if in_str:
            if c == 0x5C:
                skip = p + 1
            elif c == 0x22:
                in_str = False
            continue
        if c == 0x22:
            in_str = True
        elif c in b"[{":
            depth += 1
            count += 1
        elif c in b",:]}":
            count += 1
            depth -= c in b"]}"
        else:
            continue
        if depth > MAX_JSON_DEPTH or count > max_tokens:
            return -1
    return count


def _parse_int(v: str):
    i = int(v)
    return i if abs(i) <= INT_MAX else float(v)


def _number(v) -> str:
    if isinstance(v, int):
        if abs(v) > INT_MAX:
            raise ValueError("wide integer")
        return str(v)
    if not math.isfinite(v):
        raise ValueError("NaN/Infinity")
    if v == 0:
        return "0"
    raw = repr(v).lower()
    if 1e-6 <= abs(v) < 1e21:
        raw = format(Decimal(raw), "f") if "e" in raw else raw
        return raw.rstrip("0").rstrip(".") if "." in raw else raw
    coef, exp = (raw if "e" in raw else format(v, ".15e")).split("e")
    return "{}e{:+d}".format(coef.rstrip("0").rstrip("."), int(exp))


def _v3(v, depth: int = 0):
    """``kernel.canonical_json`` (SPEC 0.2), as text pieces (no whole copy of a body)."""
    if v is None or isinstance(v, bool):
        yield "null" if v is None else "true" if v else "false"
    elif isinstance(v, str):
        yield '"'
        for i in range(0, len(v), _SLICE):
            yield json.dumps(v[i : i + _SLICE], ensure_ascii=False)[1:-1]
        yield '"'
    elif isinstance(v, (int, float)):
        yield _number(v)
    elif depth >= MAX_JSON_DEPTH:
        raise ValueError("too deep")
    elif isinstance(v, list):
        yield "["
        for n, x in enumerate(v):
            if n:
                yield ","
            yield from _v3(x, depth + 1)
        yield "]"
    else:
        yield "{"
        for n, k in enumerate(sorted(v, key=lambda k: k.encode("utf-16be"))):
            yield ("," if n else "") + json.dumps(k, ensure_ascii=False) + ":"
            yield from _v3(v[k], depth + 1)
        yield "}"


def _is_v3(v, body: bytes) -> bool:
    view, at = memoryview(body), 0
    for piece in _v3(v):
        b = piece.encode("utf-8")
        if view[at : at + len(b)] != b:
            return False
        at += len(b)
    return at == len(body)


def _utf8(body: bytes) -> str:
    """``body.decode()`` in pieces: a whole-body decode of astral text peaks near 5x it."""
    d, view = codecs.getincrementaldecoder("utf-8")("strict"), memoryview(body)
    parts = [d.decode(view[i : i + (1 << 16)]) for i in range(0, len(body), 1 << 16)]
    parts.append(d.decode(b"", final=True))
    return "".join(parts)


def load(body: bytes, ctx, blob: bool = False) -> dict:
    """Parse a body under OpenTine's reader rules; anything else is ``derive``."""
    ctx.charge(len(body))
    budget = min(_TOK_MAX, max(_TOK_MIN, len(body))) if blob else EVENT_TOKENS
    n = tokens(body, budget)
    if n < 0:
        raise HecError("derive", "JSON nested too deeply or too many tokens")
    # the parsed tree is ~TOKEN_COST bytes a token, ~40x a dense body: one derivation's
    # trees are metered before any is built
    ctx.mem += (n + 1) * TOKEN_COST
    if ctx.mem > PARSE_MAX:
        raise HecError("limit", "parsed JSON of one derivation exceeds PARSE_MAX")
    try:
        v = json.loads(_utf8(body), parse_int=_parse_int)
        if not _is_v3(v, body):
            raise ValueError("not canonical")
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise HecError("derive", f"not canonical JSON: {exc}") from None
    if not isinstance(v, dict):
        raise HecError("derive", "body is not an object")
    return v


def canonical_v2(o) -> bytes:
    """``_canon._canonical_bytes`` over plain parsed JSON (SPEC 0.3)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _v2_chunks(v):
    """``canonical_v2`` as small pieces, so no expanded string ever exists whole."""
    if isinstance(v, str):
        yield '"'
        for i in range(0, len(v), _SLICE):
            yield _ESC(v[i : i + _SLICE])[1:-1]
        yield '"'
    elif isinstance(v, dict):
        yield "{"
        for n, k in enumerate(sorted(v)):
            if n:
                yield ","
            yield from _v2_chunks(k)
            yield ":"
            yield from _v2_chunks(v[k])
        yield "}"
    elif isinstance(v, list):
        yield "["
        for n, x in enumerate(v):
            if n:
                yield ","
            yield from _v2_chunks(x)
        yield "]"
    else:
        yield json.dumps(v, allow_nan=False)  # null/true/false/int/float: one token


def hash_v2(o, ctx) -> str:
    """sha256 of ``canonical_v2(o)``, charging each piece before hashing it."""
    h = hashlib.sha256()
    for piece in _v2_chunks(o):
        ctx.charge(len(piece))
        h.update(piece.encode("ascii"))
    return h.hexdigest()
