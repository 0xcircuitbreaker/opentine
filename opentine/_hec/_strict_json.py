"""Strict JSON for the derived ``legacy_step_id``: read bodies as OpenTine reads them.

Decoder side and input-controlled: bounded, linear checks first. A body must be
the v3 canonical JSON (SPEC 0.2) of what it parses to, or derivation is refused
(``derive``). The hash is over the v2 canonical form (SPEC 0.3).
"""

from __future__ import annotations

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


def shape_ok(body: bytes, max_tokens: int) -> bool:
    """``kernel.validate_json_shape`` in one linear pass."""
    depth = tokens = 0
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
            tokens += 1
        elif c in b",:]}":
            tokens += 1
            depth -= c in b"]}"
        else:
            continue
        if depth > MAX_JSON_DEPTH or tokens > max_tokens:
            return False
    return True


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


def _v3(v, depth: int = 0) -> str:
    """``kernel.canonical_json`` (SPEC 0.2), as text."""
    if v is None or isinstance(v, bool):
        return "null" if v is None else "true" if v else "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    if isinstance(v, (int, float)):
        return _number(v)
    if depth >= MAX_JSON_DEPTH:
        raise ValueError("too deep")
    parts = []
    if isinstance(v, list):
        for x in v:
            parts.append(_v3(x, depth + 1))
        return "[" + ",".join(parts) + "]"
    for k in sorted(v, key=lambda k: k.encode("utf-16be")):
        parts.append(json.dumps(k, ensure_ascii=False) + ":" + _v3(v[k], depth + 1))
    return "{" + ",".join(parts) + "}"


def load(body: bytes, ctx, blob: bool = False) -> dict:
    """Parse a body under OpenTine's reader rules; anything else is ``derive``."""
    ctx.charge(len(body))
    budget = min(_TOK_MAX, max(_TOK_MIN, len(body))) if blob else EVENT_TOKENS
    if not shape_ok(body, budget):
        raise HecError("derive", "JSON nested too deeply or too many tokens")
    try:
        v = json.loads(body.decode("utf-8"), parse_int=_parse_int)
        if _v3(v).encode("utf-8") != body:
            raise ValueError("not canonical")
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise HecError("derive", f"not canonical JSON: {exc}") from None
    if not isinstance(v, dict):
        raise HecError("derive", "body is not an object")
    return v


def canonical_v2(o) -> bytes:
    """``_canon._canonical_bytes`` over plain parsed JSON (SPEC 0.3)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
