"""The ``opentine-1`` HEC grammar: OpenTine objects, ``header NL body``.

The header line is the type descriptor. Derivable digests:

* ``type:sha256:<hex>`` -- the typed oid of an in-pack object: a link, relative;
* ``legacy_step_id`` -- 64 hex in an event, derived from the event, its input
  and output blobs and its parents' legacy ids: self-derived;
* any other 64-hex -- not derivable: opaque (32 raw bytes).

JSON strings of 24 bytes or more are literal units, so a repeated string is one
back-reference. ``oid = type ":sha256:" hex(sha256(type NUL schema NUL body))``;
the engine's identifier is the full oid as ASCII bytes. Any change the grammar
must learn is a new grammar name, never an edit of this one.
"""

from __future__ import annotations

import hashlib
import re

from opentine._hec import _strict_json as sj
from opentine._hec._core import HecError
from opentine._hec._grammar import UNIT, Link, Opaque, SelfDerived, Type, as_hex, hex_parse

F_OID, F_LEGACY, F_HEX = 0, 1, 2
UNIT_MIN = 24
SCHEMA_MAX = 9_007_199_254_740_991  # kernel.object_id accepts 1 <= schema < 2**53
_HEADER = re.compile(
    rb'\{"encoding":"(json|raw)","schema":(0|[1-9][0-9]{0,15}),"type":"([a-z_]{1,32})"\}'
)
_STRING = re.compile(rb'"([^"\\]*(?:\\.[^"\\]*)*)"', re.S)
_OID = re.compile(rb"(?:[a-z_]{1,32}:sha256:)?([0-9a-f]{64})")
_LEGACY_KEY = b'"legacy_step_id":'
OBJECT_TYPES = frozenset({"blob", "event", "run", "attestation", "annotation"})
SPLIT_KEYS = ("instructions", "system", "tools")  # = repository._prompt_parts.SPLIT_KEYS


def _scanner(is_event: bool):
    def scan(body: bytes) -> list:
        out = []
        for m in _STRING.finditer(body):
            s, e = m.span(1)
            n = e - s
            if n < UNIT_MIN:
                continue
            if n >= 64:
                o = _OID.fullmatch(body, s, e)
                if o is not None:
                    opaque = (o.start(1), e, F_HEX, None, None)
                    if n > 64:
                        out.append((s, e, F_OID, body[s:e], opaque))
                    elif is_event and body[s - 18 : s - 1] == _LEGACY_KEY:
                        out.append((s, e, F_LEGACY, None, opaque))
                    else:
                        out.append(opaque)
                    continue
            out.append((s, e, UNIT, None, None))
        return out

    return scan


def _legacy_of(obj, ctx) -> str:
    """The legacy_step_id an earlier event carries (an input, not a proof)."""
    if obj.memo is None:
        obj.memo = {}
    v = obj.memo.get("legacy")
    if v is None:
        t = sj.load(obj.body, ctx)
        v = t.get("legacy_step_id")
        if not isinstance(v, str):
            raise HecError("derive", "parent has no legacy_step_id")
        obj.memo["legacy"] = v
    return v


def _blob(ev: dict, key: str, ctx, seen: dict | None = None) -> dict:
    o = ctx.lookup(ev[key].encode()) if isinstance(ev.get(key), str) else None
    if o is None:
        raise HecError("derive", f"{key} is not an earlier object")
    if seen is not None and id(o) in seen:  # input and output name one blob: parse it once
        return seen[id(o)]
    v = sj.load(o.body, ctx, blob=True)
    if seen is not None:
        seen[id(o)] = v
    return v


def _inputs(ev: dict, ctx, seen: dict) -> dict:
    inputs = _blob(ev, "input_blob", ctx, seen)
    parts = ev.get("input_parts")
    if parts is None:
        return inputs
    if not isinstance(parts, dict) or not parts:  # 0.38+ prompt parts (SPEC 1.5.2)
        raise HecError("derive", "bad input_parts")
    inputs = dict(inputs)
    for k in sorted(parts):
        if k not in SPLIT_KEYS or not isinstance(parts[k], str) or not parts[k]:
            raise HecError("derive", "unknown input part")
        o = ctx.lookup(parts[k].encode())
        if o is None:
            raise HecError("derive", "input part is not an earlier object")
        part = sj.load(o.body, ctx, blob=True)
        if list(part) != [k] or k in inputs:
            raise HecError("derive", "bad input part")
        inputs[k] = part[k]
    return inputs


def _legacy_step_id(ctx) -> bytes:
    """sha256 over the canonical JSON of the step payload, as OpenTine 0.5x computed it."""
    ctx.mem = 0  # parsed-tree bytes of this derivation (sj.load)
    ev = sj.load(ctx.body, ctx)
    try:
        parents = []
        for p in ev["parent_ids"]:
            o = ctx.lookup(p.encode()) if isinstance(p, str) else None
            if o is None:
                raise HecError("derive", "parent is not an earlier object")
            parents.append(_legacy_of(o, ctx))
        seen: dict = {}
        inputs = _inputs(ev, ctx, seen)
        payload = {
            "error": ev.get("error") or {},
            "inputs": inputs,
            "kind": ev["kind"],
            "model_info": ev.get("model", ""),
            "outputs": _blob(ev, "output_blob", ctx, seen) or {},
            "parent_ids": parents,
            "tool_info": ev.get("tool") or {},
        }
        # hashed in pieces, each charged first: the budget refuses before the
        # ensure_ascii expansion (up to 6x a body, twice) is ever materialized
        digest = sj.hash_v2(payload, ctx)
    except HecError:
        raise
    except Exception as exc:  # any shape the derivation cannot read is a refusal
        raise HecError("derive", f"legacy_step_id: {exc!r}") from None
    return digest.encode()


class OpenTineGrammar:
    name = "opentine-1"
    fields = (
        Link("oid", "rel", None, top=True),
        SelfDerived("legacy_step_id", _legacy_step_id),
        Opaque("hex64", 32, as_hex, hex_parse(32)),
    )

    def __init__(self) -> None:
        self._types: dict[bytes, Type] = {}

    def type_info(self, desc: bytes) -> Type:
        desc = bytes(desc)
        t = self._types.get(desc)
        if t is None:
            m = _HEADER.fullmatch(desc)
            if m is None:
                raise HecError("grammar", "header is not the canonical OpenTine header")
            name, schema = m.group(3), m.group(2)
            # the id covers type and schema only: every other header byte must follow from them
            if (
                name.decode() not in OBJECT_TYPES
                or schema == b"0"
                or int(schema) > SCHEMA_MAX
                or (m.group(1) == b"raw") != (name == b"blob")
            ):
                raise HecError("grammar", "header not reachable from (type, schema)")
            t = Type(desc, name, 0, _scanner(name == b"event"), extra=name + b"\0" + schema + b"\0")
            if len(self._types) < 4096:
                self._types[desc] = t
        return t

    def object_id(self, t: Type, body: bytes) -> bytes:
        return t.name + b":sha256:" + hashlib.sha256(t.extra + body).hexdigest().encode()


OPENTINE = OpenTineGrammar()


def split(raw: bytes) -> tuple[bytes, bytes]:
    """Stored object bytes -> ``(type descriptor, body)``."""
    head, nl, body = raw.partition(b"\n")
    if not nl:
        raise HecError("grammar", "object has no header line")
    return head, body
