"""The HEC1 encoder: ``[(type descriptor, body)]`` in table order -> pack bytes.

Only links to earlier objects are elided, so dependencies go first
(:func:`dependency_order`). A scanner only proposes spans; the encoder keeps one
when the decoder's rendering reproduces it exactly, so a wrong proposal costs
bytes, never correctness. ``verify=True`` decodes the pack again and compares.
"""

from __future__ import annotations

import heapq

from opentine._hec import _backend as backend
from opentine._hec import _container
from opentine._hec._core import (
    C_FIELD0,
    C_UNIT_EXT,
    C_UNIT_NEW,
    C_UNIT_PREFIX,
    C_UNIT_REF,
    DEFAULT_LIMITS,
    HASH_WORK_FACTOR,
    STREAMS,
    HecError,
    Limits,
    Obj,
    uv,
)
from opentine._hec._decode import decode
from opentine._hec._decode_util import Ctx
from opentine._hec._grammar import UNIT

UNIT_KEY = 64  # units sharing their first 64 bytes are prefix/extension candidates
UNIT_PREFIX_MIN = 512  # only units at least this long are tried as prefix/extension


def dependency_order(objects: list[tuple[bytes, bytes]], grammar) -> list[int]:
    """A permutation where every object follows the in-pack objects it links to."""
    n = len(objects)
    types = [grammar.type_info(d) for d, _ in objects]
    ids = [grammar.object_id(t, b) for t, (_, b) in zip(types, objects)]
    index: dict[bytes, int] = {}
    for i, k in enumerate(ids):
        index.setdefault(k, i)
    users: list[list[int]] = [[] for _ in range(n)]
    missing = [0] * n
    for i, (t, (_, body)) in enumerate(zip(types, objects)):
        deps = set()
        for c in t.scan(body):
            if c[2] != UNIT and grammar.fields[c[2]].kind == "link":
                j = index.get(c[3])
                if j is not None and j != i:
                    deps.add(j)
        missing[i] = len(deps)
        for j in deps:
            users[j].append(i)
    ready = [i for i in range(n) if not missing[i]]
    heapq.heapify(ready)
    order: list[int] = []
    while ready:
        i = heapq.heappop(ready)
        order.append(i)
        for u in users[i]:
            missing[u] -= 1
            if not missing[u]:
                heapq.heappush(ready, u)
    if len(order) != n:  # a hash cycle would be a collision; keep the rest as given
        order += sorted(set(range(n)) - set(order))
    return order


class _State:
    def __init__(self, limits: Limits, total: int) -> None:
        self.S = {name: bytearray() for name in STREAMS}
        self.units: list[bytes] = []
        self.unit_ix: dict[bytes, int] = {}
        self.unit_pfx: dict[bytes, list[int]] = {}
        self.orphans: list[int] = []
        self.refd = bytearray()
        self.objs: list[Obj] = []
        self.index: dict[bytes, int] = {}
        self.ctx = Ctx(Limits(max_output_bytes=1 << 62))
        # mirror the receiver's hashed-work meter: a derivation it would refuse stays opaque
        cap = HASH_WORK_FACTOR * total + limits.work_slack
        self.ctx.budget = min(cap, limits.max_hashed_bytes)

    def unit(self, span: bytes) -> tuple[int, bytes]:
        u = self.unit_ix.get(span)
        units = self.units
        if u is not None:
            return C_UNIT_REF, uv(len(units) - u)
        code, arg = None, b""
        if len(span) >= UNIT_PREFIX_MIN:
            cands = self.unit_pfx.setdefault(span[:UNIT_KEY], [])
            for u in reversed(cands):
                w = units[u]
                if len(w) > len(span) and w.startswith(span):
                    code, arg = C_UNIT_PREFIX, uv(len(units) - u) + uv(len(span))
                    break
                if len(w) < len(span) and span.startswith(w):
                    code, arg = C_UNIT_EXT, uv(len(units) - u) + uv(len(span) - len(w))
                    self.S["unit"] += span[len(w) :]
                    break
            cands.append(len(units))
        if code is None:
            code, arg = C_UNIT_NEW, uv(len(span))
            self.S["unit"] += span
        self.unit_ix[span] = len(units)
        units.append(span)
        return code, arg

    def field(self, f, fi, i, typ, body, start, end, key, prev, has_self):
        """``(code, arg, stream, target)`` or ``None`` when the span cannot be elided."""
        span = body[start:end]
        ctx = self.ctx
        if f.kind == "opaque":
            raw = f.parse(span)
            if raw is not None and f.render(raw) == span:
                self.S["opaque"] += raw
                return C_FIELD0 + fi, b"", None, prev
            return None
        if f.kind == "self":
            if has_self:
                return None
            ctx.body, ctx.type, w0 = body[:start] + body[end:], typ, ctx.work
            try:
                ok = f.render(ctx) == span
            except HecError:
                ok = False
            ctx.body = None
            if not ok:
                ctx.work = w0  # the decoder never runs this derivation
                return None
            return C_FIELD0 + fi, b"", None, prev
        t = prev if f.mode == "prev" else self.index.get(key, -1)
        if t < 0:
            return None
        try:
            got = self.objs[t].id if f.form is None else f.render(self.objs[t], ctx)
        except HecError:
            return None
        if got != span:
            return None
        if f.mode == "prev":
            return C_FIELD0 + fi, b"", None, prev
        orphans, refd = self.orphans, self.refd
        while orphans and refd[orphans[-1]]:
            orphans.pop()
        v = 0 if f.top and orphans and orphans[-1] == t else (i - t if f.mode == "rel" else t + 1)
        refd[t] = 1
        return C_FIELD0 + fi, uv(v), "rel" if f.mode == "rel" else "abs", t


def encode(
    objects: list[tuple[bytes, bytes]],
    grammar,
    level: int = 19,
    codec: int = backend.ZSTD,
    limits: Limits = DEFAULT_LIMITS,
    verify: bool = True,
) -> bytes:
    total = sum(len(b) for _, b in objects)
    st = _State(limits, total)
    S, fields = st.S, grammar.fields
    type_ix: dict[bytes, int] = {}
    type_info: list = []
    for i, (desc, body) in enumerate(objects):
        ti = type_ix.get(desc)
        if ti is None:
            ti = type_ix[desc] = len(type_info)
            type_info.append(grammar.type_info(desc))
        typ = type_info[ti]
        lit = S[f"lit{typ.lit}"]
        holes = pos = lit_len = 0
        prev = -1
        has_self = False
        for c in typ.scan(body):
            while c is not None:
                start, end, fi, key, alt = c
                if start < pos or holes >= limits.max_holes_per_object:
                    break
                if fi == UNIT:
                    code, arg = st.unit(body[start:end])
                    where = None
                else:
                    got = st.field(fields[fi], fi, i, typ, body, start, end, key, prev, has_self)
                    if got is None:
                        c = alt
                        continue
                    code, arg, where, prev = got
                    has_self = has_self or fields[fi].kind == "self"
                S["gap"] += uv(start - pos)
                lit += body[pos:start]
                lit_len += start - pos
                S["code"].append(code)
                S[where or "arg"] += arg
                holes += 1
                pos = end
                break
        lit += body[pos:]
        lit_len += len(body) - pos
        S["type"] += uv(ti)
        S["nholes"] += uv(holes)
        S["litlen"] += uv(lit_len)
        oid = grammar.object_id(typ, body)
        if oid in st.index:
            raise HecError("duplicate", "object appears twice in the input")
        st.ctx.work += len(body)  # the decoder charges every rebuilt body
        o = Obj(i, typ, oid, body)
        st.objs.append(o)
        st.index[oid] = i
        st.ctx.by_id[oid] = o
        st.orphans.append(i)
        st.refd.append(0)
    S["head"] += uv(len(objects)) + uv(total) + uv(len(type_info))
    for t in type_info:
        S["head"] += uv(len(t.desc)) + t.desc
    pack = _container.write(S, grammar.name.encode(), codec, level)
    if verify:
        _verify(pack, grammar, objects, st.objs, total, limits)
    return pack


def _verify(pack, grammar, objects, objs, total, limits: Limits) -> None:
    big = Limits(
        max_output_bytes=max(total, 1),
        max_objects=len(objs) + 1,
        max_window_log=31,
        max_unit_bytes=1 << 62,
        max_aux_bytes=1 << 62,
        max_hashed_bytes=limits.max_hashed_bytes,
        work_slack=limits.work_slack,
    )
    got = decode(pack, grammar, {o.id for o in objs}, big)
    if len(got.objects) != len(objects) or any(
        g.type.desc != d or g.body != b for g, (d, b) in zip(got.objects, objects)
    ):
        raise HecError("encode-verify", "round trip mismatch")
