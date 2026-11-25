"""The HEC1 decoder: one forward pass, all-or-nothing, identifiers recomputed.

A link names a strictly earlier object, so there is no recursion and no cycle;
every hole emits at least one byte; output never exceeds the declared total;
every stream is consumed exactly; the decoded set must equal the want-set.
"""

from __future__ import annotations

from opentine._hec import _container
from opentine._hec._core import (
    ANY,
    C_FIELD0,
    C_UNIT_REF,
    DEFAULT_LIMITS,
    HASH_WORK_FACTOR,
    N_LIT,
    UNIT_OVERHEAD,
    Closure,
    Decoded,
    HecError,
    Limits,
    Obj,
    Reader,
)
from opentine._hec._decode_util import Ctx, check_want, unit_hole


def _head(S: dict[str, bytes], grammar, limits: Limits) -> tuple[int, int, list]:
    head = Reader(S["head"], "head")
    n_obj, total_out, n_types = head.uv(), head.uv(), head.uv()
    _container.check_head(n_obj, total_out, n_types, limits)
    if len(S["aux"]) > limits.max_aux_bytes:
        raise HecError("limit", "aux bytes")
    if S["aux"]:  # no OpenTine grammar reads aux: bytes no identifier covers are refused
        raise HecError("trailing", "aux stream not used by this grammar")
    types = []
    for _ in range(n_types):
        k = head.uv()
        if k > limits.max_type_desc:
            raise HecError("limit", "type descriptor")
        types.append(grammar.type_info(head.take(k)))
    if len({t.desc for t in types}) != n_types:
        raise HecError("header", "duplicate type descriptor")
    if not head.done():
        raise HecError("trailing", "head")
    for name in ("type", "nholes", "litlen"):  # each object uses >= 1 byte of each
        if len(S[name]) < n_obj:
            raise HecError("truncated", name)
    return n_obj, total_out, types


def decode(pack: bytes, grammar, want, limits: Limits = DEFAULT_LIMITS) -> Decoded:
    """Decode and verify a pack: ``Decoded`` or ``HecError``, never partial.

    *want* is mandatory: a set of identifiers (the decoded set must equal it),
    ``Closure(roots)``, or ``ANY`` for a receiver that checks the set itself.
    """
    if want is ANY:
        want_set = None
    elif isinstance(want, Closure):
        want_set = None
    elif isinstance(want, (set, frozenset)):
        want_set = want
    else:
        raise TypeError("want must be a set of identifiers or Closure(roots)")
    S = _container.read(bytes(pack), grammar.name.encode(), limits)
    n_obj, total_out, types = _head(S, grammar, limits)
    fields = grammar.fields
    check = getattr(grammar, "check", None)
    R = {name: Reader(S[name], name) for name in S if name not in ("head", "aux")}
    r_type, r_nh, r_ll, r_gap = R["type"], R["nholes"], R["litlen"], R["gap"]
    r_code, r_arg, r_rel, r_abs = R["code"], R["arg"], R["rel"], R["abs"]
    r_unit, r_opq = R["unit"], R["opaque"]
    r_lit = [R[f"lit{k}"] for k in range(N_LIT)]
    ctx = Ctx(limits, HASH_WORK_FACTOR * total_out + limits.work_slack)
    by_id = ctx.by_id
    objs: list[Obj] = []
    units: list[bytes] = []
    unit_bytes = out_total = types_seen = 0
    orphans: list[int] = []
    refd = bytearray()
    edges: list[list[int]] | None = [] if isinstance(want, Closure) else None
    for i in range(n_obj):
        ti = r_type.uv()
        if ti > types_seen or ti >= len(types):
            raise HecError("bad-ref", "type index")
        if ti == types_seen:
            types_seen += 1
        typ = types[ti]
        nh = r_nh.uv()
        if nh > limits.max_holes_per_object:
            raise HecError("limit", "holes per object")
        lit_left = r_ll.uv()
        lit = r_lit[typ.lit]
        parts: list[bytes] = []
        size = 0
        selfs = None
        prev = -1
        mine: list[int] | None = [] if edges is not None else None
        for _ in range(nh):
            gap = r_gap.uv()
            if gap > lit_left:
                raise HecError("bad-ref", "gap exceeds literal length")
            if gap:
                lit_left -= gap
                parts.append(lit.take(gap))
                size += gap
            code = r_code.take(1)[0]
            kind = None
            if code >= C_FIELD0:
                if code - C_FIELD0 >= len(fields):
                    raise HecError("bad-code", "field")
                f = fields[code - C_FIELD0]
                kind = f.kind
                if kind == "opaque":
                    piece = f.render(r_opq.take(f.size))
                elif kind == "self":
                    if selfs is not None:
                        raise HecError("bad-code", "second self-derived field in one object")
                    selfs = (len(parts), f)
                    piece = b""
                else:
                    if f.mode == "prev":
                        if prev < 0:
                            raise HecError("bad-ref", "no previous link in object")
                        t = prev
                    else:
                        v = r_rel.uv() if f.mode == "rel" else r_abs.uv()
                        if v == 0:  # the most recent object nothing links to yet
                            while orphans and refd[orphans[-1]]:
                                orphans.pop()
                            if not orphans:
                                raise HecError("bad-ref", "no unreferenced object")
                            t = orphans[-1]
                        elif v > i:
                            raise HecError("bad-ref", "link target not strictly earlier")
                        else:
                            t = i - v if f.mode == "rel" else v - 1
                        refd[t] = 1
                        prev = t
                        if mine is not None:
                            mine.append(t)
                    if kind == "link" and f.form is None:
                        piece = objs[t].id
                    else:
                        piece = f.render(objs[t], ctx)
            else:
                piece = unit_hole(code, r_arg, r_unit, units, total_out - out_total - size)
            if code >= C_FIELD0 and typ.holes is not None and code - C_FIELD0 not in typ.holes:
                raise HecError("bad-code", "field not allowed in this object type")
            if not piece and kind != "self":
                raise HecError("bad-ref", "hole emits nothing")
            if code < C_FIELD0 and code != C_UNIT_REF:
                unit_bytes += len(piece) + UNIT_OVERHEAD
                if unit_bytes > limits.max_unit_bytes:
                    raise HecError("limit", "unit bytes")
            parts.append(piece)
            size += len(piece)
            if out_total + size > total_out:
                raise HecError("size-mismatch", "more output than declared")
        if lit_left:
            parts.append(lit.take(lit_left))
            size += lit_left
            if out_total + size > total_out:
                raise HecError("size-mismatch", "more output than declared")
        if selfs is not None:
            ctx.body = b"".join(parts)
            ctx.type = typ
            parts[selfs[0]] = selfs[1].render(ctx)
            ctx.body = None
            size = sum(map(len, parts))
            if out_total + size > total_out:
                raise HecError("size-mismatch", "more output than declared")
        body = b"".join(parts)
        out_total += size
        ctx.charge(size)
        if check is not None and not check(typ, body):
            raise HecError("grammar", "type descriptor does not match the body")
        oid = grammar.object_id(typ, body)
        if oid in by_id:
            raise HecError("duplicate", "object appears twice")
        o = Obj(i, typ, oid, body)
        objs.append(o)
        by_id[oid] = o
        orphans.append(i)
        refd.append(0)
        if edges is not None:
            edges.append(mine or [])
    for r in R.values():
        if not r.done():
            raise HecError("trailing", r.name)
    if out_total != total_out:
        raise HecError("size-mismatch", "less output than declared")
    if types_seen != len(types):
        raise HecError("header", "unused type descriptor")
    if want is not ANY:
        check_want(want, want_set, by_id, edges, n_obj)
    return Decoded(objs, S["aux"])
