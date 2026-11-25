"""Decoder helpers: the derive work meter, unit holes, the want-set check."""

from __future__ import annotations

from opentine._hec._core import (
    C_UNIT_NEW,
    C_UNIT_PREFIX,
    C_UNIT_REF,
    HecError,
    Limits,
    Obj,
    Reader,
)


class Ctx:
    """What a derived field may use: the object being rebuilt, earlier objects, a work meter."""

    __slots__ = ("body", "budget", "by_id", "limits", "type", "work")

    def __init__(self, limits: Limits, budget: int | None = None) -> None:
        self.by_id: dict[bytes, Obj] = {}
        self.limits = limits
        self.work = 0
        self.body: bytes | None = None
        self.type = None
        cap = limits.max_hashed_bytes
        self.budget = cap if budget is None else min(budget, cap)

    def lookup(self, id_: bytes) -> Obj | None:
        return self.by_id.get(id_)

    def charge(self, nbytes: int) -> None:
        self.work += nbytes
        if self.work > self.budget:
            raise HecError("limit", "hashed bytes")


def unit_hole(code: int, r_arg: Reader, r_unit: Reader, units: list, room: int) -> bytes:
    if code == C_UNIT_NEW:
        piece = r_unit.take(r_arg.uv())
        units.append(piece)
        return piece
    d = r_arg.uv()
    k = 0 if code == C_UNIT_REF else r_arg.uv()  # both read before either is checked
    if not 1 <= d <= len(units):
        raise HecError("bad-ref", "unit distance")
    if code == C_UNIT_REF:
        return units[-d]
    src = units[-d]
    if code == C_UNIT_PREFIX:
        if k > len(src):
            raise HecError("bad-ref", "prefix longer than unit")
        piece = src[:k]
    else:  # C_UNIT_EXT
        if len(src) + k > room:
            raise HecError("size-mismatch", "more output than declared")
        piece = src + r_unit.take(k)
    units.append(piece)
    return piece


def check_want(want, want_set, by_id: dict, edges, n_obj: int) -> None:
    if want_set is not None:
        if len(by_id) != len(want_set) or any(k not in want_set for k in by_id):
            raise HecError("want-mismatch", "decoded set differs from the want-set")
        return
    seen = bytearray(n_obj)
    stack = []
    for root in want.roots:
        o = by_id.get(root)
        if o is None:
            raise HecError("want-mismatch", "wanted root missing")
        stack.append(o.index)
    while stack:  # explicit stack, no recursion
        j = stack.pop()
        if not seen[j]:
            seen[j] = 1
            stack.extend(edges[j])
    if not all(seen):
        raise HecError("want-mismatch", "object not reachable from the wanted roots")
