"""HEC core: reason-coded errors, decoder limits, canonical varints, stream readers.

Normative rules: ``docs/SPEC.md`` section "TINEPACK6" (HEC1 decode rules).
"""

from __future__ import annotations

MAGIC = b"HEC1"
STREAMS = (
    "head", "type", "nholes", "litlen", "gap", "code", "arg", "rel", "abs",
    "lit0", "lit1", "lit2", "lit3", "unit", "opaque", "aux",
)  # fmt: skip
N_LIT = 4
#: Hole codes: four unit codes, then one code per grammar field.
C_UNIT_NEW, C_UNIT_REF, C_UNIT_PREFIX, C_UNIT_EXT, C_FIELD0 = 0, 1, 2, 3, 4
VARINT_MAX = 1 << 63
#: Bytes charged to ``max_unit_bytes`` per stored unit, besides its length.
UNIT_OVERHEAD = 32
#: Derive/hash work allowed per declared output byte (plus ``work_slack``).
HASH_WORK_FACTOR = 8
#: Output budget default of the engine (4 GiB); OpenTine passes smaller ones.
DEFAULT_OUTPUT_BUDGET = 1 << 32
#: Fixed allowance in :func:`stream_bound`.
STREAM_SLACK = 1 << 16

#: Every reason code a decode can answer (normative, SPEC "TINEPACK6").
REASON_CODES = (
    "header", "budget", "limit", "truncated", "trailing", "bad-varint", "backend",
    "grammar", "bad-ref", "bad-code", "derive", "duplicate", "size-mismatch", "want-mismatch",
)  # fmt: skip


class HecError(ValueError):
    """Reason-coded rejection. ``code`` is stable; the message is for people."""

    def __init__(self, code: str, msg: str = "") -> None:
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


class Limits:
    """Decoder limits; the output budget is the caller's (no ratio rule)."""

    def __init__(
        self,
        max_output_bytes: int = DEFAULT_OUTPUT_BUDGET,
        work_slack: int = 1 << 20,
        max_objects: int = 1 << 22,
        max_holes_per_object: int = 1 << 20,
        max_types: int = 4096,
        max_type_desc: int = 1024,
        max_unit_bytes: int = 1 << 28,
        max_aux_bytes: int = 1 << 24,
        max_hashed_bytes: int | None = None,
        max_stream_bytes: int | None = None,
        max_window_log: int = 27,
        max_depth: int = 64,
    ) -> None:
        self.max_output_bytes = max_output_bytes
        self.work_slack = work_slack
        self.max_objects = max_objects
        self.max_holes_per_object = max_holes_per_object
        self.max_types = max_types
        self.max_type_desc = max_type_desc
        self.max_unit_bytes = max_unit_bytes
        self.max_aux_bytes = max_aux_bytes
        if max_hashed_bytes is None:
            max_hashed_bytes = 4 * max_output_bytes
        self.max_hashed_bytes = max_hashed_bytes
        if max_stream_bytes is None:
            max_stream_bytes = 2 * max_output_bytes + STREAM_SLACK
        self.max_stream_bytes = max_stream_bytes
        self.max_window_log = max_window_log
        self.max_depth = max_depth


DEFAULT_LIMITS = Limits()


class Closure:
    """Want-set given as roots: every root present, every object reachable from one."""

    def __init__(self, roots) -> None:
        self.roots = frozenset(roots)


class _AnySet:
    """Want-set of a receiver that cannot name the exact set in advance.

    ``TINEPACK6`` receive paths pass it and then run the same id, envelope,
    boundary and link checks as for every pack; the engine skips only rule 7.
    """

    def __repr__(self) -> str:
        return "ANY"


ANY = _AnySet()


class Obj:
    """One decoded object."""

    __slots__ = ("body", "id", "index", "memo", "type")

    def __init__(self, index: int, type_, id_: bytes, body: bytes) -> None:
        self.index = index
        self.type = type_
        self.id = id_
        self.body = body
        self.memo: dict | None = None


class Decoded:
    __slots__ = ("aux", "objects")

    def __init__(self, objects: list[Obj], aux: bytes) -> None:
        self.objects = objects
        self.aux = aux


def uv(n: int) -> bytes:
    """Canonical unsigned LEB128."""
    if not 0 <= n < VARINT_MAX:
        raise HecError("limit", "varint out of range")
    out = bytearray()
    while n >= 0x80:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


class Reader:
    """Bounds-checked cursor over one stream."""

    __slots__ = ("b", "n", "name", "p")

    def __init__(self, b: bytes, name: str) -> None:
        self.b = b
        self.p = 0
        self.n = len(b)
        self.name = name

    def uv(self) -> int:
        b, p, n = self.b, self.p, self.n
        if p >= n:
            raise HecError("truncated", self.name)
        c = b[p]
        p += 1
        if c < 0x80:
            self.p = p
            return c
        v, shift = c & 0x7F, 7
        while True:
            if p >= n:
                raise HecError("truncated", self.name)
            c = b[p]
            p += 1
            v |= (c & 0x7F) << shift
            shift += 7
            if c < 0x80:
                if c == 0:
                    raise HecError("bad-varint", "overlong in " + self.name)
                if v >= VARINT_MAX:
                    raise HecError("bad-varint", "too large in " + self.name)
                self.p = p
                return v
            if shift > 63:
                raise HecError("bad-varint", "too long in " + self.name)

    def take(self, k: int) -> bytes:
        p = self.p
        q = p + k
        if q > self.n:
            raise HecError("truncated", self.name)
        self.p = q
        return self.b[p:q]

    def done(self) -> bool:
        return self.p == self.n


def stream_bound(total_out: int, n_obj: int) -> int:
    """Cap on the summed raw size of every stream but head and aux."""
    return 2 * total_out + 3 * n_obj + STREAM_SLACK


def head_cap(limits: Limits) -> int:
    """The head holds three varints and at most ``max_types`` descriptors."""
    return 27 + limits.max_types * (limits.max_type_desc + 2)
