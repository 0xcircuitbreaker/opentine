"""0.81: the HEC1 engine's decode rules (SPEC "TINEPACK6") on packs built here."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from opentine import _hec
from opentine._hec import _backend
from opentine._hec._core import uv

G = _hec.OPENTINE
BLOB = b'{"encoding":"raw","schema":1,"type":"blob"}'
EVENT = b'{"encoding":"json","schema":1,"type":"event"}'
CODECS = [_backend.STORED, _backend.ZLIB] + ([_backend.ZSTD] if _backend.zstd_available() else [])


def _oid(desc: bytes, body: bytes) -> bytes:
    return G.object_id(G.type_info(desc), body)


def _table(n: int = 6) -> list[tuple[bytes, bytes]]:
    """Blobs, then events linking to them and to each other: links, units, opaque hex."""
    shared = "the same long instruction string, repeated in every blob " * 3
    rows = []
    for i in range(n):
        rows.append((BLOB, json.dumps({"i": i, "text": shared}, sort_keys=True).encode()))
    prev = None
    for i in range(n):
        body = {"blob": _oid(*rows[i]).decode(), "hash": hashlib.sha256(b"%d" % i).hexdigest()}
        if prev:
            body["parent"] = prev
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        rows.append((EVENT, raw))
        prev = _oid(EVENT, raw).decode()
    return rows


def _ids(rows) -> set[bytes]:
    return {_oid(d, b) for d, b in rows}


@pytest.mark.parametrize("codec", CODECS)
def test_round_trip_recomputes_every_id_and_elides_links(codec):
    rows = _table()
    pack = _hec.encode(rows, G, codec=codec)
    got = _hec.decode(pack, G, _ids(rows))
    assert [(o.type.desc, o.body) for o in got.objects] == rows
    assert [o.id for o in got.objects] == [_oid(d, b) for d, b in rows]
    assert b"sha256:" not in pack  # no id is carried: every link is a back-reference


def _refusal(pack: bytes, want=None, limits=_hec.DEFAULT_LIMITS) -> str:
    with pytest.raises(_hec.HecError) as info:
        _hec.decode(pack, G, want if want is not None else _hec.ANY, limits)
    assert info.value.code in _hec.REASON_CODES
    return info.value.code


def test_every_prefix_and_every_trailing_byte_is_refused_with_a_reason():
    rows = _table(3)
    pack = _hec.encode(rows, G, codec=_backend.STORED)
    for cut in range(len(pack)):
        _refusal(pack[:cut])
    assert _refusal(pack + b"\0") == "trailing"


def test_tampering_with_any_byte_never_yields_other_objects():
    rows = _table(3)
    pack = _hec.encode(rows, G, codec=_backend.STORED)
    expected = [(d, b) for d, b in rows]
    for at in range(len(pack)):
        bad = bytearray(pack)
        bad[at] ^= 0x01
        try:
            got = _hec.decode(bytes(bad), G, _hec.ANY)
        except _hec.HecError as exc:
            assert exc.code in _hec.REASON_CODES
            continue
        ids = {o.id for o in got.objects}
        assert ids == {_oid(o.type.desc, o.body) for o in got.objects}  # ids always recomputed
        if [(o.type.desc, o.body) for o in got.objects] != expected:
            assert ids != _ids(rows)  # a changed body is a different object, never the same id


def test_the_want_set_must_match_exactly():
    rows = _table(3)
    pack = _hec.encode(rows, G)
    ids = _ids(rows)
    assert _refusal(pack, ids - {next(iter(ids))}) == "want-mismatch"
    assert _refusal(pack, ids | {b"blob:sha256:" + b"0" * 64}) == "want-mismatch"
    assert _refusal(pack, _hec.Closure({_oid(*rows[0])})) == "want-mismatch"  # events unreached
    _hec.decode(pack, G, _hec.Closure({_oid(*rows[-1])}))  # the last event reaches every object
    with pytest.raises(TypeError):
        _hec.decode(pack, G, list(ids))


def test_declared_output_over_the_budget_is_refused_before_inflation():
    rows = _table()
    pack = _hec.encode(rows, G)
    total = sum(len(b) for _, b in rows)
    assert _refusal(pack, limits=_hec.Limits(max_output_bytes=total - 1)) == "budget"
    _hec.decode(pack, G, _hec.ANY, _hec.Limits(max_output_bytes=total))


def _forged(n_obj: int, total_out: int, body_streams: dict[str, bytes]) -> bytes:
    """A stored-codec pack with a hand-written head and the given streams."""
    from opentine._hec._core import MAGIC, STREAMS

    head = uv(n_obj) + uv(total_out) + uv(1) + uv(len(BLOB)) + BLOB
    streams = {name: b"" for name in STREAMS} | {"head": head} | body_streams
    out = [MAGIC, uv(len(G.name)), G.name.encode()]
    for name in STREAMS:
        out += [b"\0", uv(len(streams[name])), streams[name]]
    return b"".join(out)


def test_a_bomb_declaring_little_output_is_refused_without_allocating_it():
    big = {"opaque": b"\0" * (300 << 10)}  # structure far beyond 2 x total_out + 64 KiB
    assert _refusal(_forged(1, 5, big)) == "budget"
    assert _refusal(_forged(10, 2, {})) == "budget"  # more objects than output allows


def test_a_unit_hole_cannot_emit_more_than_declared():
    lit = b'{"a":"' + b"x" * 30 + b'"}'
    streams = {
        "type": uv(0), "nholes": uv(1), "litlen": uv(0), "gap": uv(0),
        "code": b"\0", "arg": uv(len(lit)), "unit": lit,
    }  # fmt: skip
    assert _refusal(_forged(1, len(lit) - 1, streams)) == "size-mismatch"
    got = _hec.decode(_forged(1, len(lit), streams), G, _hec.ANY)
    assert got.objects[0].body == lit


def test_long_link_chains_decode_without_recursion():
    rows = []
    prev = None
    for i in range(3000):
        body = json.dumps({"i": i, "parent": prev}, separators=(",", ":"), sort_keys=True)
        raw = body.encode()
        rows.append((EVENT, raw))
        prev = _oid(EVENT, raw).decode()
    pack = _hec.encode(rows, G, codec=_backend.ZLIB, verify=False)
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(120)
    try:
        got = _hec.decode(pack, G, _ids(rows))
    finally:
        sys.setrecursionlimit(limit)
    assert len(got.objects) == 3000


def test_type_descriptors_are_strict():
    for desc in (
        b'{"encoding":"json","schema":1,"type":"blob"}',  # blob must be raw
        b'{"encoding":"raw","schema":0,"type":"blob"}',
        b'{"encoding":"json","schema":1,"type":"nonsense"}',
        b'{"schema":1,"encoding":"json","type":"event"}',
    ):
        with pytest.raises(_hec.HecError) as info:
            G.type_info(desc)
        assert info.value.code == "grammar"


def test_dependency_order_puts_targets_first():
    rows = list(reversed(_table(4)))
    order = _hec.dependency_order(rows, G)
    placed = [rows[i] for i in order]
    seen: set[bytes] = set()
    for desc, body in placed:
        for value in json.loads(body).values():
            if isinstance(value, str) and ":sha256:" in value:
                assert value.encode() in seen
        seen.add(_oid(desc, body))
