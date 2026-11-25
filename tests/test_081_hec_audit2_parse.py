"""Audit round 2: a derivation's parsed JSON trees are metered before any is built."""

from __future__ import annotations

import hashlib

import pytest

from opentine import _hec
from opentine._hec import _backend
from opentine._hec import _strict_json as sj
from opentine.kernel import canonical_json

BLOB = b'{"encoding":"raw","schema":1,"type":"blob"}'
EVENT = b'{"encoding":"json","schema":1,"type":"event"}'


def _oid(body: bytes) -> str:
    return "blob:sha256:" + hashlib.sha256(b"blob\0" + b"1\0" + body).hexdigest()


def _pack(n: int) -> tuple[bytes, int]:
    """A blob of n empty lists (~3 bytes each, ~64 parsed bytes each) as an event's input."""
    body = canonical_json({"a": [[] for _ in range(n)]})
    out = canonical_json({})
    leg = "ab" * 32
    ev = {"input_blob": _oid(body), "kind": "k", "legacy_step_id": leg, "output_blob": _oid(out)}
    ev = canonical_json({**ev, "parent_ids": []})
    field = _hec.OPENTINE.fields[1]
    real = field.render
    field.render = lambda ctx: leg.encode()  # force the self-derived coding
    try:
        rows = [(BLOB, body), (BLOB, out), (EVENT, ev)]
        hec = _hec.encode(rows, _hec.OPENTINE, level=3, verify=False)
    finally:
        field.render = real
    return hec, len(body) + len(out) + len(ev)


@pytest.mark.skipif(not _backend.zstd_available(), reason="zstd not installed")
def test_a_list_bomb_blob_is_refused_before_json_loads_runs(monkeypatch):
    hec, total = _pack(sj.PARSE_MAX // sj.TOKEN_COST // 2 + 1)
    calls = []
    real = sj.json.loads
    monkeypatch.setattr(sj.json, "loads", lambda *a, **k: calls.append(1) or real(*a, **k))
    with pytest.raises(_hec.HecError) as err:
        _hec.decode(hec, _hec.OPENTINE, _hec.ANY, _hec.Limits(max_output_bytes=total + 100))
    assert err.value.code == "limit"
    assert len(calls) == 1  # the event itself; never the bomb blob


def test_parsed_bytes_are_charged_per_structural_token():
    class Ctx:
        mem = work = 0

        def charge(self, n):
            self.work += n

    ctx = Ctx()
    sj.load(b'{"a":[1,2]}', ctx, blob=True)
    assert ctx.mem == (sj.tokens(b'{"a":[1,2]}', 99) + 1) * sj.TOKEN_COST
    ctx.mem = sj.PARSE_MAX - 4 * sj.TOKEN_COST
    with pytest.raises(_hec.HecError):
        sj.load(canonical_json({"a": list(range(200))}), ctx, blob=True)


@pytest.mark.skipif(not _backend.zstd_available(), reason="zstd not installed")
def test_closure_accepts_only_a_dependency_ordered_pack():
    # Normative (SPEC "HEC1"): Closure edges are elided links only; a link to a later
    # object is literal, so a valid reverse-order pack is refused under Closure.
    a = canonical_json({"x": "leaf object body"})
    b = canonical_json({"ref": _oid(a)})
    rows = [(BLOB, a), (BLOB, b)]
    ids = {o.encode() for o in (_oid(a), _oid(b))}
    root = _hec.Closure([_oid(b).encode()])
    assert len(_hec.decode(_hec.encode(rows, _hec.OPENTINE), _hec.OPENTINE, root).objects) == 2
    rev = _hec.encode(rows[::-1], _hec.OPENTINE)
    assert len(_hec.decode(rev, _hec.OPENTINE, ids).objects) == 2
    with pytest.raises(_hec.HecError) as err:
        _hec.decode(rev, _hec.OPENTINE, root)
    assert err.value.code == "want-mismatch"
