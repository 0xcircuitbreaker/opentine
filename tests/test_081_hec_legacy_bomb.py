"""A derived legacy_step_id cannot expand a blob in memory before the budget refuses it."""

from __future__ import annotations

import hashlib
import json
import tracemalloc

import pytest

from opentine import _hec
from opentine._hec import _backend
from opentine._hec import _strict_json as sj
from opentine.kernel import canonical_json
from opentine.repository import _pack6

BLOB = b'{"encoding":"raw","schema":1,"type":"blob"}'
EVENT = b'{"encoding":"json","schema":1,"type":"event"}'


def _bomb(n: int) -> tuple[bytes, int]:
    """One emoji blob named as both input and output of an event that derives its legacy id."""
    body = canonical_json({"x": "\U0001f600" * n})
    bid = "blob:sha256:" + hashlib.sha256(b"blob\0" + b"1\0" + body).hexdigest()
    leg = "ab" * 32  # never checked: the decoder refuses on budget first
    ev = {"input_blob": bid, "kind": "k", "legacy_step_id": leg, "output_blob": bid}
    ev = canonical_json({**ev, "parent_ids": []})
    field = _hec.OPENTINE.fields[1]
    real = field.render
    field.render = lambda ctx: leg.encode()  # force the self-derived coding
    try:
        hec = _hec.encode([(BLOB, body), (EVENT, ev)], _hec.OPENTINE, level=3, verify=False)
    finally:
        field.render = real
    return hec, len(body) + len(ev)


@pytest.mark.skipif(not _backend.zstd_available(), reason="zstd not installed")
def test_legacy_step_id_derivation_is_refused_before_its_expansion_exists():
    budget = 4 << 20
    hec, out = _bomb(budget // 5)  # output fits the budget; the ascii expansion is ~6x it
    assert out <= budget and len(hec) < 8192
    tracemalloc.start()
    try:
        with pytest.raises(_pack6.Pack6Error) as err:
            _pack6._decode_hec(hec, budget, 10)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert err.value.code == "limit"
    assert peak < 4 * budget, peak / budget


@pytest.mark.parametrize(
    "value",
    [
        {"b": ["\U0001f600" * 40000, 'é\n"\\\x01', 1.5, -0.0, 10**15, True, None]},
        {"z": {}, "a": [], "é": {"k": [1e-7, 3e21]}},
    ],
)
def test_streamed_v2_hash_matches_canonical_v2(value):
    class Ctx:
        work = 0

        def charge(self, n):
            self.work += n

    ctx = Ctx()
    data = sj.canonical_v2(json.loads(json.dumps(value)))
    assert sj.hash_v2(value, ctx) == hashlib.sha256(data).hexdigest()
    assert ctx.work == len(data)
