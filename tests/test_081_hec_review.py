"""Red-team regressions for the TINEPACK6 decoder (0.81 review)."""

from __future__ import annotations

import tracemalloc

import pytest

from opentine._hec import _backend, _container
from opentine._hec._core import STREAMS, uv
from opentine.repository import _pack6

BLOB = b'{"encoding":"raw","schema":1,"type":"blob"}'


def _tiny_units(total: int, holes: int = 1 << 14) -> bytes:
    """A valid pack whose output is all 4-byte literal units: cheap streams, costly objects."""
    n = total // (4 * holes)
    st = {k: bytearray() for k in STREAMS}
    st["head"] += uv(n) + uv(total) + uv(1) + uv(len(BLOB)) + BLOB
    for i in range(n):
        st["type"] += uv(0)
        st["nholes"] += uv(holes)
        st["litlen"] += uv(0)
        st["gap"] += b"\0" * holes
        st["code"] += b"\0" * holes
        st["arg"] += uv(4) * holes
        st["unit"] += i.to_bytes(4, "big") * holes
    return _container.write(st, b"opentine-1", _backend.ZSTD, 3)


@pytest.mark.skipif(not _backend.zstd_available(), reason="zstd not installed")
def test_tiny_literal_units_cannot_cost_many_times_the_output_budget():
    budget = 2 << 20
    pack = _tiny_units(budget)
    assert len(pack) < 4096
    tracemalloc.start()
    try:
        try:
            _pack6._decode_hec(pack, budget, 10_000)
        except _pack6.Pack6Error as exc:
            assert exc.code == "limit"
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4.5 * budget, peak / budget


def test_serve_never_runs_more_than_its_decode_slots(tmp_path, monkeypatch):
    import threading

    from opentine.repository import _pack6_build
    from opentine.repository.pack import inspect_pack
    from tests.test_081_tinepack6 import _repo

    v6 = _pack6_build.from_v3(_repo(tmp_path, runs=1).pack())
    real, lock, state = _pack6._decode_hec, threading.Lock(), {"now": 0, "max": 0}
    gate = threading.Event()

    def counted(*args):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        gate.wait(0.05)
        try:
            return real(*args)
        finally:
            with lock:
                state["now"] -= 1

    monkeypatch.setattr(_pack6, "_decode_hec", counted)
    threads = [
        threading.Thread(target=inspect_pack, args=(v6,), kwargs={"serve": True}) for _ in range(6)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert 1 <= state["max"] <= _pack6.SERVE_DECODES
    assert _pack6._SERVE_SLOTS._value == _pack6.SERVE_DECODES
