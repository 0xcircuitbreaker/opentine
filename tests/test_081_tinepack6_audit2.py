"""Audit round 2: TINEPACK6 manifest, serve budget and server-side encode bounds."""

from __future__ import annotations

import hashlib

import pytest

from opentine import _codec, _codec_long, _hec
from opentine.kernel import KernelError, canonical_json
from opentine.repository import _pack6, _pack6_build, _pack_peer

pytestmark = pytest.mark.skipif(not _codec.available("zstd"), reason="TINEPACK6 needs zstd")
HEAD = b'{"encoding":"raw","schema":1,"type":"blob"}\n'


def _blobs(n: int, size: int) -> list[tuple[str, bytes]]:
    out = []
    for i in range(n):
        body = (b"%04d" % i) * (size // 4)
        oid = "blob:sha256:" + hashlib.sha256(b"blob\0" + b"1\0" + body).hexdigest()
        out.append((oid, HEAD + body))
    return out


def _manifest_bomb(entries: int) -> bytes:
    manifest = b'{"objects":[' + b",".join([b"257"] * entries) + b"]}"
    frames = _codec_long.compress_blocks([manifest])
    hec = _hec.encode([], _hec.OPENTINE)
    header = canonical_json(
        {
            "grammar": "opentine-1",
            "hec": "HEC1",
            "hec_bytes": len(hec),
            "plain_blocks": [[len(f), len(b)] for f, b in zip(frames, [manifest])],
            "shallow": [],
            "version": 1,
        }
    )
    payload = _codec._uvarint(len(header)) + header + hec + b"".join(frames)
    return _pack6.MAGIC6 + hashlib.sha256(payload).digest() + payload


def test_an_oversized_manifest_block_is_refused_before_it_is_inflated(monkeypatch):
    pack = _manifest_bomb(500_000)  # ~2 MiB of sizes, far past what 10 000 objects need
    assert len(pack) < 64 * 1024

    def boom(frames):
        raise AssertionError("manifest inflated")

    monkeypatch.setattr(_codec_long, "decompress_blocks", boom)
    with pytest.raises(KernelError, match="invalid pack manifest"):
        _pack6.inspect(pack, max_body=1 << 28, max_objects=10_000, serve=True)


def test_a_plain_section_past_the_serve_hec_budget_is_read_as_tinepack5_reads_it(monkeypatch):
    objects = _blobs(8, 1024)
    pack = _pack6.frame(_hec.encode([], _hec.OPENTINE), [raw for _, raw in objects], [])
    monkeypatch.setattr(_pack6, "SERVE_MAX_OUTPUT", 2048)  # below the 8 KiB plain section
    _, got, _ = _pack6.inspect(pack, max_body=1 << 20, max_objects=100, serve=True)
    assert sorted(got) == sorted(objects)
    with pytest.raises(_pack6.Pack6Error, match="budget"):
        _pack6.inspect(pack, max_body=4096, max_objects=100, serve=True)


def test_the_hec_section_keeps_the_serve_budget(monkeypatch):
    objects = _blobs(8, 1024)
    pack = _pack6.frame(_pack6_build._hec_pack([raw for _, raw in objects], 3), [], [])
    monkeypatch.setattr(_pack6, "SERVE_MAX_OUTPUT", 2048)
    with pytest.raises(_pack6.Pack6Error, match="budget"):
        _pack6.inspect(pack, max_body=1 << 20, max_objects=100, serve=True)


def test_the_writer_never_puts_more_than_the_serve_budget_in_hec(monkeypatch):
    encoded = []
    real = _hec.encode
    monkeypatch.setattr(_pack6_build, "SERVE_MAX_OUTPUT", 2048)
    monkeypatch.setattr(
        _hec, "encode", lambda rows, *a, **k: encoded.append(len(rows)) or real(rows, *a, **k)
    )
    pack = _pack6_build.build(_blobs(8, 1024), [])
    assert encoded == [0]  # only the empty HEC body of the plain candidate
    monkeypatch.setattr(_pack6, "SERVE_MAX_OUTPUT", 2048)
    assert len(_pack6.inspect(pack, max_body=1 << 20, max_objects=100, serve=True)[1]) == 8


def test_a_server_response_is_encoded_at_the_serve_level(monkeypatch):
    levels = []
    monkeypatch.setattr(_pack6_build, "from_v3", lambda data, *, level: levels.append(level))
    _pack_peer.convert(b"v3", _pack6.V6, None, serve=True)
    _pack_peer.convert(b"v3", _pack6.V6, None)
    assert levels == [_pack6_build.SERVE_LEVEL, _pack6_build.HEC_LEVEL]
    assert _pack6_build.SERVE_LEVEL < _pack6_build.HEC_LEVEL


@pytest.mark.parametrize("path", ["opentine/remote/app.py", "opentine/remote/_hosted_http.py"])
def test_every_server_fetch_path_asks_for_the_serve_level(path):
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / path).read_text()
    assert "_pack_peer.convert(" in text
    assert "serve=True" in text.split("_pack_peer.convert(", 1)[1].split(")", 1)[0]
