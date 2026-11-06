"""0.37 TINEPACK5: recording-order long-window packs, their negotiation and X13/X17."""

from __future__ import annotations

import hashlib
import json
import os
import random

import pytest

from opentine import Recorder, TraceEvent, _bundle, _codec, _codec_io, _codec_long
from opentine.kernel import KernelError, canonical_json
from opentine.repository import Repo, _pack4, _pack5, _pack_peer
from opentine.repository import _run_delta as forms
from opentine.repository import client as repository_client
from opentine.repository._pack_v3 import stored_forms
from opentine.repository.pack import MAGIC, inspect_pack
from tests.test_remote_0_12 import URL, _remote

needs_zstd = pytest.mark.skipif(not _codec.available("zstd"), reason="zstd not installed")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _record(repo: Repo, ref: str, steps: int = 8) -> None:
    rec = Recorder.start(repo, ref=ref, prompt=f"task {ref}", capture=False)
    history = [{"role": "user", "content": f"task {ref}"}]
    for index in range(steps):
        rec.append(
            TraceEvent(
                kind="model" if index % 2 else "tool",
                timestamp=index + 1.0,
                trace_id="t",
                span_id=f"s{index}",
                actor="" if index % 2 else "read_file",
                inputs={"messages": list(history)},
                outputs={"text": f"{ref} body {index} " * 40},
            )
        )
        history.append({"role": "tool", "content": f"{ref} {index}"})
    rec.finalize()


def _repo(tmp_path, runs: int = 3) -> Repo:
    repo = Repo.init(tmp_path / "origin", compression="zlib")
    for index in range(runs):
        _record(repo, f"heads/r{index}")
    return repo


def _payload(header: dict, blocks: list[bytes]) -> bytes:
    raw = canonical_json(header)
    payload = _codec._uvarint(len(raw)) + raw + b"".join(blocks)
    return _pack5.MAGIC5 + hashlib.sha256(payload).digest() + payload


# --- the format ------------------------------------------------------------- #


@needs_zstd
@pytest.mark.parametrize("slim", [False, True])
def test_v5_carries_the_same_objects_as_v3_and_installs(tmp_path, slim):
    repo = _repo(tmp_path)
    v3 = repo.pack()
    v5 = _pack5.from_v3(v3, slim=slim)
    assert v5.startswith(_pack5.MAGIC5)
    old, new = inspect_pack(v3), inspect_pack(v5)
    assert old[1] == new[1] and old[2] == new[2]
    assert new[0] == _pack4.pack_digest(v5)
    assert len(v5) < len(_pack4.from_v3(v3, "zstd"))
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(v5)
    assert clone.fsck().ok and all(clone.has(oid) for oid, _ in new[1])


@needs_zstd
def test_slim_v5_uses_event_slim_and_run_delta_forms(tmp_path):
    repo = _repo(tmp_path, runs=1)
    objects = inspect_pack(repo.pack())[1]
    used = {encoding for _, _, encoding, _ in stored_forms(objects)}
    assert {forms.EVENT_SLIM, forms.RUN_DELTA} <= used
    assert inspect_pack(_pack5.build(objects, [], slim=True))[1] == objects


@needs_zstd
def test_v5_is_in_recording_order_with_4_mib_blocks(monkeypatch, tmp_path):
    assert _pack5.BLOCK_BYTES == 4 * 1024 * 1024 and _codec_long.WINDOW_LOG == 27
    repo = _repo(tmp_path, runs=2)
    objects = inspect_pack(repo.pack())[1]
    monkeypatch.setattr(_pack5, "BLOCK_BYTES", 4096)  # many blocks, read in order
    pack = _pack5.build(objects, [])
    payload = pack[len(_pack5.MAGIC5) + 32 :]
    length, start = _codec._read_uvarint(payload, 0)
    header = json.loads(payload[start : start + length])
    assert len(header["blocks"]) > 3 and header["window_log"] == 27
    assert inspect_pack(pack)[1] == objects


@needs_zstd
def test_tampered_or_inconsistent_v5_packs_are_refused(tmp_path):
    objects = inspect_pack(_repo(tmp_path, runs=1).pack())[1]
    pack = bytearray(_pack5.build(objects, []))
    pack[-3] ^= 0xFF
    with pytest.raises(KernelError, match="checksum"):
        inspect_pack(bytes(pack))
    entries = [[forms.FULL, 10, 10]]
    manifest = canonical_json({"objects": entries, "shallow": []})
    frames = _codec_long.compress_blocks([manifest, b"x" * 9])
    sizes = [[len(f), n] for f, n in zip(frames, (len(manifest), 9))]
    forged = _payload({"blocks": sizes, "version": 1, "window_log": 27}, frames)
    with pytest.raises(KernelError, match="does not match"):
        inspect_pack(forged)
    bad_window = _payload({"blocks": sizes, "version": 1, "window_log": 31}, frames)
    with pytest.raises(KernelError, match="window"):
        inspect_pack(bad_window)


@needs_zstd
def test_a_body_over_the_limit_is_refused_before_inflating(tmp_path):
    pack = _pack5.build(inspect_pack(_repo(tmp_path, runs=1).pack())[1], [])
    with pytest.raises(KernelError, match="maximum decompressed"):
        _pack5.inspect(pack, max_body=100, max_objects=10_000)


# --- X17: the decoder window cap ---------------------------------------------- #


def _oversized_frame(rng: random.Random, window_log: int) -> bytes:
    module = _codec._zstd()
    param = module.CompressionParameter
    engine = module.ZstdCompressor(
        options={param.window_log: window_log, param.enable_long_distance_matching: 1}
    )
    data = rng.randbytes(rng.randint(1, 4096)) * rng.randint(1, 8)
    return engine.compress(data, mode=engine.FLUSH_BLOCK) + engine.flush(mode=engine.FLUSH_FRAME)


@needs_zstd
def test_fuzz_oversized_window_frames_are_rejected_every_time():
    rng = random.Random(37)
    rejected = trials = 0
    for _ in range(200):
        window_log = rng.randint(28, 30)
        frame = _oversized_frame(rng, window_log)
        trials += 1
        manifest = canonical_json({"objects": [], "shallow": []})
        head = _codec_long.compress_blocks([manifest])[0]
        # The oversized frame as the whole stream, and after a valid manifest.
        for blocks in ([frame], [head, frame]):
            sizes = [[len(b), 100] for b in blocks]
            pack = _payload({"blocks": sizes, "version": 1, "window_log": 27}, blocks)
            with pytest.raises(KernelError):
                inspect_pack(pack)
        with pytest.raises(_codec.CodecError, match="oversized"):
            list(_codec_long.decompress_blocks([(frame, len(frame) * 8)]))
        rejected += 1
    assert rejected == trials == 200


# --- negotiation ------------------------------------------------------------ #


@needs_zstd
def test_v5_goes_only_to_peers_that_list_it():
    old = (["TINEPACK4", "TINEPACK3"], ["zstd", "zlib"])  # 0.34-0.36
    assert _pack_peer.choose(*old) == (_pack4.V4, "zstd")
    assert _pack_peer.choose(["TINEPACK5", *old[0]], old[1]) == (_pack5.V5, None)
    assert _pack_peer.choose(None, None) == (_pack4.V3, None)
    assert _pack_peer.request_fields({"pack_formats": old[0], "version": "0.36.0"}) == {
        "pack_codecs": _pack4.local_codecs(),
        "pack_formats": ["TINEPACK4", "TINEPACK3"],
    }
    fields = _pack_peer.request_fields(
        {"pack_formats": _pack_peer.local_formats(), "version": "0.37.0"}
    )
    assert fields["pack_formats"][0] == "TINEPACK5" and fields["peer_version"]


@needs_zstd
def test_new_client_and_server_round_trip_in_v5(tmp_path, monkeypatch):
    service, _, seen = _remote(tmp_path, monkeypatch)
    caps = service.capabilities()
    assert caps["pack_formats"][0] == "TINEPACK5" and _pack_peer.at_least(caps["version"], (0, 35))
    origin = _repo(tmp_path)
    repository_client.push(origin, URL, ref="heads/r1")
    clone = Repo.init(tmp_path / "clone")
    repository_client.fetch(clone, URL, ref="heads/r1")
    assert clone.has(origin.read_ref("heads/r1")) and clone.fsck().ok
    fetches = [json.loads(r.content) for r in seen if r.url.path.endswith("/fetch")]
    assert fetches[-1]["pack_formats"][0] == "TINEPACK5" and fetches[-1]["peer_version"]
    assert any(r.content.startswith(_pack5.MAGIC5) for r in seen)  # the pushed pack


@needs_zstd
def test_a_036_peer_keeps_getting_v4(tmp_path, monkeypatch):
    service, _, seen = _remote(tmp_path, monkeypatch)
    caps = service.capabilities()
    caps.pop("version")
    caps["pack_formats"] = ["TINEPACK4", "TINEPACK3"]
    monkeypatch.setattr(service, "capabilities", lambda: caps)
    origin = _repo(tmp_path, runs=1)
    repository_client.push(origin, URL, ref="heads/r0")
    assert any(r.content.startswith(_pack4.MAGIC4) for r in seen)
    assert not any(r.content.startswith(_pack5.MAGIC5) for r in seen)
    clone = Repo.init(tmp_path / "clone")
    repository_client.fetch(clone, URL, ref="heads/r0")
    fetches = [json.loads(r.content) for r in seen if r.url.path.endswith("/fetch")]
    assert fetches and "TINEPACK5" not in fetches[-1]["pack_formats"]
    assert "peer_version" not in fetches[-1]


# --- bundles ---------------------------------------------------------------- #


@needs_zstd
def test_bundles_stay_v3_unless_v5_is_asked_for(tmp_path):
    repo = _repo(tmp_path, runs=2)
    default = _bundle.verify(_bundle.create(repo))
    assert default.pack.startswith(MAGIC)  # what a 0.34 CLI reads
    v5 = _bundle.verify(_bundle.create(repo, pack_format="TINEPACK5"))
    assert v5.pack.startswith(_pack5.MAGIC5) and v5.objects == default.objects
    assert len(v5.pack) < len(default.pack)
    clone = Repo.init(tmp_path / "clone")
    _bundle.unbundle(clone, _bundle.create(repo, pack_format="TINEPACK5"), "b")
    assert clone.fsck().ok
    with pytest.raises(ValueError):
        _bundle.create(repo, pack_format="TINEPACK4")


# --- X13: codec v2 frames --------------------------------------------------- #


def test_codec_v2_frames_only_when_allowed():
    raw = b"\0" * (4 << 20)  # compresses far past 1000:1
    plain = _codec.wrap(raw, "zlib", force=True)
    assert plain[len(_codec.MAGIC)] == _codec.RAW  # what a 0.34 reader accepts
    v2 = _codec.wrap(raw, "zlib", force=True, v2=True)
    assert v2[len(_codec.MAGIC)] == _codec.ZLIB and len(v2) < len(raw) // 1000
    assert _codec.unwrap(v2, limit=len(raw)) == raw


def test_v4_bodies_use_v2_frames_only_for_peers_at_035(tmp_path):
    v3 = _repo(tmp_path, runs=1).pack()
    objects = inspect_pack(v3)[1]
    old = _pack_peer.convert(v3, _pack4.V4, "zlib", peer_version="0.34.0")
    new = _pack_peer.convert(v3, _pack4.V4, "zlib", peer_version="0.35.1")
    assert inspect_pack(old)[1] == inspect_pack(new)[1] == objects
    assert not _pack_peer.at_least(None, (0, 35)) and not _pack_peer.at_least("x", (0, 35))
    assert _pack4.build(objects, [], "zlib") == old  # no version: no v2 frames


def test_tine_files_never_carry_v2_frames(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "zlib")
    text = '{"a": "' + "x" * (2 << 20) + '"}'
    path = _codec_io.write_artifact(tmp_path / "run.tine", text)
    data = path.read_bytes()
    assert not _codec.is_wrapped(data) or len(data) * _codec.MAX_RATIO >= len(text)
    assert os.path.getsize(path) > 0
