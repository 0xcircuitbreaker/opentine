"""TINEPACK4: the binary compressed transfer pack and its reader limits."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from opentine import Run, _codec
from opentine.graph import StepKind
from opentine.kernel import KernelError, canonical_json
from opentine.repository import Repo, _pack4
from opentine.repository.pack import inspect_pack


def _repo(tmp_path: Path, steps: int = 12) -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / "origin")
    run = Run(id="pack4")
    for index in range(steps):
        run.add_step(StepKind.think, {"text": f"step {index} " + "reasoning text " * 40})
    return repo, repo.put_run(run, ref="heads/main").run_id


def _rebuild(header: dict, body: bytes) -> bytes:
    raw_header = canonical_json(header)
    payload = _codec._uvarint(len(raw_header)) + raw_header + body
    return _pack4.MAGIC4 + hashlib.sha256(payload).digest() + payload


def _parts(pack: bytes) -> tuple[dict, bytes]:
    payload = pack[len(_pack4.MAGIC4) + 32 :]
    length, start = _codec._read_uvarint(payload, 0)
    return json.loads(payload[start : start + length]), payload[start + length :]


def test_v4_carries_the_same_objects_and_boundaries_as_v3(tmp_path):
    repo, _ = _repo(tmp_path)
    v3 = repo.pack()
    v4 = _pack4.from_v3(v3, "zlib")
    assert v4.startswith(_pack4.MAGIC4)
    old, new = inspect_pack(v3), inspect_pack(v4)
    assert old[1] == new[1] and old[2] == new[2]
    assert new[0] == _pack4.pack_digest(v4)
    assert len(v4) < len(v3)  # no base64: smaller on the wire


@pytest.mark.skipif(not _codec.available("zstd"), reason="zstd not installed")
def test_v4_with_zstd_installs_and_verifies(tmp_path):
    repo, run_id = _repo(tmp_path)
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(_pack4.from_v3(repo.pack(), "zstd"))
    assert clone.has(run_id) and clone.fsck().ok


def test_v4_installs_into_a_repository(tmp_path):
    repo, run_id = _repo(tmp_path)
    clone = Repo.init(tmp_path / "clone")
    result = clone.import_pack(_pack4.from_v3(repo.pack(), "zlib"))
    assert run_id in result.objects and clone.fsck().ok


def test_a_tampered_v4_pack_is_refused(tmp_path):
    repo, _ = _repo(tmp_path)
    pack = bytearray(_pack4.from_v3(repo.pack(), "zlib"))
    pack[-5] ^= 0xFF
    with pytest.raises(KernelError, match="checksum"):
        inspect_pack(bytes(pack))


def test_lengths_that_do_not_match_the_body_are_refused_before_inflating(tmp_path):
    repo, _ = _repo(tmp_path)
    header, body = _parts(_pack4.from_v3(repo.pack(), "zlib"))
    header["objects"][0][1] += 1
    with pytest.raises(KernelError, match="does not match"):
        inspect_pack(_rebuild(header, body))


def test_a_declared_size_over_the_body_limit_is_refused_before_inflating(tmp_path):
    repo, _ = _repo(tmp_path)
    pack = _pack4.from_v3(repo.pack(), "zlib")
    with pytest.raises(KernelError, match="maximum decompressed size"):
        inspect_pack(pack, max_body=100)


def test_a_body_that_inflates_past_its_declared_size_is_refused(tmp_path):
    repo, _ = _repo(tmp_path)
    header, _ = _parts(_pack4.from_v3(repo.pack(), "zlib"))
    total = sum(length for _, length in header["objects"])
    bomb = _codec.MAGIC + bytes([_codec.ZLIB]) + _codec._uvarint(total)
    bomb += _codec.compress_frame(b"\0" * (total * 4), "zlib")
    with pytest.raises(KernelError):
        inspect_pack(_rebuild(header, bomb))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda header: header.update(codec="lzma"),
        lambda header: header.update(version=2),
        lambda header: header.update(extra=1),
        lambda header: header["objects"].reverse(),
        lambda header: header.update(objects="nope"),
    ],
)
def test_malformed_headers_are_refused(tmp_path, mutate):
    repo, _ = _repo(tmp_path)
    header, body = _parts(_pack4.from_v3(repo.pack(), "zlib"))
    mutate(header)
    with pytest.raises(KernelError):
        inspect_pack(_rebuild(header, body))


def test_a_non_canonical_header_is_refused(tmp_path):
    repo, _ = _repo(tmp_path)
    header, body = _parts(_pack4.from_v3(repo.pack(), "zlib"))
    raw_header = json.dumps(header, indent=1).encode()
    payload = _codec._uvarint(len(raw_header)) + raw_header + body
    pack = _pack4.MAGIC4 + hashlib.sha256(payload).digest() + payload
    with pytest.raises(KernelError, match="non-canonical"):
        inspect_pack(pack)


def test_format_choice_falls_back_to_v3_for_older_peers():
    assert _pack4.choose(None, None) == (_pack4.V3, None)
    assert _pack4.choose(["TINEPACK3"], ["zlib"]) == (_pack4.V3, None)
    assert _pack4.choose(["TINEPACK4", "TINEPACK3"], ["zlib"]) == (_pack4.V4, "zlib")
    assert _pack4.choose(["TINEPACK4"], ["lzma"]) == (_pack4.V3, None)
    assert _pack4.request_fields({"pack_format": "TINEPACK3"}) == {}
    fields = _pack4.request_fields({"pack_formats": ["TINEPACK4", "TINEPACK3"]})
    assert fields["pack_formats"] == ["TINEPACK4", "TINEPACK3"]
