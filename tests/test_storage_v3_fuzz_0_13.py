"""Storage v3 against hostile bytes: binary index, blocks, delta chains, bombs.

The rule every case checks: a damaged or crafted v3 pack may make an object
unreadable (``KernelError``/``CodecError``) or missing, but never makes a read
return bytes other than the object's canonical bytes.
"""

from __future__ import annotations

import hashlib
import os
import random
import struct

import pytest

from opentine import _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository import Repo
from opentine.repository import _pack_v3_index as ix
from opentine.repository import _run_delta as forms
from opentine.repository._gc import gc
from opentine.repository._pack_write import load_pack, verify_packs
from opentine.repository._packs import pack_set
from tests.test_storage_v3_0_13 import _isolated, _record  # noqa: F401 -- fixture

RUN_HEADER = b'{"encoding":"json","schema":1,"type":"run"}'
REFUSED = (KernelError, _codec.CodecError, KeyError)


@pytest.fixture
def v3repo(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _record(repo, "heads/a", steps=8)
    _record(repo, "heads/b", steps=4)
    raw = {oid: repo.raw(oid) for oid in repo.iter_oids()}
    gc(repo, upgrade=True)
    (digest,) = [n[:64] for n in os.listdir(repo.path / "packs") if n.endswith(".tpk")]
    return repo, digest, raw


def _files(repo, digest):
    return repo.path / "packs" / f"{digest}.tidx", repo.path / "packs" / f"{digest}.tpk"


def _never_wrong(repo, digest, raw) -> None:
    try:
        single = load_pack(repo.path, digest)
    except REFUSED + (OSError, ValueError):
        return
    for oid in single.in_block_order():
        try:
            got = single.read(oid)
        except REFUSED:
            continue
        assert got == raw[oid], oid


def _resign(data: bytes) -> bytes:
    return data[:-32] + hashlib.sha256(data[:-32]).digest()


def test_random_index_damage_is_refused_or_harmless(v3repo):
    repo, digest, raw = v3repo
    tidx, _ = _files(repo, digest)
    original = tidx.read_bytes()
    rng = random.Random(1313)
    for trial in range(300):
        data = bytearray(original)
        if trial % 3 == 0:
            data = data[: rng.randrange(len(data))]
        else:
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        if trial % 2:  # a forger who recomputes the checksum
            data = bytearray(_resign(bytes(data))) if len(data) >= 32 else data
        tidx.write_bytes(bytes(data))
        _never_wrong(repo, digest, raw)


def test_checksum_valid_field_extremes_are_refused(v3repo):
    repo, digest, raw = v3repo
    tidx, tpk = _files(repo, digest)
    original = tidx.read_bytes()
    head = struct.calcsize(">8s32sII")
    count = struct.unpack_from(">I", original, 40)[0]
    offsets = range(head, len(original) - 32)
    for offset in sorted(random.Random(5).sample(offsets, min(120, len(offsets)))):
        for value in (b"\x00", b"\xff"):
            data = bytearray(original)
            data[offset : offset + 1] = value
            tidx.write_bytes(_resign(bytes(data)))
            _never_wrong(repo, digest, raw)
    assert count >= 1
    with pytest.raises(KernelError, match="too many"):
        ix.parse_index(
            original[:40] + struct.pack(">II", 2**31, 0) + bytes(32), digest, tpk.stat().st_size
        )


def test_random_block_damage_is_refused_or_harmless(v3repo):
    repo, digest, raw = v3repo
    _, tpk = _files(repo, digest)
    original = tpk.read_bytes()
    rng = random.Random(7)
    for _ in range(200):
        data = bytearray(original)
        for _ in range(rng.randint(1, 3)):
            data[rng.randrange(8, len(data))] ^= 1 << rng.randrange(8)
        tpk.write_bytes(bytes(data))
        _never_wrong(repo, digest, raw)
    tpk.write_bytes(original)
    assert verify_packs(repo.path) == []


def test_truncated_pack_refuses_its_tail_and_fsck_names_it(v3repo):
    repo, digest, raw = v3repo
    _, tpk = _files(repo, digest)
    tpk.write_bytes(tpk.read_bytes()[:-10])
    packs = pack_set(repo.path)
    packs.refresh()
    last = max(packs.where, key=lambda oid: packs.where[oid][1])
    with pytest.raises(REFUSED):
        Repo.open(repo.path).raw(last)
    _never_wrong(repo, digest, raw)
    assert any(digest in error for error in verify_packs(repo.path))


# -- handcrafted packs --------------------------------------------------------


def _install(repo, objects: list[tuple[str, bytes, int, int]], frame=None) -> str:
    """Write one single-kind block of (oid, stored, encoding, size) as a v3 pack."""
    block = b"".join(stored for _, stored, _, _ in objects)
    frame = frame if frame is not None else _codec.wrap(block, "zlib", force=True)
    body = ix.PACK3_MAGIC + frame
    digest = hashlib.sha256(body).hexdigest()
    entries, start = [], 0
    for oid, stored, encoding, size in objects:
        entries.append((oid, 0, start, len(stored), size, encoding))
        start += len(stored)
    kind = ix.KINDS.index(objects[0][0].split(":")[0])
    index = ix.encode_index(digest, [(len(frame), len(block), kind)], entries)
    (repo.path / "packs").mkdir(exist_ok=True)
    (repo.path / "packs" / f"{digest}.tpk").write_bytes(body)
    (repo.path / "packs" / f"{digest}.tidx").write_bytes(index)
    return digest


def _run_oid(n: int) -> str:
    return f"run:sha256:{n:064x}"


def _delta() -> bytes:
    body = {"append": {"events": ["x"]}, "drop": [], "set": {}}
    return RUN_HEADER + b"\n" + canonical_json(body)


FULL_RUN = RUN_HEADER + b'\n{"events":["x"]}'


def test_a_delta_cannot_start_a_block(tmp_path):
    """Its base is the object before it, so a block-leading delta (or a loop) is unspellable."""
    repo = Repo.init(tmp_path / "r", compression="zlib")
    digest = _install(repo, [(_run_oid(1), _delta(), 1, 100), (_run_oid(2), _delta(), 1, 100)])
    with pytest.raises(KernelError, match="no base"):
        load_pack(repo.path, digest)


def test_deep_chain_is_refused_iteratively(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    count = forms.MAX_DELTA_DEPTH + 5
    objects = [(_run_oid(0), FULL_RUN, 0, len(FULL_RUN))]
    objects += [(_run_oid(n), _delta(), 1, 100) for n in range(1, count)]
    digest = _install(repo, objects)
    with pytest.raises(KernelError, match="too deep"):
        load_pack(repo.path, digest).read(_run_oid(count - 1))


def test_a_delta_rebuilding_other_bytes_is_refused(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    objects = [(_run_oid(5), FULL_RUN, 0, len(FULL_RUN)), (_run_oid(6), _delta(), 1, 66)]
    digest = _install(repo, objects)
    with pytest.raises(KernelError, match="does not match its id"):
        load_pack(repo.path, digest).read(_run_oid(5))  # the base itself is checked too
    real = Repo.init(tmp_path / "s", compression="zlib")
    _record(real, "heads/a", steps=4)
    runs = sorted((o, real.raw(o)) for o in real.iter_oids() if o.startswith("run:"))
    base_oid, base = runs[0]
    forged = [(base_oid, base, 0, len(base)), (runs[1][0], _delta(), 1, len(runs[1][1]))]
    digest = _install(repo, forged)
    with pytest.raises(KernelError, match="size does not match|does not match its id|run delta"):
        load_pack(repo.path, digest).read(runs[1][0])
    assert load_pack(repo.path, digest).read(base_oid) == base


def test_slim_event_storing_a_default_is_refused():
    stored = b'{"encoding":"json","schema":1,"type":"event"}\n{"actor":"","kind":"tool"}'
    with pytest.raises(KernelError, match="default"):
        forms.unslim_event(stored)


@pytest.mark.parametrize(
    "mutate",
    [
        {"append": {"events": "x"}},
        {"append": {"events": []}},
        {"drop": ["events"], "append": {"events": ["x"]}},
        {"base": _run_oid(1)},
        {"extra": 1},
    ],
)
def test_malformed_delta_bodies_are_refused(mutate):
    body = {"append": {"events": ["x"]}, "drop": [], "set": {}, **mutate}
    with pytest.raises(KernelError):
        forms.parse_delta(RUN_HEADER + b"\n" + canonical_json(body))


def test_bomb_caps_hold_before_inflating(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    blob = b'{"encoding":"raw","schema":1,"type":"blob"}\n'
    oid_a, oid_b = f"blob:sha256:{1:064x}", f"blob:sha256:{2:064x}"
    big = ix.MAX_BLOCK_BYTES // 2 + 1
    frame = _codec.wrap(blob + b"\0" * (2 * big - len(blob)), "zlib", force=True)
    digest = _install(repo, [(oid_a, b"x" * big, 0, big), (oid_b, b"y" * big, 0, big)], frame)
    with pytest.raises(KernelError, match="oversized"):
        load_pack(repo.path, digest)
    calls = []
    real = _codec.unwrap
    monkeypatch.setattr(
        _codec, "unwrap", lambda data, limit: calls.append(limit) or real(data, limit=limit)
    )
    lying = _codec.MAGIC + bytes([_codec.ZLIB]) + _codec._uvarint(10**8) + b"\x78\x9c"
    digest = _install(repo, [(oid_a, b"x" * 50, 0, 50)], lying)
    with pytest.raises(KernelError, match="size does not match"):
        load_pack(repo.path, digest).read(oid_a)
    assert calls == []
