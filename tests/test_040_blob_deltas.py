"""0.40: BLOB_DELTA stored form in local v3 packs (``_blob_delta``, ``_gc_deltas``)."""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter

import pytest

from opentine import _codec
from opentine.kernel import KernelError, ObjectEnvelope
from opentine.repository import Repo, _gc_deltas
from opentine.repository import _blob_delta as bd
from opentine.repository import _run_delta as forms
from opentine.repository._config import read_config
from opentine.repository._gc import gc
from opentine.repository._pack_v3_index import PACK3_MAGIC, encode_index
from opentine.repository._pack_write import write_pack
from opentine.repository._packs import oid_of, pack_set
from opentine.repository._paths import internal_path

WORDS = "agent tool model token plan step file test commit diff patch error retry".split()


def _env(kind: str, payload) -> tuple[str, bytes]:
    envelope = ObjectEnvelope.create(kind, payload)
    return envelope.oid, envelope.encode()


def _text(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def _objects(seed: int, count: int) -> dict[str, bytes]:
    """*count* seeded objects covering FULL, RUN_DELTA, EVENT_SLIM and BLOB_DELTA."""
    rng = random.Random(seed)
    out: dict[str, bytes] = {}
    blobs, events, runs = count * 2 // 5, count * 2 // 5, count // 5
    family: list[str] = []
    while len(out) < blobs:
        if not family or rng.random() < 0.1:
            family = [_text(rng, rng.randint(50, 400)) for _ in range(rng.randint(1, 4))]
        roll = rng.random()
        if roll < 0.5:
            family.append(_text(rng, rng.randint(1, 40)))  # transcript growth
        elif roll < 0.8:
            family[rng.randrange(len(family))] = _text(rng, rng.randint(5, 60))  # edit
        body = json.dumps(family).encode() if rng.random() < 0.9 else rng.randbytes(64)
        oid, raw = _env("blob", body)
        out[oid] = raw
    event_ids: list[str] = []
    while len(event_ids) < events:
        payload = {k: (v if rng.random() < 0.7 else _text(rng, 2)) for k, v in
                   forms.EVENT_DEFAULTS.items()}  # fmt: skip
        payload.update(kind="model", text=_text(rng, rng.randint(1, 30)), n=len(event_ids))
        oid, raw = _env("event", payload)
        if oid not in out:
            out[oid] = raw
            event_ids.append(oid)
    made, session, upto = 0, 0, 0
    while made < runs:
        if upto == 0 or rng.random() < 0.05:
            session, upto = session + 1, 0
        upto = min(len(event_ids), upto + rng.randint(1, 3))
        body = {"session_id": f"s{session}", "events": event_ids[:upto], "note": _text(rng, 3)}
        oid, raw = _env("run", body)
        if oid not in out:
            out[oid] = raw
            made += 1
    return out


@pytest.fixture
def delta_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    repo = Repo.init(tmp_path / "repo")
    gc(repo, upgrade=True)
    _gc_deltas.enable(repo)
    return repo


def _encodings(repo) -> Counter:
    packs = pack_set(repo.path)
    packs.refresh()
    return Counter(entry[4] for entries in packs.v3.values() for entry in entries.values())


def test_10k_random_objects_round_trip_through_every_stored_form(delta_repo):
    objects = _objects(400, 10_000)
    assert len(objects) == 10_000
    write_pack(delta_repo.path, sorted(objects.items()), "zlib", 1, 3)
    seen = _encodings(delta_repo)
    assert {forms.FULL, forms.RUN_DELTA, forms.EVENT_SLIM, forms.BLOB_DELTA} <= set(seen)
    reader = Repo.open(delta_repo.path)
    packs = pack_set(reader.path)
    for oid in packs.in_block_order(sorted(objects)):
        raw = packs.read(oid)
        assert raw == objects[oid] and oid_of(raw) == oid
    for oid in random.Random(1).sample(sorted(objects), 500):  # random order: cold chains
        assert reader.raw(oid) == objects[oid]


def test_without_the_opt_in_no_pack_holds_a_blob_delta(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    repo = Repo.init(tmp_path / "repo")
    gc(repo, upgrade=True)
    write_pack(repo.path, sorted(_objects(3, 500).items()), "zlib", 1, 3)
    assert forms.BLOB_DELTA not in _encodings(repo)


# --- hand-built packs: deep, cyclic, corrupt --------------------------------


def _install(repo, rows: list[tuple[str, bytes, int, int]]) -> None:
    """One v3 blob block holding *rows* of (oid, stored, encoding, canonical size)."""
    raw = b"".join(stored for _, stored, _, _ in rows)
    frame = _codec.wrap(raw, "zlib", force=True)
    body = PACK3_MAGIC + frame
    digest = hashlib.sha256(body).hexdigest()
    entries, offset = [], 0
    for oid, stored, encoding, size in rows:
        entries.append((oid, 0, offset, len(stored), size, encoding))
        offset += len(stored)
    index = encode_index(digest, [(len(frame), len(raw), 2)], entries)
    internal_path(repo.path, "packs").mkdir(parents=True, exist_ok=True)
    internal_path(repo.path, "packs", f"{digest}.tpk").write_bytes(body)
    internal_path(repo.path, "packs", f"{digest}.tidx").write_bytes(index)


def _chain(length: int) -> list[tuple[str, bytes]]:
    items = [_env("blob", b"x" * 600)]
    for n in range(length):
        items.append(_env("blob", items[-1][1].split(b"\n", 1)[1] + b"y%d" % n))
    return items


def _deltas(items):
    rows = [(items[0][0], items[0][1], forms.FULL, len(items[0][1]))]
    for (base, base_raw), (oid, raw) in zip(items, items[1:], strict=False):
        rows.append((oid, bd.encode(raw, base, base_raw) or _force(raw, base), forms.BLOB_DELTA,
                     len(raw)))  # fmt: skip
    return rows


def _force(raw: bytes, base: str) -> bytes:
    header, body = raw.split(b"\n", 1)
    return header + b"\n" + f"{base} 600 0".encode() + b"\n" + body[600:]


def test_a_chain_within_the_depth_limit_reads(delta_repo):
    items = _chain(forms.MAX_DELTA_DEPTH)
    _install(delta_repo, _deltas(items))
    assert Repo.open(delta_repo.path).raw(items[-1][0]) == items[-1][1]


def test_a_chain_deeper_than_the_limit_is_refused(delta_repo):
    items = _chain(forms.MAX_DELTA_DEPTH + 1)
    _install(delta_repo, _deltas(items))
    with pytest.raises(KernelError, match="too deep"):
        Repo.open(delta_repo.path).raw(items[-1][0])


@pytest.mark.parametrize("size", [1, 2, 3])
def test_a_cyclic_chain_is_refused(delta_repo, size):
    items = [_env("blob", b"z" * 700 + b"%d" % n) for n in range(size)]
    rows = []
    for n, (oid, raw) in enumerate(items):
        base = items[(n + 1) % size][0]
        header, body = raw.split(b"\n", 1)
        stored = header + b"\n" + f"{base} 700 0".encode() + b"\n" + body[700:]
        rows.append((oid, stored, forms.BLOB_DELTA, len(raw)))
    _install(delta_repo, rows)
    with pytest.raises(KernelError, match="loops"):
        Repo.open(delta_repo.path).raw(items[0][0])


def test_a_corrupted_delta_is_detected(delta_repo):
    items = _chain(3)
    rows = _deltas(items)
    oid, stored, encoding, size = rows[2]
    rows[2] = (oid, stored[:-1] + bytes([stored[-1] ^ 1]), encoding, size)
    _install(delta_repo, rows)
    reader = Repo.open(delta_repo.path)
    with pytest.raises(KernelError, match="does not match its id"):
        reader.raw(items[3][0])  # its base is corrupt: the chain fails at that object
    with pytest.raises(KernelError, match="does not match its id"):
        reader.raw(items[2][0])


def test_a_delta_whose_base_is_not_in_its_pack_is_refused(delta_repo):
    items = _chain(1)
    rows = _deltas(items)[1:]
    _install(delta_repo, rows)
    with pytest.raises(KernelError, match="not in its pack"):
        Repo.open(delta_repo.path).raw(items[1][0])


@pytest.mark.parametrize(
    "line", [b"blob:sha256:zz 1 1", b"blob:sha256:" + b"a" * 64 + b" 01 0", b"run:sha256:x 0 0"]
)
def test_a_malformed_delta_line_is_refused(line):
    with pytest.raises(KernelError, match="malformed"):
        bd.parse(b'{"type":"blob"}\n' + line + b"\nmiddle")


def test_a_delta_taking_more_than_its_base_is_refused():
    base_oid, base_raw = _env("blob", b"abc")
    with pytest.raises(KernelError, match="more bytes"):
        bd.apply(bd.parse(b"{}\n" + f"{base_oid} 2 2".encode() + b"\n"), base_raw)


# --- transcript growth, opt-in and transfer ---------------------------------


def _growing_run(repo, turns: int) -> None:
    from opentine import Run

    run = Run(id="grow", run_id="grow", created_at=1_767_225_600.0, model_info="mock/m")
    for turn in range(turns):
        run.transcript.append({"role": "user", "content": f"turn {turn} " + "w" * 900})
        repo.put_run(run, ref="heads/grow")


def test_put_transcript_growth_is_delta_stored(delta_repo):
    _growing_run(delta_repo, 12)
    gc(delta_repo, repack=True)
    assert _encodings(delta_repo)[forms.BLOB_DELTA] >= 10
    reader = Repo.open(delta_repo.path)
    assert len(reader.load_run("heads/grow").transcript) == 12


def test_opt_in_gates_older_readers_and_transfer_stays_canonical(delta_repo, tmp_path, monkeypatch):
    from opentine.repository import _config

    config = read_config(internal_path(delta_repo.path, "config.json"))
    assert config["packs"] == "delta" and config["min_reader"] == "0.40.0"
    monkeypatch.setattr(_config, "READER_VERSION", (0, 39, 0))
    with pytest.raises(ValueError, match="needs opentine 0.40.0"):
        Repo.open(delta_repo.path)
    monkeypatch.undo()
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    _growing_run(delta_repo, 6)
    gc(delta_repo, repack=True)
    oids = pack_set(delta_repo.path).oids()
    target = Repo.init(tmp_path / "fetched")
    target.import_pack(Repo.open(delta_repo.path).pack(oids))
    assert all(target.raw(oid) == delta_repo.raw(oid) for oid in oids)
    assert "packs" not in read_config(internal_path(target.path, "config.json"))


def test_disable_rewrites_the_packs_then_lowers_min_reader(delta_repo):
    _growing_run(delta_repo, 6)
    gc(delta_repo, repack=True)
    assert _encodings(delta_repo)[forms.BLOB_DELTA]
    _gc_deltas.disable(delta_repo)
    config = read_config(internal_path(delta_repo.path, "config.json"))
    assert "packs" not in config and config["min_reader"] == "0.26.0"
    assert forms.BLOB_DELTA not in _encodings(delta_repo)
    assert len(Repo.open(delta_repo.path).load_run("heads/grow").transcript) == 6
