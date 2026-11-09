"""0.50: per-kind zstd dictionaries in local v3 packs (P3, ``_pack_dicts``, ``_gc_dicts``)."""

from __future__ import annotations

import json
import random

import pytest

from opentine import _codec, _codec_dict
from opentine.kernel import ObjectEnvelope
from opentine.repository import Repo, _gc_dicts, _pack_dicts
from opentine.repository._config import read_config
from opentine.repository._gc import gc
from opentine.repository._packs import oid_of, pack_set
from opentine.repository._paths import internal_path

pytestmark = pytest.mark.skipif(not _codec.available("zstd"), reason="needs zstd")

WORDS = "agent tool model token plan step file test commit diff patch error retry".split()


def _objects(seed: int, count: int) -> dict[str, bytes]:
    """Small, similar JSON blobs and events: what a dictionary is for."""
    rng = random.Random(seed)
    out: dict[str, bytes] = {}
    for n in range(count):
        words = " ".join(rng.choice(WORDS) for _ in range(rng.randint(5, 40)))
        if n % 2:
            envelope = ObjectEnvelope.create(
                "blob", json.dumps({"role": "tool", "text": words}).encode()
            )
        else:
            envelope = ObjectEnvelope.create("event", {"kind": "model", "n": n, "text": words})
        out[envelope.oid] = envelope.encode()
    return out


@pytest.fixture
def dict_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    monkeypatch.setattr(_pack_dicts, "MIN_TRAIN_BYTES", 4096)
    monkeypatch.setattr(_pack_dicts, "DICT_BYTES", 4096)
    monkeypatch.setattr(_pack_dicts, "_pays", lambda content, stored: content)
    repo = Repo.init(tmp_path / "repo")
    for raw in _objects(50, 600).values():
        repo._store_envelope(ObjectEnvelope.decode(raw, oid_of(raw)))
    _gc_dicts.enable(repo)
    gc(repo, upgrade=True, repack=True)
    return repo


def _dicts(repo) -> list[str]:
    directory = repo.path / "dicts"
    return sorted(p.name for p in directory.glob("*.zdict")) if directory.is_dir() else []


def test_codec_3_round_trips_and_names_its_dictionary():
    rows = list(_objects(1, 420).values())
    content = _codec_dict.train(rows[:400], 4096)
    assert content
    raw = b"".join(rows[400:405])  # a few small objects: where a dictionary pays
    body = _codec.wrap(raw, "zstd", force=True, dictionary=content)
    assert body[len(_codec.MAGIC)] == _codec.DICT
    assert _pack_dicts.block_dict(body[:64]) == _codec_dict.dict_id(content).hex()
    by_id = {_codec_dict.dict_id(content): content}
    assert _codec.unwrap(body, limit=len(raw), dictionaries=by_id.get) == raw
    with pytest.raises(_codec.CodecError, match="needs zstd dictionary sha256:"):
        _codec.unwrap(body, limit=len(raw))
    with pytest.raises(_codec.CodecError, match="does not match its id"):
        _codec.unwrap(body, limit=len(raw), dictionaries=lambda wanted: content + b"x")
    assert _codec.unwrap(_codec.wrap(raw, "zstd", force=True), limit=len(raw)) == raw


def test_gc_trains_per_kind_and_every_object_reads_back_by_its_id(dict_repo):
    names = _dicts(dict_repo)
    assert names and set(_pack_dicts.referenced(dict_repo.path)) <= {n[:64] for n in names}
    assert _pack_dicts.referenced(dict_repo.path), "no block uses a dictionary"
    assert set(_pack_dicts._latest(dict_repo.path)) <= {"blob", "event"}
    reader = Repo.open(dict_repo.path)
    oids = pack_set(reader.path).oids()
    assert len(oids) == 600
    for oid in oids:
        assert oid_of(reader.raw(oid)) == oid
    assert reader.fsck().ok


def test_a_missing_or_altered_dictionary_is_refused(dict_repo):
    used = sorted(_pack_dicts.referenced(dict_repo.path))[0]
    path = internal_path(dict_repo.path, "dicts", f"{used}.zdict")
    original = path.read_bytes()
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    pack_set(dict_repo.path).refresh()
    result = Repo.open(dict_repo.path).fsck()
    assert not result.ok and any("does not match its id" in e for e in map(str, result.errors))
    path.unlink()
    result = Repo.open(dict_repo.path).fsck()
    assert not result.ok and any("not here" in e for e in map(str, result.errors))
    path.write_bytes(original)
    assert Repo.open(dict_repo.path).fsck().ok


def test_packs_written_before_the_opt_in_stay_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    repo = Repo.init(tmp_path / "old")
    objects = _objects(7, 200)
    for raw in objects.values():
        repo._store_envelope(ObjectEnvelope.decode(raw, oid_of(raw)))
    gc(repo, upgrade=True)
    _gc_dicts.enable(repo)  # no rewrite: the old packs are read as they are
    reader = Repo.open(repo.path)
    assert all(reader.raw(oid) == raw for oid, raw in objects.items())
    assert not _pack_dicts.referenced(repo.path)


def test_opt_in_gates_older_readers_and_transfer_stays_canonical(dict_repo, tmp_path, monkeypatch):
    from opentine.repository import _config

    config = read_config(internal_path(dict_repo.path, "config.json"))
    assert config["pack_dicts"] == "zstd" and config["min_reader"] == _gc_dicts.MIN_READER
    monkeypatch.setattr(_config, "READER_VERSION", (0, 49, 0))
    with pytest.raises(ValueError, match="needs opentine 0.50.0"):
        Repo.open(dict_repo.path)
    monkeypatch.undo()
    oids = pack_set(dict_repo.path).oids()
    wire = Repo.open(dict_repo.path).pack(oids)
    target = Repo.init(tmp_path / "fetched")
    target.import_pack(wire)
    assert all(target.raw(oid) == dict_repo.raw(oid) for oid in oids)
    assert not (target.path / "dicts").exists()
    assert "pack_dicts" not in read_config(internal_path(target.path, "config.json"))


def test_disable_rewrites_the_packs_then_lowers_min_reader(dict_repo):
    _gc_dicts.disable(dict_repo)
    config = read_config(internal_path(dict_repo.path, "config.json"))
    assert "pack_dicts" not in config and config["min_reader"] == "0.26.0"
    assert not _pack_dicts.referenced(dict_repo.path) and not _dicts(dict_repo)
    assert Repo.open(dict_repo.path).fsck().ok


def test_a_dictionary_that_does_not_pay_for_itself_is_not_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    monkeypatch.setattr(_pack_dicts, "MIN_TRAIN_BYTES", 4096)
    repo = Repo.init(tmp_path / "repo")
    for raw in _objects(3, 200).values():
        repo._store_envelope(ObjectEnvelope.decode(raw, oid_of(raw)))
    _gc_dicts.enable(repo)
    gc(repo, upgrade=True, repack=True)  # a 110 KiB dictionary cannot pay on ~20 KiB
    assert not _dicts(repo) and Repo.open(repo.path).fsck().ok


def test_cli_opt_in_and_out(dict_repo, capsys):
    from opentine.cli import main

    assert main(["gc", "--repo", str(dict_repo.path.parent), "--dictionaries", "--json"]) in (
        0,
        None,
    )
    json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert main(["gc", "--repo", str(dict_repo.path.parent), "--no-dictionaries"]) in (0, None)
    assert "pack_dicts" not in read_config(internal_path(dict_repo.path, "config.json"))
