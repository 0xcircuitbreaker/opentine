"""0.11 storage compression: codecs, limits, v2 artifacts, v3 objects, packs, archives."""

from __future__ import annotations

import gzip
import json
import os
import zlib

import pytest

from opentine import Run, _codec
from opentine._artifact_io import read_artifact_bytes
from opentine._codec_io import recompress
from opentine.cli import main
from opentine.graph import RunStatus, StepKind
from opentine.kernel import KernelError
from opentine.repository import Repo
from opentine.repository._archive import create_archive, restore_archive
from opentine.repository._blob_io import read_verified_blob_prefix
from opentine.repository._gc import footprint, gc
from opentine.repository._packs import pack_set

_ZSTD = _codec.available("zstd")
_CODECS = ["zlib", *(["zstd"] if _ZSTD else [])]


@pytest.fixture
def compress_on(monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "1")


def _run(steps: int = 12) -> Run:
    run = Run(id="compress")
    for index in range(steps):
        run.add_step(
            StepKind.tool,
            {"name": "Bash", "arguments": {"command": f"ls -la /srv/project/{index} " * 20}},
            outputs={"result": "total 48\ndrwxr-xr-x  2 user user 4096 file.txt\n" * 40},
        )
    run.add_step(StepKind.done, {"text": "finished"})
    return run


# -- the wrapper ---------------------------------------------------------------


@pytest.mark.parametrize("codec", _CODECS)
def test_wrapped_bodies_round_trip_and_plain_bodies_pass_through(codec):
    raw = b'{"hello": "world"}\n' * 400
    stored = _codec.wrap(raw, codec)
    assert stored is not None and stored.startswith(_codec.MAGIC) and len(stored) < len(raw)
    assert _codec.unwrap(stored, limit=len(raw)) == raw
    assert _codec.declared_size(stored) == len(raw)
    assert _codec.unwrap(raw, limit=10) == raw  # legacy form is returned as it is


def test_small_or_incompressible_bodies_are_stored_plain():
    assert _codec.wrap(b"x" * 100, "zlib") is None
    assert _codec.wrap(os.urandom(4096), "zlib") is None


def test_a_body_that_would_exceed_the_ratio_limit_is_stored_plain():
    zeros = b"\0" * (4 * 1024 * 1024)
    assert _codec.wrap(zeros, "zlib") is None
    forced = _codec.wrap(zeros, "zlib", force=True)  # packs: stored, but as codec 0
    assert forced[len(_codec.MAGIC)] == _codec.RAW
    assert _codec.unwrap(forced, limit=len(zeros)) == zeros


def _frame(codec: int, size: int, frame: bytes) -> bytes:
    return _codec.MAGIC + bytes([codec]) + _codec._uvarint(size) + frame


@pytest.mark.parametrize(
    "stored, reason",
    [
        (_frame(1, 10**9, zlib.compress(b"a" * 1000)), "more bytes than the reader allows"),
        (_frame(1, 100_000, zlib.compress(b"a" * 1000)), "ratio"),
        (_frame(1, 1000, zlib.compress(b"a" * 1000) + b"junk"), "trailing"),
        (_frame(1, 1000, zlib.compress(b"a" * 1000)[:-4]), "trailing or missing"),
        (_frame(1, 999, zlib.compress(b"a" * 1000)), "declared length"),
        (_frame(1, 1001, zlib.compress(b"a" * 1000)), "declared length"),
        (_frame(9, 3, b"abc"), "unknown storage codec"),
        (_codec.MAGIC + b"\x01\x80\x00" + b"x", "minimally encoded"),
        (_codec.MAGIC, "truncated"),
    ],
    ids=lambda value: value if isinstance(value, str) else "stored",
)
def test_unwrap_refuses_bombs_lies_and_garbage(stored, reason):
    with pytest.raises(_codec.CodecError, match=reason):
        _codec.unwrap(stored, limit=2_000_000)


def test_nested_compression_is_refused():
    inner = _codec.wrap(b"y" * 4000, "zlib")
    outer = _frame(_codec.ZLIB, len(inner), zlib.compress(inner))
    with pytest.raises(_codec.CodecError, match="nested"):
        _codec.unwrap(outer, limit=10_000)


def test_without_zstd_writers_fall_back_and_readers_say_how_to_install(monkeypatch):
    monkeypatch.setattr(_codec, "_zstd", lambda: None)
    monkeypatch.delenv("OPENTINE_COMPRESS", raising=False)
    assert _codec.wanted() == "zlib"
    assert _codec.wanted("zstd") == "zlib"
    with pytest.raises(_codec.CodecError, match=r"opentine\[zstd\]"):
        _codec.unwrap(_frame(_codec.ZSTD, 10, b"\x28\xb5\x2f\xfd"), limit=100)


def test_the_environment_switch_turns_compression_off(monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")
    assert _codec.wanted() is None and _codec.wanted("zstd") is None
    monkeypatch.setenv("OPENTINE_COMPRESS", "zlib")
    assert _codec.wanted("zstd") == "zlib"


# -- v2 .tine artifacts --------------------------------------------------------


def test_a_saved_run_is_compressed_and_loads_unchanged(tmp_path, compress_on):
    run = _run()
    path = run.save(tmp_path / "run.tine")
    stored = path.read_bytes()
    assert stored.startswith(_codec.MAGIC)
    plain = json.loads(read_artifact_bytes(path))
    assert len(stored) * 3 < len(json.dumps(plain))
    loaded = Run.load(path)
    assert loaded.run_id == run.run_id and len(loaded.steps) == len(run.steps)
    assert Run.verify_integrity(path).ok


def test_a_signature_verifies_across_stored_forms(tmp_path, compress_on, monkeypatch):
    run = _run()
    run.status = RunStatus.completed
    key = b"k" * 32
    path = run.save(tmp_path / "signed.tine", sign_key=key)
    assert path.read_bytes().startswith(_codec.MAGIC)
    assert Run.verify_signature(path, hmac_key=key).state == "verified"
    recompress(path, decompress=True)
    assert path.read_bytes().startswith(b"{")
    assert Run.verify_signature(path, hmac_key=key).state == "verified"
    recompress(path)
    assert path.read_bytes().startswith(_codec.MAGIC)
    assert Run.verify_signature(path, hmac_key=key).state == "verified"


def test_compression_off_writes_the_plain_form_older_releases_read(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")
    path = _run().save(tmp_path / "plain.tine")
    assert json.loads(path.read_text())["run_id"]


def test_a_compressed_artifact_bomb_is_refused(tmp_path):
    path = tmp_path / "bomb.tine"
    path.write_bytes(_frame(_codec.ZLIB, 300 * 1024 * 1024, zlib.compress(b"{}")))
    with pytest.raises(ValueError, match="more bytes than the reader allows"):
        read_artifact_bytes(path)


def test_tine_compress_rewrites_a_directory_both_ways(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")
    paths = [_run().save(tmp_path / f"r{index}.tine") for index in range(2)]
    main(["compress", str(tmp_path)])
    assert all(path.read_bytes().startswith(_codec.MAGIC) for path in paths)
    main(["compress", "--decompress", str(tmp_path)])
    assert all(path.read_bytes().startswith(b"{") for path in paths)
    assert all(Run.verify_integrity(path).ok for path in paths)


# -- v3 objects ----------------------------------------------------------------


def test_a_new_repository_stores_compressed_objects_under_the_same_ids(tmp_path, compress_on):
    run = _run()
    packed = Repo.init(tmp_path / "packed")
    plain = Repo.init(tmp_path / "plain", compression=None)
    config = json.loads((packed.path / "config.json").read_text())
    assert config["version"] == 2 and config["storage"]["compression"] in _CODECS
    assert json.loads((plain.path / "config.json").read_text())["version"] == 1
    left = packed.put_run(run, ref="heads/main").run_id
    right = plain.put_run(run, ref="heads/main").run_id
    assert left == right  # identity is over canonical bytes, never the stored form
    files = list((packed.path / "objects").rglob("*"))
    assert any(f.is_file() and f.read_bytes().startswith(_codec.MAGIC) for f in files)
    assert sorted(packed.iter_oids()) == sorted(plain.iter_oids())
    assert all(packed.raw(oid) == plain.raw(oid) for oid in plain.iter_oids())
    assert packed.fsck().ok and len(packed.load_run(left).steps) == len(run.steps)


def test_an_existing_plain_repository_is_never_written_compressed(tmp_path, compress_on):
    Repo.init(tmp_path / "old", compression=None)
    repo = Repo.open(tmp_path / "old")
    repo.put_run(_run(), ref="heads/main")
    files = [f for f in (repo.path / "objects").rglob("*") if f.is_file()]
    assert files and not any(f.read_bytes().startswith(_codec.MAGIC) for f in files)


def test_a_corrupt_compressed_object_is_reported_not_returned(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(), ref="heads/main").run_id
    victim = next(
        f
        for f in (repo.path / "objects").rglob("*")
        if f.is_file() and f.read_bytes().startswith(_codec.MAGIC)
    )
    data = bytearray(victim.read_bytes())
    data[-3] ^= 0xFF
    victim.write_bytes(bytes(data))
    assert not Repo.open(repo.path).fsck().ok
    assert run_id


# -- packs ---------------------------------------------------------------------


def test_gc_packs_loose_objects_and_everything_still_reads(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(30), ref="heads/main").run_id
    oids = sorted(repo.iter_oids())
    raws = {oid: repo.raw(oid) for oid in oids}
    before = footprint(repo.path)
    result = gc(repo)
    assert result.packed == len(oids) and result.removed_loose == len(oids)
    after = footprint(repo.path)
    assert after[1] < before[1] / 4  # disk, not just bytes: small objects waste blocks
    reopened = Repo.open(repo.path)
    assert sorted(reopened.iter_oids()) == oids
    assert all(reopened.raw(oid) == raws[oid] for oid in oids)
    assert reopened.fsck().ok
    assert len(reopened.load_run(run_id).steps) == 31
    assert not [f for f in (repo.path / "objects").rglob("*") if f.is_file()]


def test_repack_merges_packs_and_new_loose_objects(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(5), ref="heads/main")
    gc(repo)
    second = Run(id="second")
    second.add_step(StepKind.done, {"text": "another"})
    repo.put_run(second, ref="heads/second")
    gc(repo)
    assert len(list((repo.path / "packs").glob("*.tidx"))) == 2
    result = gc(repo, repack=True)
    assert result.removed_packs == 2
    assert len(list((repo.path / "packs").glob("*.tidx"))) == 1
    assert Repo.open(repo.path).fsck().ok


def test_a_tampered_pack_fails_fsck_and_reads(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(), ref="heads/main").run_id
    gc(repo)
    body = next((repo.path / "packs").glob("*.tpk"))
    data = bytearray(body.read_bytes())
    data[len(data) // 2] ^= 0xFF
    body.write_bytes(bytes(data))
    pack_set(repo.path).refresh()
    reopened = Repo.open(repo.path)
    assert not reopened.fsck().ok
    with pytest.raises((KernelError, ValueError)):
        reopened.load_run(run_id)


def test_a_pack_index_without_its_pack_is_an_fsck_error(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    gc(repo)
    next((repo.path / "packs").glob("*.tpk")).unlink()
    pack_set(repo.path).fingerprint = None
    assert any("missing" in error for error in Repo.open(repo.path).fsck().errors)


def test_blob_inspection_reads_compressed_and_packed_blobs(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    body = b"line of tool output that repeats\n" * 500
    oid = repo.put("blob", body)
    assert repo.raw_size(oid) == len(repo.raw(oid))
    prefix, total, _ = read_verified_blob_prefix(
        repo, oid, prefix_limit=64, source_limit=len(body) + 10
    )
    assert total == len(body) and prefix == body[:64]
    gc(repo)
    reopened = Repo.open(repo.path)
    prefix, total, _ = read_verified_blob_prefix(
        reopened, oid, prefix_limit=64, source_limit=len(body) + 10
    )
    assert total == len(body) and prefix == body[:64]
    with pytest.raises(KernelError, match="source-byte limit"):
        read_verified_blob_prefix(reopened, oid, prefix_limit=1, source_limit=100)


def test_transfer_packs_move_canonical_bytes_between_storage_forms(tmp_path, compress_on):
    source = Repo.init(tmp_path / "packed")
    run_id = source.put_run(_run(), ref="heads/main").run_id
    gc(source)
    plain = Repo.init(tmp_path / "plain", compression=None)
    plain.import_pack(Repo.open(source.path).pack())
    files = [f for f in (plain.path / "objects").rglob("*") if f.is_file()]
    assert files and not any(f.read_bytes().startswith(_codec.MAGIC) for f in files)
    assert plain.fsck().ok and len(plain.load_run(run_id).steps) == 13
    back = Repo.init(tmp_path / "back")
    back.import_pack(plain.pack())
    assert back.fsck().ok and sorted(back.iter_oids()) == sorted(plain.iter_oids())


# -- archives ------------------------------------------------------------------


def test_an_archive_restores_a_whole_repository(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(20), ref="heads/main").run_id
    stats = create_archive(repo, tmp_path / "r.tinearc")
    assert stats["archive_bytes"] * 4 < stats["raw_bytes"]
    restored = restore_archive(tmp_path / "r.tinearc", tmp_path / "copy")
    copy = Repo.open(tmp_path / "copy")
    assert restored["refs"] == 1 and copy.read_ref("heads/main") == run_id
    assert copy.fsck().ok
    with pytest.raises(KernelError, match="already holds"):
        restore_archive(tmp_path / "r.tinearc", tmp_path / "copy")


def test_a_tampered_archive_is_refused(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    archive = tmp_path / "r.tinearc"
    create_archive(repo, archive)
    data = bytearray(archive.read_bytes())
    data[-10] ^= 0xFF
    archive.write_bytes(bytes(data))
    with pytest.raises(KernelError):
        restore_archive(archive, tmp_path / "copy")


def test_storage_commands_run_from_the_cli(tmp_path, compress_on, capsys):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    main(["gc", "--repo", str(tmp_path / "r"), "--json"])
    assert json.loads(capsys.readouterr().out)["removed_loose"] > 0
    main(["archive", "create", str(tmp_path / "r.arc"), "--repo", str(tmp_path / "r")])
    main(["archive", "restore", str(tmp_path / "r.arc"), str(tmp_path / "copy")])
    main(["fsck", "--repo", str(tmp_path / "copy")])
    main(["--no-compress", "init", str(tmp_path / "plain")])
    assert json.loads((tmp_path / "plain" / ".tine" / "config.json").read_text())["version"] == 1


def test_export_can_write_a_gzip_document(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")
    path = _run().save(tmp_path / "run.tine")
    out = tmp_path / "trace.json.gz"
    main(["export", str(path), "--output", str(out), "--compress", "gzip"])
    assert "resourceSpans" in json.loads(gzip.decompress(out.read_bytes()))
    with pytest.raises(SystemExit):
        main(["export", str(path), "--compress", "gzip"])


# -- hostile pack indexes (audit 0.11 #6) ---------------------------------------


def _index(blocks, objects, digest="0" * 64):
    from opentine.kernel import canonical_json

    return canonical_json({"blocks": blocks, "objects": objects, "pack": digest, "version": 1})


def _oid(n: int) -> str:
    return f"blob:sha256:{n:064x}"


@pytest.mark.parametrize(
    "objects",
    [
        [[_oid(1), 0, 0, 10], [_oid(2), 0, 20, 10]],  # gap
        [[_oid(1), 0, 0, 10], [_oid(2), 0, 5, 10]],  # overlap
        [[_oid(1), 0, 5, 10]],  # does not start at 0
        [[_oid(1), 0, 0, 900_000], [_oid(2), 0, 900_000, 900_000]],  # oversized shared block
    ],
)
def test_a_pack_index_whose_entries_do_not_tile_small_blocks_is_refused(objects):
    from opentine.repository._packs import PACK_MAGIC, _parse_index

    data = _index([[len(PACK_MAGIC), 100]], objects)
    with pytest.raises(KernelError):
        _parse_index(data, "0" * 64, len(PACK_MAGIC) + 100)


def test_a_block_that_inflates_beyond_its_entries_is_refused(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    gc(repo)
    index_path = next((repo.path / "packs").glob("*.tidx"))
    index = json.loads(_codec.unwrap(index_path.read_bytes(), limit=1 << 26))
    oid, block, start, length = index["objects"][0]
    index["objects"] = [[oid, block, start, length]]  # the block now holds more than its entries
    index["objects"][0][2] = 0
    from opentine.kernel import canonical_json

    index_path.write_bytes(canonical_json(index))
    packs = pack_set(repo.path)
    packs.fingerprint = None
    packs.refresh()
    if oid in packs.where:  # only a block holding a single object at 0 can reach the read
        with pytest.raises(KernelError):
            packs.read(oid)
    assert not Repo.open(repo.path).fsck().ok


def test_verify_reads_each_block_once(tmp_path, compress_on, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(60), ref="heads/main")
    gc(repo)
    from opentine.repository import _pack_write

    calls: list[int] = []
    real = _codec.unwrap

    def counting(data, *, limit):
        calls.append(1)
        return real(data, limit=limit)

    monkeypatch.setattr(_codec, "unwrap", counting)
    assert _pack_write.verify_packs(repo.path) == []
    blocks = len(
        json.loads(real(next((repo.path / "packs").glob("*.tidx")).read_bytes(), limit=1 << 26))[
            "blocks"
        ]
    )
    assert len(calls) <= blocks + 1  # + the index itself


# -- gc locking and crash safety -----------------------------------------------


def test_a_second_gc_is_refused_while_one_holds_the_lock(tmp_path, compress_on):
    from opentine.repository._gc import gc_lock

    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    with gc_lock(repo.path):
        with pytest.raises(KernelError, match="another tine gc"):
            gc(repo)
    assert gc(repo).packed > 0  # released afterwards


def test_a_stale_gc_lock_from_a_dead_process_is_taken_over(tmp_path, compress_on, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    lock = repo.path / "gc.lock"
    lock.write_text("1 0\n", encoding="ascii")  # a day-old stamp
    assert gc(repo).packed > 0
    assert not lock.exists()


def test_an_interrupted_gc_loses_nothing_and_can_be_rerun(tmp_path, compress_on, monkeypatch):
    from opentine.repository import _gc

    repo = Repo.init(tmp_path / "r")
    run_id = repo.put_run(_run(20), ref="heads/main").run_id
    raws = {oid: repo.raw(oid) for oid in repo.iter_oids()}
    removed: list[str] = []
    real = _gc._remove_loose

    def crash_after_three(target, oid):
        if len(removed) == 3:
            raise KeyboardInterrupt
        removed.append(oid)
        real(target, oid)

    monkeypatch.setattr(_gc, "_remove_loose", crash_after_three)
    with pytest.raises(KeyboardInterrupt):
        gc(repo)
    assert not (repo.path / "gc.lock").exists()
    reopened = Repo.open(repo.path)
    assert all(reopened.raw(oid) == raw for oid, raw in raws.items())
    assert reopened.fsck().ok
    monkeypatch.setattr(_gc, "_remove_loose", real)
    gc(Repo.open(repo.path), repack=True)
    final = Repo.open(repo.path)
    assert all(final.raw(oid) == raw for oid, raw in raws.items())
    assert final.fsck().ok and len(final.load_run(run_id).steps) == 21


def test_an_archive_keeps_the_unadopted_record_so_planted_labels_stay_unadopted(
    tmp_path, compress_on
):
    from opentine.repository._unadopted import read_unadopted, record_unadopted

    repo = Repo.init(tmp_path / "r")
    run = Run(id="labelled")
    run.tags = ["approved"]
    run.add_step(StepKind.done, {"text": "t"})
    repo.put_run(run, ref="heads/main")
    refs = repo.list_refs().items()
    ((name, annotation),) = [(n, o) for n, o in refs if n.startswith("annotations/")]
    run_id = repo.read_ref("heads/main")
    # A foreign annotation: unheaded and recorded as unadopted, so it labels nothing.
    (repo.path / "refs" / name).unlink()
    record_unadopted(repo.path, [annotation])
    assert repo.load_run(run_id).tags == []
    create_archive(repo, tmp_path / "r.tinearc")
    restore_archive(tmp_path / "r.tinearc", tmp_path / "copy")
    copy = Repo.open(tmp_path / "copy")
    assert read_unadopted(copy.path, strict=True) == read_unadopted(repo.path, strict=True)
    assert copy.load_run(run_id).tags == [] and copy.fsck().ok
    assert copy.list_refs() == repo.list_refs()


def test_an_archive_carries_remote_annotation_refs_and_shallow_state(tmp_path, compress_on):
    repo = Repo.init(tmp_path / "r")
    run = Run(id="tagged")
    run.tags = ["x"]
    run.add_step(StepKind.done, {"text": "t"})
    repo.put_run(run, ref="heads/main")
    refs = repo.list_refs().items()
    ((name, annotation),) = [(n, o) for n, o in refs if n.startswith("annotations/")]
    repo.update_ref("remotes/origin/" + name, annotation)
    create_archive(repo, tmp_path / "r.tinearc")
    restore_archive(tmp_path / "r.tinearc", tmp_path / "copy")
    copy = Repo.open(tmp_path / "copy")
    assert copy.list_refs() == repo.list_refs()
    assert copy.shallow_oids() == repo.shallow_oids()


def test_an_archive_with_a_forged_unadopted_record_is_refused(tmp_path, compress_on):
    from opentine.repository import _archive

    repo = Repo.init(tmp_path / "r")
    repo.put_run(_run(), ref="heads/main")
    path = tmp_path / "r.tinearc"
    create_archive(repo, path)
    manifest, index, body = _archive._parts(path.read_bytes())
    data = json.loads(manifest)
    data["unadopted"] = ["run:sha256:" + "0" * 64]
    forged = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    out = _archive.MAGIC
    for part in (forged, index, body):
        out += _archive._uvarint(len(part)) + part
    path.write_bytes(out)
    with pytest.raises(KernelError, match="non-annotation"):
        restore_archive(path, tmp_path / "copy")
