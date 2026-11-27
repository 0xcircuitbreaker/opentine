"""A writer killed while publishing a pack leaves residue fsck accepts and gc reaps.

``publish_pack`` renames the ``.tpk`` in before the ``.tidx`` that makes
readers see it; SIGKILL between the two (or before either staging file is
renamed) is the nightly kill-writers stress failure.
"""

from __future__ import annotations

import os
import time

import pytest

from opentine import Run, StepKind, _codec
from opentine.repository import Repo, _storage, _write_batch
from opentine.repository._gc import gc
from opentine.repository._pack_write import build_pack


class _Killed(BaseException):
    pass


def _objects(repo: Repo) -> list[tuple[str, bytes]]:
    oids = [repo.put("blob", f"payload {n} ".encode() * 50) for n in range(4)]
    return sorted((oid, repo.raw(oid)) for oid in oids)


def _kill_before_index(repo: Repo, monkeypatch) -> str:
    digest, body, index = build_pack(_objects(repo), _codec.default_codec(), None)
    real = _write_batch._winretry.replace

    def replace(source, target):
        if str(target).endswith(".tidx"):
            raise _Killed
        real(source, target)

    monkeypatch.setattr(_write_batch._winretry, "replace", replace)
    with pytest.raises(_Killed):
        _write_batch.publish_pack(repo.path, digest, body, index)
    monkeypatch.undo()
    return digest


def _age(path) -> None:
    old = time.time() - 2 * 3600
    os.utime(path, (old, old))


def test_a_pack_body_without_its_index_passes_fsck_and_gc_reaps_it(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    digest = _kill_before_index(repo, monkeypatch)
    body = repo.path / "packs" / f"{digest}.tpk"
    assert body.exists() and not body.with_suffix(".tidx").exists()
    assert Repo.open(repo.path).fsck().ok, Repo.open(repo.path).fsck()
    _age(body)
    assert gc(repo).reaped_temp == 1
    assert not body.exists()
    assert Repo.open(repo.path).fsck().ok


def test_an_unpublished_pack_body_is_still_checked(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    digest = _kill_before_index(repo, monkeypatch)
    body = repo.path / "packs" / f"{digest}.tpk"
    body.write_bytes(body.read_bytes()[:-1] + b"\x00")
    errors = Repo.open(repo.path).fsck().errors
    assert any(digest in error and "does not match" in error for error in errors), errors


def test_an_index_without_its_pack_body_still_fails_fsck(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r")
    digest, body, index = build_pack(_objects(repo), _codec.default_codec(), None)
    _write_batch.publish_pack(repo.path, digest, body, index)
    (repo.path / "packs" / f"{digest}.tpk").unlink()
    errors = Repo.open(repo.path).fsck().errors
    assert f"pack {digest}: missing its .tpk" in errors


def test_a_killed_writers_pack_staging_file_passes_fsck(tmp_path):
    repo = Repo.init(tmp_path / "r")
    staging = repo.path / "packs" / f".{'ab' * 32}.tpk.ikqn47gg"
    staging.write_bytes(b"partial")
    assert Repo.open(repo.path).fsck().ok
    _age(staging)
    assert gc(repo).reaped_temp == 1


def _run(n: int) -> Run:
    run = Run(id=f"killed-{n}", model_info="mock/stress")
    for i in range(8):  # 8 steps: ~27 objects, events linking events
        run.add_step(StepKind.tool, {"i": i}, {"output": f"{i} " * 40})
    return run


@pytest.mark.parametrize("survivors", range(1, 21))
def test_a_writer_killed_mid_loose_flush_never_orphans_a_link(tmp_path, monkeypatch, survivors):
    """Loose flushes follow staging order, so every object on disk has its links."""
    monkeypatch.setenv("OPENTINE_RUN_PACK", "0")
    repo = Repo.init(tmp_path / "r")
    real, written = _storage.write_loose, []

    def write_loose(repo_, oid, raw):
        if len(written) == survivors:
            raise _Killed
        written.append(oid)
        real(repo_, oid, raw)

    monkeypatch.setattr(_storage, "write_loose", write_loose)
    with pytest.raises(_Killed):
        repo.put_run(_run(survivors), ref="heads/main")
    monkeypatch.undo()
    result = Repo.open(repo.path).fsck()
    assert result.ok, result
